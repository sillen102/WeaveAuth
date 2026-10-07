//! What after-recovery and after-password-change share: ending every other way
//! into the account. The two routes differ only in whether the credentials are
//! purged first.

pub(crate) use controller::{RevocationError, RevocationRequest};
pub(crate) use service::{Revocation, revoke};

mod controller {
    use axum::http::StatusCode;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;
    use uuid::Uuid;

    use super::service::RevocationServiceError;

    /// The body Kratos's Jsonnet template builds for the after-recovery and
    /// after-settings (password) web hooks: `{ identity_id: ctx.identity.id,
    /// session_id: ctx.session.id }`, the latter left out when `ctx` has no session.
    #[derive(Deserialize)]
    pub(crate) struct RevocationRequest {
        pub(crate) identity_id: Uuid,
        /// The session to keep (the one the user is in right now). Absent:
        /// every Kratos session of the identity goes.
        #[serde(default)]
        pub(crate) session_id: Option<Uuid>,
    }

    /// 5xx: Kratos retries and then fails the flow. Every step is safe to repeat.
    #[derive(Debug, Error, ErrorResponses)]
    pub(crate) enum RevocationError {
        #[error("revoking the account's other sign-ins did not complete")]
        #[error_response(StatusCode::BAD_GATEWAY)]
        RevocationIncomplete,
    }

    impl From<RevocationServiceError> for RevocationError {
        fn from(err: RevocationServiceError) -> Self {
            tracing::error!(%err, "revocation incomplete");
            Self::RevocationIncomplete
        }
    }
}

mod service {
    use thiserror::Error;
    use uuid::Uuid;

    use crate::clients::kratos::PURGED_CREDENTIAL_TYPES;
    use crate::server::AppState;

    /// Every step that failed, in the order they ran.
    #[derive(Debug, Error)]
    #[error("{} step(s) failed: {}", .0.len(), .0.join("; "))]
    pub(crate) struct RevocationServiceError(Vec<String>);

    pub(crate) struct Revocation {
        pub(crate) identity_id: Uuid,
        pub(crate) keep_session: Option<Uuid>,
        /// Also end every credential: the password, passkeys, TOTP, lookup codes and social logins.
        pub(crate) purge_credentials: bool,
    }

    /// Runs every step even when one fails: a Kratos outage must not leave
    /// Hydra's tokens and bff's sessions alive. Order: Kratos (credentials,
    /// sessions, credentials again), then Hydra consent sessions, Hydra login
    /// sessions and bff together. Kratos gets half the request timeout and the
    /// rest 40% of it, so a hanging upstream can't use up the time another needs.
    pub(crate) async fn revoke(
        state: &AppState,
        revocation: Revocation,
    ) -> Result<(), RevocationServiceError> {
        let id = revocation.identity_id;
        let kratos_budget = state.request_timeout / 2;
        let mut failures =
            match tokio::time::timeout(kratos_budget, revoke_in_kratos(state, &revocation)).await {
                Ok(failures) => failures,
                Err(_) => vec![format!("kratos: gave up after {kratos_budget:?}")],
            };
        let rest_budget = state.request_timeout * 2 / 5;
        let (consent, login, bff) = tokio::join!(
            within(rest_budget, state.hydra.revoke_consent_sessions(id)),
            within(rest_budget, state.hydra.revoke_login_sessions(id)),
            within(rest_budget, state.bff.revoke(id)),
        );
        for (step, result) in [
            ("hydra consent sessions", consent),
            ("hydra login sessions", login),
            ("bff sessions", bff),
        ] {
            if let Err(cause) = result {
                failures.push(format!("{step}: {cause}"));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(RevocationServiceError(failures))
        }
    }

    async fn within<E: std::fmt::Display>(
        budget: std::time::Duration,
        call: impl std::future::Future<Output = Result<(), E>>,
    ) -> Result<(), String> {
        match tokio::time::timeout(budget, call).await {
            Ok(result) => result.map_err(|e| e.to_string()),
            Err(_) => Err(format!("gave up after {budget:?}")),
        }
    }

    /// The failures of the credential purge (if asked for) and the session revocation. The
    /// purge runs again after the sessions end: a session still alive during the first one
    /// could have added a credential since.
    async fn revoke_in_kratos(state: &AppState, revocation: &Revocation) -> Vec<String> {
        let id = revocation.identity_id;
        let mut failures = Vec::new();
        let purge = async |failures: &mut Vec<String>| {
            if revocation.purge_credentials {
                failures.extend(
                    purge_credentials(state, id)
                        .await
                        .into_iter()
                        .map(|failure| format!("purge credentials: {failure}")),
                );
            }
        };
        purge(&mut failures).await;
        if let Err(cause) = revoke_kratos_sessions(state, id, revocation.keep_session).await {
            failures.push(format!("kratos sessions: {cause}"));
        }
        purge(&mut failures).await;
        failures
    }

    /// Replaces the password with one nobody knows, then unlinks the social
    /// logins and deletes the other credentials, each attempted even when
    /// another fails. The password goes first because Kratos refuses to delete
    /// an account's last first-factor credential (a passkey-only account, say).
    /// Social logins go too: one linked by whoever held the account before
    /// recovery would otherwise let them straight back in.
    async fn purge_credentials(state: &AppState, id: Uuid) -> Vec<String> {
        let mut failures = Vec::new();
        let mut links = Vec::new();
        match state.kratos.get_identity(id, true).await {
            Ok(identity) => {
                links = identity.oidc_identifiers().to_vec();
                if let Err(error) = state.kratos.scramble_password(id).await {
                    failures.push(error.to_string());
                }
            }
            Err(error) => failures.push(error.to_string()),
        }
        for link in &links {
            if let Err(error) = state.kratos.delete_oidc_link(id, link).await {
                failures.push(error.to_string());
            }
        }
        for credential_type in PURGED_CREDENTIAL_TYPES.iter().copied() {
            if let Err(error) = state.kratos.delete_credential(id, credential_type).await {
                failures.push(error.to_string());
            }
        }
        failures
    }

    /// Most rounds of "list the first page, revoke what isn't `keep`" before
    /// giving up on an identity with more sessions than that.
    const MAX_SESSION_ROUNDS: usize = 20;

    async fn revoke_kratos_sessions(
        state: &AppState,
        id: Uuid,
        keep: Option<Uuid>,
    ) -> Result<(), String> {
        let Some(keep) = keep else {
            return state
                .kratos
                .revoke_all_sessions(id)
                .await
                .map_err(|e| e.to_string());
        };
        for _ in 0..MAX_SESSION_ROUNDS {
            let others: Vec<Uuid> = state
                .kratos
                .active_sessions(id)
                .await
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|session| *session != keep)
                .collect();
            if others.is_empty() {
                return Ok(());
            }
            let mut failed = Vec::new();
            for session in others {
                if let Err(error) = state.kratos.revoke_session(session).await {
                    failed.push(error.to_string());
                }
            }
            if !failed.is_empty() {
                return Err(failed.join(", "));
            }
        }
        Err(format!(
            "sessions remain after {MAX_SESSION_ROUNDS} rounds of revoking"
        ))
    }
}
