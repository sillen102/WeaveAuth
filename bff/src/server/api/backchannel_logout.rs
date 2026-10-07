pub(crate) use controller::backchannel_logout;

mod controller {
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiForm;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;

    use crate::server::AppState;

    use super::service::{self, BackchannelServiceError};

    #[derive(Deserialize)]
    pub(crate) struct LogoutTokenForm {
        pub(super) logout_token: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum BackchannelLogoutError {
        #[error("invalid logout_token")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid logout_token")]
        InvalidLogoutToken,
        #[error("logout_token was already used")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid logout_token")]
        ReplayedLogoutToken,
        #[error("signing keys unavailable")]
        #[error_response(StatusCode::SERVICE_UNAVAILABLE, details = "signing keys unavailable")]
        KeysUnavailable,
    }

    impl From<BackchannelServiceError> for BackchannelLogoutError {
        fn from(err: BackchannelServiceError) -> Self {
            tracing::warn!(%err, "back-channel logout refused");
            match err {
                BackchannelServiceError::Invalid(_) => BackchannelLogoutError::InvalidLogoutToken,
                BackchannelServiceError::Replayed => BackchannelLogoutError::ReplayedLogoutToken,
                BackchannelServiceError::KeysUnavailable(_) => {
                    BackchannelLogoutError::KeysUnavailable
                }
            }
        }
    }

    /// Hydra telling bff a user logged out (OpenID Connect Back-Channel Logout 1.0): the
    /// sessions the verified `logout_token` names end. Only on the internal listener, and
    /// authorized by the token itself, which only Hydra can sign. `200` on success, which
    /// includes a user with no session here.
    pub(crate) async fn backchannel_logout(
        State(mut state): State<AppState>,
        ApiForm(form): ApiForm<LogoutTokenForm>,
    ) -> Result<StatusCode, BackchannelLogoutError> {
        service::logout(&mut state, &form.logout_token).await?;
        Ok(StatusCode::OK)
    }
}

mod service {
    use thiserror::Error;

    use crate::hydra::{JwksError, LogoutTokenError};
    use crate::server::AppState;
    use crate::storage::{JtiReplayed, JtiStorage};

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum BackchannelServiceError {
        #[error("logout token refused: {0}")]
        Invalid(LogoutTokenError),
        #[error("logout token replayed")]
        Replayed,
        #[error("could not get Hydra's signing keys: {0}")]
        KeysUnavailable(JwksError),
    }

    /// Verifies the token, remembers its `jti` and ends the sessions it names. The `jti` is
    /// remembered only once the token verified, so forged tokens can neither fill the store
    /// nor burn a genuine token's `jti`.
    pub(crate) async fn logout(
        state: &mut AppState,
        logout_token: &str,
    ) -> Result<(), BackchannelServiceError> {
        let claims = state
            .hydra
            .verify_logout_token(logout_token)
            .await
            .map_err(|error| match error {
                // A `kid` Hydra doesn't publish is the token's fault.
                LogoutTokenError::Keys(error @ JwksError::UnknownKey(_)) => {
                    BackchannelServiceError::Invalid(LogoutTokenError::Keys(error))
                }
                // Not the token's fault: Hydra's keys could not be had, so say so and let Hydra retry.
                LogoutTokenError::Keys(error) => BackchannelServiceError::KeysUnavailable(error),
                error => BackchannelServiceError::Invalid(error),
            })?;
        state
            .logout_jtis
            .record(&claims.jti, claims.replay_until)
            .await
            .map_err(|JtiReplayed| BackchannelServiceError::Replayed)?;
        state.end_sessions(&claims.target).await;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::Config;

        #[tokio::test]
        async fn a_token_that_does_not_parse_is_invalid() {
            let mut state = AppState::new(Config {
                hydra_internal_url: "http://127.0.0.1:1".into(),
                ..Config::default()
            })
            .unwrap();
            let result = logout(&mut state, "not-a-jwt").await;
            assert!(
                matches!(result, Err(BackchannelServiceError::Invalid(_))),
                "{result:?}"
            );
        }
    }
}
