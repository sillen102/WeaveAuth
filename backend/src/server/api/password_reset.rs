pub(crate) use controller::confirm_password_reset;
pub(crate) use controller::confirm_password_reset_doc;
pub(crate) use controller::request_password_reset;
pub(crate) use controller::request_password_reset_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiJson;
    use common_macros::ErrorResponses;
    use indoc::indoc;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;
    use uuid::Uuid;

    use crate::server::AppState;

    use super::service;
    use super::service::PasswordResetConfirmServiceError;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct PasswordResetRequestRequest {
        pub(super) email: String,
    }

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct PasswordResetConfirmRequest {
        pub(super) token: String,
        pub(super) new_password: String,
    }

    #[derive(Debug, Serialize, JsonSchema)]
    pub(crate) struct PasswordResetConfirmResponse {
        /// Whose password was reset, so bff can end that user's sessions.
        pub(crate) user_id: Uuid,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum PasswordResetConfirmError {
        #[error("invalid or expired password reset token")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "invalid or expired password reset token"
        )]
        InvalidOrExpiredToken,
        #[error("password does not meet the password policy")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "password must be at least 8 characters and at most 1024 bytes"
        )]
        WeakPassword,
        #[error("internal error")]
        #[error_response(StatusCode::INTERNAL_SERVER_ERROR)]
        UnexpectedError,
    }

    impl From<PasswordResetConfirmServiceError> for PasswordResetConfirmError {
        fn from(err: PasswordResetConfirmServiceError) -> Self {
            if let PasswordResetConfirmServiceError::UnexpectedError(_) = &err {
                tracing::error!(%err, "password reset failed");
            }
            match err {
                PasswordResetConfirmServiceError::InvalidOrExpiredToken => {
                    PasswordResetConfirmError::InvalidOrExpiredToken
                }
                PasswordResetConfirmServiceError::WeakPassword(_) => {
                    PasswordResetConfirmError::WeakPassword
                }
                PasswordResetConfirmServiceError::UnexpectedError(_) => {
                    PasswordResetConfirmError::UnexpectedError
                }
            }
        }
    }

    pub(crate) fn request_password_reset_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("request_password_reset")
            .summary("Request a password reset")
            .description(indoc! {"
                Always returns 202, whether or not `email` matches an account and whether or not
                a mail went out, so the response can't be used to enumerate registered addresses.
                On a match, mails a single-use reset link to the account's stored address through
                the configured email handler, at most once per cooldown. The token is never in the
                response or a log."})
    }

    pub(crate) fn confirm_password_reset_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("confirm_password_reset")
            .summary("Redeem a password reset token")
            .description(indoc! {"
                Sets a new password on the account `token` was issued for, marks its email
                verified, and ends every session, code and refresh token issued before. Returns
                the account's `user_id`, so bff can end its sessions too; 400 if
                the token is unknown, expired, or already used, or if the password is shorter
                than 8 characters or longer than 1024 bytes (the token stays usable then)."})
    }

    pub(crate) async fn request_password_reset(
        State(mut state): State<AppState>,
        ApiJson(req): ApiJson<PasswordResetRequestRequest>,
    ) -> StatusCode {
        service::request_password_reset(&mut state, &req.email).await;
        StatusCode::ACCEPTED
    }

    pub(crate) async fn confirm_password_reset(
        State(mut state): State<AppState>,
        ApiJson(req): ApiJson<PasswordResetConfirmRequest>,
    ) -> Result<Json<PasswordResetConfirmResponse>, PasswordResetConfirmError> {
        let user_id =
            service::confirm_password_reset(&mut state, &req.token, req.new_password.into())
                .await?;
        Ok(Json(PasswordResetConfirmResponse { user_id }))
    }
}

mod service {
    use chrono::Utc;
    use secrecy::SecretString;
    use thiserror::Error;
    use uuid::Uuid;

    use crate::crypto;
    use crate::email::{EmailKind, OutboundEmail};
    use crate::model::email::normalize_email;
    use crate::model::password::{PasswordPolicyError, validate_new_password};
    use crate::model::user::PasswordHash;
    use crate::server::AppState;
    use crate::storage::{
        EmailVerificationCodeStorage, IssueResetOutcome, LoginSessionStorage, MarkVerifiedOutcome,
        PasswordResetTokenStorage, RefreshTokenStorage, RevokeOutcome, SetPasswordOutcome,
        UserStorage, VerificationSessionStorage,
    };

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum PasswordResetConfirmServiceError {
        #[error("invalid or expired password reset token")]
        InvalidOrExpiredToken,
        #[error(transparent)]
        WeakPassword(#[from] PasswordPolicyError),
        #[error("internal error: {0}")]
        UnexpectedError(String),
    }

    /// Mails a reset link to the account matching `email`, if any. Nothing
    /// here may change the caller's response (no account, no handler, the
    /// cooldown), or it would tell who has an account; the send runs in the
    /// background for the same reason.
    pub(crate) async fn request_password_reset(state: &mut AppState, email: &str) {
        let Some(user) = state.users.get_user_by_email(&normalize_email(email)).await else {
            return;
        };
        let Some(handler) = state.email_handler.clone() else {
            // Warned about once at startup; anyone can trigger this line.
            tracing::debug!(user_id = %user.id, "password reset requested but no email handler is configured");
            return;
        };
        let token = match state.password_reset_tokens.issue_reset_token(user.id).await {
            IssueResetOutcome::Issued(token) => token,
            IssueResetOutcome::CoolingDown => {
                tracing::info!(user_id = %user.id, "password reset email skipped: resend cooldown");
                return;
            }
        };

        // The token goes in the fragment, which browsers never send to a
        // server or in a Referer.
        let login_url = &state.login_public_url;
        let mail = OutboundEmail {
            user_id: user.id,
            email: user.email,
            expires_at: Utc::now()
                + chrono::Duration::seconds(state.password_reset_tokens.ttl_secs()),
            kind: EmailKind::PasswordReset {
                reset_url: format!("{login_url}/reset-password.html#token={token}"),
            },
        };
        tokio::spawn(async move {
            if let Err(error) = handler.send(&mail).await {
                tracing::warn!(%error, user_id = %mail.user_id, "could not deliver password reset email");
            }
        });
    }

    /// Redeems a password reset token: sets the new password, which ends
    /// every credential issued before (see `User::credential_version`), and
    /// marks the email verified, since the token proves control of it.
    pub(crate) async fn confirm_password_reset(
        state: &mut AppState,
        token: &str,
        new_password: SecretString,
    ) -> Result<Uuid, PasswordResetConfirmServiceError> {
        // Before the token is spent, so a rejected password can be retried.
        validate_new_password(&new_password)?;

        let user_id = state
            .password_reset_tokens
            .take_reset_token(token)
            .await
            .ok_or(PasswordResetConfirmServiceError::InvalidOrExpiredToken)?;

        let password_hash = crypto::hash_password(new_password).await.map_err(|error| {
            PasswordResetConfirmServiceError::UnexpectedError(error.to_string())
        })?;

        // `UserNotFound` can't happen (nothing deletes users); to the caller
        // the token just no longer resolves to anything.
        match state
            .users
            .set_password(user_id, PasswordHash::Argon2(password_hash.into()))
            .await
        {
            SetPasswordOutcome::Ok => {}
            SetPasswordOutcome::UserNotFound => {
                return Err(PasswordResetConfirmServiceError::InvalidOrExpiredToken);
            }
        }
        match state.users.mark_email_verified(user_id).await {
            MarkVerifiedOutcome::Ok => {}
            MarkVerifiedOutcome::UserNotFound => {
                return Err(PasswordResetConfirmServiceError::InvalidOrExpiredToken);
            }
        }

        clean_up_after_reset(state, user_id).await;
        Ok(user_id)
    }

    /// Drops what the reset already made worthless, plus the verification
    /// lockout guesses burned before the owner took the account back. A
    /// failure is logged, not returned: the password is already changed, and
    /// the credentials left behind are refused by their stale stamp anyway.
    async fn clean_up_after_reset(state: &mut AppState, user_id: Uuid) {
        let outcomes = [
            (
                "refresh tokens",
                state.refresh_tokens.revoke_all_for_user(user_id).await,
            ),
            (
                "login sessions",
                state.login_sessions.revoke_all_for_user(user_id).await,
            ),
            (
                "verification sessions",
                state
                    .email_verification
                    .sessions
                    .revoke_all_for_user(user_id)
                    .await,
            ),
            (
                "verification code state",
                state.email_verification.codes.clear_user(user_id).await,
            ),
        ];
        for (what, outcome) in outcomes {
            if outcome == RevokeOutcome::Failed {
                tracing::error!(%user_id, "clearing {what} after a password reset failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use crate::email::EmailKind;
    use crate::model::user::{CredentialStamp, PasswordHash, User};
    use crate::server::AppState;
    use crate::server::api::email_verification::test_support::{
        Sent, assert_nothing_sent, install_recorder, lock_out, next_sent,
    };
    use crate::storage::{CheckCodeOutcome, EmailVerificationCodeStorage, IssueCodeOutcome};
    use crate::storage::{
        LoginSessionStorage, PasswordResetTokenStorage, RefreshTokenStorage, UserStorage,
        VerificationSessionStorage,
    };
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiJson;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    fn state() -> AppState {
        AppState {
            pkce: crate::storage::in_memory::InMemoryPkceStorage::new(300),
            users: crate::storage::in_memory::InMemoryUserStorage::new(),
            login_sessions: crate::storage::in_memory::InMemoryLoginSessionStorage::new(60),
            redirect_uri_allowlist: Arc::new(vec![]),
            jwt_keys: crate::storage::in_memory::InMemoryJwkStorage::new()
                .expect("RSA keygen for tests never fails"),
            access_token_ttl_secs: 900,
            refresh_tokens: crate::storage::in_memory::InMemoryRefreshTokenStorage::new(2_592_000),
            refresh_token_ttl_secs: 2_592_000,
            jwt_key_rotation_interval_secs: 2_592_000,
            issuer: "http://localhost:1983".into(),
            oidc_providers: Arc::new(std::collections::HashMap::new()),
            oidc_extra_claims: Arc::new(Default::default()),
            oidc_scopes: Arc::new(Default::default()),
            oidc_display_names: Arc::new(Default::default()),
            oidc_profile_apis: Arc::new(Default::default()),
            oidc_state: crate::storage::in_memory::InMemoryOidcStateStorage::new(300),
            pending_oidc_links: crate::storage::in_memory::InMemoryPendingOidcLinkStorage::new(300),
            oidc_http_client: Arc::new(openidconnect::reqwest::Client::new()),
            email_verification: crate::server::api::email_verification::EmailVerification::disabled(
            ),
            password_reset_tokens:
                crate::storage::in_memory::InMemoryPasswordResetTokenStorage::new(1_800, 0),
            max_bcrypt_cost: 12,
            extra_data_handler: None,
            login_claims_handler: None,
            email_handler: None,
            login_public_url: String::new(),
        }
    }

    async fn issued_token(state: &mut AppState, user_id: Uuid) -> String {
        match state.password_reset_tokens.issue_reset_token(user_id).await {
            crate::storage::IssueResetOutcome::Issued(token) => token,
            crate::storage::IssueResetOutcome::CoolingDown => unreachable!("expected a token"),
        }
    }

    #[tokio::test]
    async fn request_returns_the_same_accepted_status_for_an_unknown_email() {
        // No account-existence oracle: an unknown email gets the exact same
        // response as a known one.
        let state = state();
        let req = PasswordResetRequestRequest {
            email: "nobody@example.com".to_string(),
        };

        let status = request_password_reset(State(state), ApiJson(req)).await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn confirm_sets_a_new_password_and_is_single_use() {
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2("old-hash".into())),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let token = issued_token(&mut state, user_id).await;

        let req = PasswordResetConfirmRequest {
            token: token.clone(),
            new_password: "new-password".to_string(),
        };
        let result = confirm_password_reset(State(state.clone()), ApiJson(req)).await;
        // bff ends the user's sessions with it.
        assert_eq!(result.map(|Json(body)| body.user_id), Ok(user_id));

        let updated = state.users.get_user_by_id(user_id).await.unwrap();
        assert_ne!(updated.password.unwrap().expose(), ("argon2", "old-hash"));

        // Single-use: the same token can't be redeemed twice.
        let replay = PasswordResetConfirmRequest {
            token,
            new_password: "another-password".to_string(),
        };
        let replay_result = confirm_password_reset(State(state), ApiJson(replay)).await;
        assert_eq!(
            replay_result.err(),
            Some(PasswordResetConfirmError::InvalidOrExpiredToken)
        );
    }

    #[tokio::test]
    async fn confirm_revokes_existing_refresh_tokens_and_login_sessions() {
        // The whole point of resetting a password after a suspected
        // compromise: an attacker holding a live refresh token or login
        // session from before the reset must be logged out by it, not just
        // locked out of future logins.
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2("old-hash".into())),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        state
            .refresh_tokens
            .save_refresh_token(
                "refresh-token".to_string(),
                CredentialStamp::initial(user_id),
                Uuid::new_v4(),
            )
            .await;
        let login_session = state
            .login_sessions
            .create_session(CredentialStamp::initial(user_id))
            .await;
        let token = issued_token(&mut state, user_id).await;

        let req = PasswordResetConfirmRequest {
            token,
            new_password: "new-password".to_string(),
        };
        let result = confirm_password_reset(State(state.clone()), ApiJson(req)).await;
        assert_eq!(result.map(|Json(body)| body.user_id), Ok(user_id));

        assert_eq!(
            state
                .refresh_tokens
                .take_refresh_token("refresh-token")
                .await,
            crate::storage::RefreshTokenOutcome::NotFound
        );
        assert_eq!(
            state.login_sessions.take_session(&login_session).await,
            None
        );
    }

    #[tokio::test]
    async fn confirm_revokes_verification_sessions_too() {
        // An attacker who registered the victim's address holds a verification
        // session; after the victim resets the password it must be worthless.
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2("old-hash".into())),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let other = state
            .email_verification
            .sessions
            .create_session(CredentialStamp::initial(Uuid::new_v4()))
            .await;
        let session = state
            .email_verification
            .sessions
            .create_session(CredentialStamp::initial(user_id))
            .await;
        let token = issued_token(&mut state, user_id).await;

        let req = PasswordResetConfirmRequest {
            token,
            new_password: "new-password".to_string(),
        };
        let result = confirm_password_reset(State(state.clone()), ApiJson(req)).await;
        assert_eq!(result.map(|Json(body)| body.user_id), Ok(user_id));

        assert_eq!(
            state
                .email_verification
                .sessions
                .get_session(&session)
                .await,
            None
        );
        // Someone else's session is untouched.
        assert!(
            state
                .email_verification
                .sessions
                .get_session(&other)
                .await
                .is_some()
        );
    }

    // Someone who squatted the address can burn guesses just before the owner
    // resets the password; the lockout must not outlive the reset.
    #[tokio::test]
    async fn confirm_clears_a_verification_lockout() {
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2("old-hash".into())),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        state.email_verification.codes =
            crate::storage::in_memory::InMemoryEmailVerificationCodeStorage::new(900, 0);
        lock_out(&mut state, user_id).await;
        assert!(matches!(
            state
                .email_verification
                .codes
                .check_code(user_id, "123456789")
                .await,
            CheckCodeOutcome::Locked { .. }
        ));
        let token = issued_token(&mut state, user_id).await;

        let req = PasswordResetConfirmRequest {
            token,
            new_password: "new-password".to_string(),
        };
        let result = confirm_password_reset(State(state.clone()), ApiJson(req)).await;
        assert_eq!(result.map(|Json(body)| body.user_id), Ok(user_id));

        assert!(matches!(
            state.email_verification.codes.issue_code(user_id).await,
            IssueCodeOutcome::Issued(_)
        ));
    }

    #[tokio::test]
    async fn a_second_request_leaves_the_first_link_working_and_a_reset_spends_both() {
        let mut state = state();
        let _rx = with_recorder(&mut state);
        let user = User {
            email: "alice@example.com".to_string(),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let first_token = issued_token(&mut state, user_id).await;

        // Through the real handler: an attacker re-requesting for the owner.
        assert_eq!(
            request(&state, "alice@example.com").await,
            StatusCode::ACCEPTED
        );
        assert_eq!(state.password_reset_tokens.token_count().await, 2);

        let req = PasswordResetConfirmRequest {
            token: first_token,
            new_password: "new-password".to_string(),
        };
        let result = confirm_password_reset(State(state.clone()), ApiJson(req)).await;
        assert_eq!(result.map(|Json(body)| body.user_id), Ok(user_id));
        assert_eq!(state.password_reset_tokens.token_count().await, 0);
    }

    fn with_recorder(state: &mut AppState) -> mpsc::UnboundedReceiver<Sent> {
        install_recorder(state, false)
    }

    async fn request(state: &AppState, email: &str) -> StatusCode {
        let req = PasswordResetRequestRequest {
            email: email.to_string(),
        };
        request_password_reset(State(state.clone()), ApiJson(req)).await
    }

    fn reset_url_of(sent: Sent) -> String {
        match sent.kind {
            EmailKind::PasswordReset { reset_url } => reset_url,
            other => unreachable!("not a password reset email: {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_mails_a_working_reset_link_to_the_stored_address_only() {
        let mut state = state();
        let mut rx = with_recorder(&mut state);
        let user = User {
            email: "alice@example.com".to_string(),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;

        // Found through normalization, but the mail goes to the account's own
        // address, never to what the caller typed.
        let status = request(&state, " Alice+attacker@Example.com").await;

        assert_eq!(status, StatusCode::ACCEPTED);
        let sent = next_sent(&mut rx).await;
        assert_eq!(sent.email, "alice@example.com");
        let expires_in = sent.expires_at - chrono::Utc::now();
        assert!(
            (1_795..=1_800).contains(&expires_in.num_seconds()),
            "{expires_in}"
        );
        let reset_url = reset_url_of(sent);
        let token = reset_url
            .strip_prefix("https://login.test/reset-password.html#token=")
            .expect("token travels in the fragment of login's reset page");
        let req = PasswordResetConfirmRequest {
            token: token.to_string(),
            new_password: "new-password".to_string(),
        };
        assert_eq!(
            confirm_password_reset(State(state.clone()), ApiJson(req))
                .await
                .map(|Json(body)| body.user_id),
            Ok(user_id)
        );
        assert!(
            state
                .users
                .get_user_by_id(user_id)
                .await
                .unwrap()
                .password
                .is_some()
        );
    }

    #[tokio::test]
    async fn request_for_an_unknown_email_sends_nothing() {
        let mut state = state();
        let mut rx = with_recorder(&mut state);

        let status = request(&state, "nobody@example.com").await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn a_request_within_the_cooldown_sends_nothing_and_answers_the_same() {
        let mut state = state();
        state.password_reset_tokens =
            crate::storage::in_memory::InMemoryPasswordResetTokenStorage::new(1_800, 60);
        let mut rx = with_recorder(&mut state);
        let _ = state
            .users
            .create_user(User {
                email: "alice@example.com".to_string(),
                ..User::default()
            })
            .await;
        assert_eq!(
            request(&state, "alice@example.com").await,
            StatusCode::ACCEPTED
        );
        let _ = next_sent(&mut rx).await;

        let status = request(&state, "alice@example.com").await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn request_issues_no_token_when_no_email_handler_is_configured() {
        let mut state = state();
        let _ = state
            .users
            .create_user(User {
                email: "alice@example.com".to_string(),
                ..User::default()
            })
            .await;

        let status = request(&state, "alice@example.com").await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(state.password_reset_tokens.token_count().await, 0);
    }

    #[tokio::test]
    async fn confirm_rejects_a_weak_password_without_spending_the_token() {
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2("old-hash".into())),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let token = issued_token(&mut state, user_id).await;

        let weak = PasswordResetConfirmRequest {
            token: token.clone(),
            new_password: "short".to_string(),
        };
        let result = confirm_password_reset(State(state.clone()), ApiJson(weak)).await;
        assert_eq!(result.err(), Some(PasswordResetConfirmError::WeakPassword));
        let unchanged = state.users.get_user_by_id(user_id).await.unwrap();
        assert_eq!(unchanged.password.unwrap().expose(), ("argon2", "old-hash"));

        let retry = PasswordResetConfirmRequest {
            token,
            new_password: "long-enough".to_string(),
        };
        let result = confirm_password_reset(State(state), ApiJson(retry)).await;
        assert_eq!(result.map(|Json(body)| body.user_id), Ok(user_id));
    }

    #[tokio::test]
    async fn confirm_marks_the_email_verified() {
        // Redeeming the token proves control of the mailbox it was sent to.
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            email_verified: false,
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let token = issued_token(&mut state, user_id).await;

        let req = PasswordResetConfirmRequest {
            token,
            new_password: "new-password".to_string(),
        };
        let result = confirm_password_reset(State(state.clone()), ApiJson(req)).await;

        assert_eq!(result.map(|Json(body)| body.user_id), Ok(user_id));
        assert!(
            state
                .users
                .get_user_by_id(user_id)
                .await
                .unwrap()
                .email_verified
        );
    }

    #[tokio::test]
    async fn confirm_rejects_an_unknown_or_expired_token() {
        let state = state();
        let req = PasswordResetConfirmRequest {
            token: "no-such-token".to_string(),
            new_password: "new-password".to_string(),
        };

        let result = confirm_password_reset(State(state), ApiJson(req)).await;

        assert_eq!(
            result.err(),
            Some(PasswordResetConfirmError::InvalidOrExpiredToken)
        );
    }
}
