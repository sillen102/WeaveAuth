pub(crate) use controller::confirm_password_reset;
pub(crate) use controller::confirm_password_reset_doc;
pub(crate) use controller::request_password_reset;
pub(crate) use controller::request_password_reset_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::Json;
    use schemars::JsonSchema;
    use serde::Deserialize;

    use crate::server::AppState;

    use super::service;
    pub(crate) use super::service::PasswordResetConfirmError;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct PasswordResetRequestRequest {
        pub(super) email: String,
    }

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct PasswordResetConfirmRequest {
        pub(super) token: String,
        pub(super) new_password: String,
    }

    pub(crate) async fn request_password_reset(
        State(mut state): State<AppState>,
        Json(req): Json<PasswordResetRequestRequest>,
    ) -> StatusCode {
        service::request_password_reset(&mut state, &req.email).await;
        StatusCode::ACCEPTED
    }

    pub(crate) async fn confirm_password_reset(
        State(mut state): State<AppState>,
        Json(req): Json<PasswordResetConfirmRequest>,
    ) -> Result<StatusCode, PasswordResetConfirmError> {
        service::confirm_password_reset(&mut state, &req.token, req.new_password).await?;
        Ok(StatusCode::OK)
    }

    pub(crate) fn request_password_reset_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("request_password_reset")
            .summary("Request a password reset")
            .description(
                "Always returns 202, whether or not `email` matches an account, so the \
                 response can't be used to enumerate registered addresses. The issued token \
                 is never included in the response or logged; delivering it to the account \
                 owner is out of scope for this endpoint.",
            )
    }

    pub(crate) fn confirm_password_reset_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("confirm_password_reset")
            .summary("Redeem a password reset token")
            .description(
                "Sets a new password on the account `token` was issued for, and revokes every \
                 outstanding refresh token and login session for that account; 400 if the \
                 token is unknown, expired, or already used.",
            )
    }
}

mod service {
    use axum::http::StatusCode;
    use thiserror::Error;
    use common_macros::ErrorResponses;

    use crate::crypto;
    use crate::model::email::normalize_email;
    use crate::model::user::PasswordHash;
    use crate::server::AppState;
    use crate::storage::{
        LoginSessionStorage, PasswordResetTokenStorage, RefreshTokenStorage, RevokeOutcome,
        SetPasswordOutcome, UserStorage,
    };

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum PasswordResetConfirmError {
        #[error("invalid or expired password reset token")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid or expired password reset token")]
        InvalidOrExpiredToken,
        #[error("internal error")]
        #[error_response(StatusCode::INTERNAL_SERVER_ERROR)]
        UnexpectedError,
    }

    /// Issues a single-use password reset token for the account matching
    /// `email`, if any.
    ///
    /// The token is deliberately not surfaced anywhere in this response (nor
    /// logged) -- delivering it to the account owner is the caller's job
    /// (e.g. by email), never this endpoint's.
    pub(crate) async fn request_password_reset(state: &mut AppState, email: &str) {
        let email = normalize_email(email);
        if let Some(user) = state.users.get_user_by_email(&email).await {
            let _token = state.password_reset_tokens.save_reset_token(user.id).await;
        }

        // Same response whether or not `email` matched an account -- an
        // account-existence oracle here would let a caller enumerate
        // registered addresses, the same concern `/oauth/login`'s dummy-hash
        // check (see login.rs) exists to close off.
    }

    /// Redeems a password reset token, setting a new password on the account
    /// it was issued for.
    pub(crate) async fn confirm_password_reset(
        state: &mut AppState,
        token: &str,
        new_password: String,
    ) -> Result<(), PasswordResetConfirmError> {
        let user_id = state
            .password_reset_tokens
            .take_reset_token(token)
            .await
            .ok_or(PasswordResetConfirmError::InvalidOrExpiredToken)?;

        // A password reset is the standard remediation for "my account may
        // be compromised" -- that only actually remediates anything if it
        // also kills any refresh token or login session an attacker already
        // holds. Revoked once *before* the password changes (so nothing an
        // attacker already held survives this call) and once *after* (so a
        // token/session created in the narrow window between this line and
        // `set_password` below -- e.g. a concurrent login racing this
        // request -- doesn't survive it either). Neither revocation is
        // allowed to fail silently: `RevokeOutcome::Failed` here means a
        // durable backend's delete errored, which is exactly the case this
        // whole flow exists to not paper over with a 200.
        revoke_everything_for(state, user_id).await?;

        let password_hash = crypto::hash_password(new_password)
            .await
            .map_err(|_| PasswordResetConfirmError::UnexpectedError)?;

        match state.users.set_password(user_id, PasswordHash::Argon2(password_hash)).await {
            SetPasswordOutcome::Ok => {}
            // The token was valid a moment ago but the account is gone now --
            // vanishingly unlikely (nothing in this codebase deletes users),
            // but report it as the same not-found-shaped error rather than a
            // 500, since from the caller's perspective the token just doesn't
            // resolve to anything anymore.
            SetPasswordOutcome::UserNotFound => return Err(PasswordResetConfirmError::InvalidOrExpiredToken),
        }

        revoke_everything_for(state, user_id).await?;

        Ok(())
    }

    async fn revoke_everything_for(state: &mut AppState, user_id: uuid::Uuid) -> Result<(), PasswordResetConfirmError> {
        if state.refresh_tokens.revoke_all_for_user(user_id).await == RevokeOutcome::Failed {
            return Err(PasswordResetConfirmError::UnexpectedError);
        }
        if state.login_sessions.revoke_all_for_user(user_id).await == RevokeOutcome::Failed {
            return Err(PasswordResetConfirmError::UnexpectedError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use crate::model::user::{PasswordHash, User};
    use crate::server::AppState;
    use crate::storage::{LoginSessionStorage, PasswordResetTokenStorage, RefreshTokenStorage, UserStorage};
    use axum::extract::{Json, State};
    use axum::http::StatusCode;
    use std::sync::Arc;
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
            oidc_providers: Arc::new(std::collections::HashMap::new()),
            oidc_state: crate::storage::in_memory::InMemoryOidcStateStorage::new(300),
            pending_oidc_links: crate::storage::in_memory::InMemoryPendingOidcLinkStorage::new(300),
            oidc_http_client: Arc::new(openidconnect::reqwest::Client::new()),
            password_reset_tokens: crate::storage::in_memory::InMemoryPasswordResetTokenStorage::new(1_800),
            max_bcrypt_cost: 12,
        }
    }

    #[tokio::test]
    async fn request_returns_accepted_for_a_known_email_and_issues_a_token() {
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            ..User::default()
        };
        let _ = state.users.create_user(user).await;

        let req = PasswordResetRequestRequest {
            email: "alice@example.com".to_string(),
        };
        let status = request_password_reset(State(state.clone()), Json(req)).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(state.password_reset_tokens.token_count().await, 1);
    }

    #[tokio::test]
    async fn request_returns_the_same_accepted_status_for_an_unknown_email() {
        // No account-existence oracle: an unknown email gets the exact same
        // response as a known one.
        let state = state();
        let req = PasswordResetRequestRequest {
            email: "nobody@example.com".to_string(),
        };

        let status = request_password_reset(State(state), Json(req)).await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn confirm_sets_a_new_password_and_is_single_use() {
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2("old-hash".to_string())),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let token = state.password_reset_tokens.save_reset_token(user_id).await;

        let req = PasswordResetConfirmRequest {
            token: token.clone(),
            new_password: "new-password".to_string(),
        };
        let result = confirm_password_reset(State(state.clone()), Json(req)).await;
        assert_eq!(result, Ok(StatusCode::OK));

        let updated = state.users.get_user_by_id(user_id).await.unwrap();
        assert_ne!(updated.password, Some(PasswordHash::Argon2("old-hash".to_string())));

        // Single-use: the same token can't be redeemed twice.
        let replay = PasswordResetConfirmRequest {
            token,
            new_password: "another-password".to_string(),
        };
        let replay_result = confirm_password_reset(State(state), Json(replay)).await;
        assert_eq!(replay_result, Err(PasswordResetConfirmError::InvalidOrExpiredToken));
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
            password: Some(PasswordHash::Argon2("old-hash".to_string())),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        state
            .refresh_tokens
            .save_refresh_token("refresh-token".to_string(), user_id, Uuid::new_v4())
            .await;
        let login_session = state.login_sessions.create_session(user_id).await;
        let token = state.password_reset_tokens.save_reset_token(user_id).await;

        let req = PasswordResetConfirmRequest {
            token,
            new_password: "new-password".to_string(),
        };
        let result = confirm_password_reset(State(state.clone()), Json(req)).await;
        assert_eq!(result, Ok(StatusCode::OK));

        assert_eq!(
            state.refresh_tokens.take_refresh_token("refresh-token").await,
            crate::storage::RefreshTokenOutcome::NotFound
        );
        assert_eq!(state.login_sessions.take_session(&login_session).await, None);
    }

    #[tokio::test]
    async fn a_second_request_invalidates_the_first_token() {
        // Otherwise every unexpired token from an earlier request stays
        // independently redeemable, widening the window a leaked link stays
        // dangerous and letting an unauthenticated caller grow the token
        // table without bound by re-requesting the same email.
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;

        let stale_token = state.password_reset_tokens.save_reset_token(user_id).await;

        // The second issuance goes through the real handler, not another
        // direct `save_reset_token` call -- this is what actually exercises
        // `/oauth/password-reset/request`'s behavior instead of just
        // re-testing the storage layer's own invariant.
        let req = PasswordResetRequestRequest {
            email: "alice@example.com".to_string(),
        };
        request_password_reset(State(state.clone()), Json(req)).await;

        assert_eq!(state.password_reset_tokens.take_reset_token(&stale_token).await, None);
        assert_eq!(state.password_reset_tokens.token_count().await, 1);
    }

    #[tokio::test]
    async fn confirm_rejects_an_unknown_or_expired_token() {
        let state = state();
        let req = PasswordResetConfirmRequest {
            token: "no-such-token".to_string(),
            new_password: "new-password".to_string(),
        };

        let result = confirm_password_reset(State(state), Json(req)).await;

        assert_eq!(result.err(), Some(PasswordResetConfirmError::InvalidOrExpiredToken));
    }
}
