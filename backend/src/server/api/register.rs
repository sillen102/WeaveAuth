pub(crate) use controller::register;
pub(crate) use controller::register_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::Json;
    use schemars::JsonSchema;
    use serde::Deserialize;

    use crate::server::AppState;

    use super::service;
    pub(crate) use super::service::RegisterError;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct RegisterRequest {
        pub(super) email: String,
        pub(super) password: String,
    }

    pub(crate) async fn register(
        State(mut state): State<AppState>,
        Json(req): Json<RegisterRequest>,
    ) -> Result<StatusCode, RegisterError> {
        service::register(&mut state, req.email, req.password.into()).await?;
        Ok(StatusCode::CREATED)
    }

    // OpenAPI documentation for this route.
    pub(crate) fn register_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("register")
            .summary("Register a new user")
            .description(
                "Creates a user with a password hashed via Argon2; 400 if the email is not a \
                 valid address, 409 if it's already taken",
            )
    }
}

mod service {
    use axum::http::StatusCode;
    use chrono::Utc;
    use email_address::EmailAddress;
    use thiserror::Error;
    use uuid::Uuid;
    use common_macros::ErrorResponses;

    use secrecy::SecretString;

    use crate::crypto;
    use crate::model::email::normalize_email;
    use crate::model::user::{PasswordHash, User};
    use crate::server::AppState;
    use crate::storage::{CreateUserOutcome, UserStorage};

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum RegisterError {
        #[error("invalid email address")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid email address")]
        InvalidEmail,
        #[error("email already taken")]
        #[error_response(StatusCode::CONFLICT, details = "email already taken")]
        EmailTaken,
        #[error("internal error")]
        #[error_response(StatusCode::INTERNAL_SERVER_ERROR)]
        UnexpectedError,
    }

    pub(crate) async fn register(
        state: &mut AppState,
        email: String,
        password: SecretString,
    ) -> Result<(), RegisterError> {
        let email = normalize_email(&email);
        if !EmailAddress::is_valid(&email) {
            return Err(RegisterError::InvalidEmail);
        }

        let password_hash = crypto::hash_password(password).await.map_err(|_| RegisterError::UnexpectedError)?;

        let now = Utc::now();
        let outcome = state
            .users
            .create_user(User {
                id: Uuid::new_v4(),
                email,
                password: Some(PasswordHash::Argon2(password_hash.into())),
                // This app has no verification-email flow of its own -- only
                // an OIDC provider confirming the address (see
                // `UserStorage::link_or_create_oidc_user`) flips this to true.
                email_verified: false,
                created_at: now,
                updated_at: now,
            })
            .await;

        match outcome {
            CreateUserOutcome::Created => Ok(()),
            CreateUserOutcome::EmailTaken => Err(RegisterError::EmailTaken),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use crate::storage::in_memory::InMemoryUserStorage;
    use crate::server::AppState;
    use axum::extract::{Json, State};
    use axum::http::StatusCode;
    use std::sync::Arc;

    fn state() -> AppState {
        AppState {
            pkce: crate::storage::in_memory::InMemoryPkceStorage::new(300),
            users: InMemoryUserStorage::new(),
            login_sessions: crate::storage::in_memory::InMemoryLoginSessionStorage::new(60),
            redirect_uri_allowlist: Arc::new(vec![]),
            jwt_keys: crate::storage::in_memory::InMemoryJwkStorage::new().expect("RSA keygen for tests never fails"),
            access_token_ttl_secs: 900,
            refresh_tokens: crate::storage::in_memory::InMemoryRefreshTokenStorage::new(2_592_000),
            refresh_token_ttl_secs: 2_592_000,
            oidc_providers: std::sync::Arc::new(std::collections::HashMap::new()),
            oidc_state: crate::storage::in_memory::InMemoryOidcStateStorage::new(300),
            pending_oidc_links: crate::storage::in_memory::InMemoryPendingOidcLinkStorage::new(300),
            oidc_http_client: std::sync::Arc::new(openidconnect::reqwest::Client::new()),
            password_reset_tokens: crate::storage::in_memory::InMemoryPasswordResetTokenStorage::new(1_800),
            max_bcrypt_cost: 12,
        }
    }

    #[tokio::test]
    async fn registers_user_with_hashed_password() {
        let state = state();
        let req = RegisterRequest {
            email: "alice@example.com".to_string(),
            password: "hunter2".to_string(),
        };

        let result = register(State(state.clone()), Json(req)).await;

        assert_eq!(result, Ok(StatusCode::CREATED));
    }

    #[tokio::test]
    async fn rejects_an_invalid_email() {
        let state = state();
        let req = RegisterRequest {
            email: "not-an-email".to_string(),
            password: "hunter2".to_string(),
        };

        let result = register(State(state), Json(req)).await;

        assert_eq!(result, Err(RegisterError::InvalidEmail));
    }

    #[tokio::test]
    async fn rejects_a_taken_email() {
        let state = state();
        let first = RegisterRequest {
            email: "alice@example.com".to_string(),
            password: "hunter2".to_string(),
        };
        let second = RegisterRequest {
            email: "alice@example.com".to_string(),
            password: "different-password".to_string(),
        };

        let first_result = register(State(state.clone()), Json(first)).await;
        let second_result = register(State(state), Json(second)).await;

        assert_eq!(first_result, Ok(StatusCode::CREATED));
        assert_eq!(second_result, Err(RegisterError::EmailTaken));
    }
}
