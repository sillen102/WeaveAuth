pub(crate) use controller::register;
pub(crate) use controller::register_doc;

mod controller {
    use aide::transform::TransformOperation;
    use argon2::PasswordHasher;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::Json;
    use chrono::Utc;
    use schemars::JsonSchema;
    use serde::Deserialize;
    use thiserror::Error;
    use uuid::Uuid;
    use common_macros::ErrorResponses;

    use crate::crypto::ARGON2;
    use crate::model::user::User;
    use crate::server::AppState;
    use crate::storage::UserStorage;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct RegisterRequest {
        pub(super) identifier: String,
        pub(super) password: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum RegisterError {
        #[error("identifier already taken")]
        #[error_response(StatusCode::CONFLICT, details = "identifier already taken")]
        IdentifierTaken,
        #[error("internal error")]
        #[error_response(StatusCode::INTERNAL_SERVER_ERROR)]
        UnexpectedError,
    }

    pub(crate) async fn register(
        State(mut state): State<AppState>,
        Json(req): Json<RegisterRequest>,
    ) -> Result<StatusCode, RegisterError> {
        // Argon2 is deliberately CPU-heavy, synchronous work; spawn_blocking keeps
        // it off this tokio worker thread so it doesn't stall other tasks while
        // hashing.
        let password = req.password;
        let password_hash = tokio::task::spawn_blocking(move || {
            ARGON2
                .hash_password(password.as_bytes())
                .map(|h| h.to_string())
        })
        .await
        .map_err(|_| RegisterError::UnexpectedError)?
        .map_err(|_| RegisterError::UnexpectedError)?;

        let now = Utc::now();
        let saved = state
            .users
            .create_user(User {
                id: Uuid::new_v4(),
                identifier: req.identifier,
                password: password_hash,
                created_at: now,
                updated_at: now,
            })
            .await;

        if !saved {
            return Err(RegisterError::IdentifierTaken);
        }

        Ok(StatusCode::CREATED)
    }

    // OpenAPI documentation for this route.
    pub(crate) fn register_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("register")
            .summary("Register a new user")
            .description(
                "Creates a user with a password hashed via Argon2; 409 if the identifier is \
                 already taken",
            )
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
        }
    }

    #[tokio::test]
    async fn registers_user_with_hashed_password() {
        let state = state();
        let req = RegisterRequest {
            identifier: "alice".to_string(),
            password: "hunter2".to_string(),
        };

        let result = register(State(state.clone()), Json(req)).await;

        assert_eq!(result, Ok(StatusCode::CREATED));
    }

    #[tokio::test]
    async fn rejects_a_taken_identifier() {
        let state = state();
        let first = RegisterRequest {
            identifier: "alice".to_string(),
            password: "hunter2".to_string(),
        };
        let second = RegisterRequest {
            identifier: "alice".to_string(),
            password: "different-password".to_string(),
        };

        let first_result = register(State(state.clone()), Json(first)).await;
        let second_result = register(State(state), Json(second)).await;

        assert_eq!(first_result, Ok(StatusCode::CREATED));
        assert_eq!(second_result, Err(RegisterError::IdentifierTaken));
    }
}
