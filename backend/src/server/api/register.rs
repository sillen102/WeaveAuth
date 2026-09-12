pub(crate) use controller::register;
pub(crate) use controller::register_doc;

mod controller {
    use aide::transform::TransformOperation;
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;
    use rand_core::OsRng;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::Json;
    use chrono::Utc;
    use schemars::JsonSchema;
    use serde::Deserialize;
    use uuid::Uuid;

    use crate::crypto::ARGON2;
    use crate::model::user::User;
    use crate::server::AppState;
    use crate::storage::UserStorage;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct RegisterRequest {
        pub(super) identifier: String,
        pub(super) password: String,
    }

    // OpenAPI documentation for this route.
    pub(crate) fn register_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("register")
            .summary("Register a new user")
            .description("Creates a user with a password hashed via Argon2")
    }

    pub(crate) async fn register(
        State(mut state): State<AppState>,
        Json(req): Json<RegisterRequest>,
    ) -> Result<StatusCode, StatusCode> {
        // Argon2 is deliberately CPU-heavy, synchronous work; spawn_blocking keeps
        // it off this tokio worker thread so it doesn't stall other tasks while
        // hashing.
        let password = req.password;
        let password_hash = tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            ARGON2
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let now = Utc::now();
        state
            .users
            .save_user(User {
                id: Uuid::new_v4(),
                identifier: req.identifier,
                password: password_hash,
                created_at: now,
                updated_at: now,
            })
            .await;

        Ok(StatusCode::CREATED)
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
}
