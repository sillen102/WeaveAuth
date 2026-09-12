pub(crate) use controller::login;
pub(crate) use controller::login_doc;

mod controller {
    use aide::transform::TransformOperation;
    use argon2::password_hash::PasswordHash;
    use argon2::{Argon2, PasswordVerifier};
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::Json;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    use crate::server::AppState;
    use crate::storage::{LoginSessionStorage, UserStorage};

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct LoginRequest {
        pub(super) identifier: String,
        pub(super) password: String,
    }

    #[derive(Serialize, JsonSchema)]
    pub(crate) struct LoginResponse {
        /// Single-use proof of this authentication, required by `/oauth/authorize`.
        pub(super) login_session: String,
    }

    // OpenAPI documentation for this route.
    pub(crate) fn login_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("login")
            .summary("Authenticate a user")
            .description(
                "Checks identifier/password against stored users and, on success, returns a \
                 short-lived login_session token that /oauth/authorize requires before it will \
                 issue a code -- this is what makes authentication happen before authorization \
                 regardless of what order a caller invokes the two endpoints in",
            )
    }

    pub(crate) async fn login(
        State(mut state): State<AppState>,
        Json(req): Json<LoginRequest>,
    ) -> Result<Json<LoginResponse>, StatusCode> {
        let user = state
            .users
            .get_user_by_identifier(&req.identifier)
            .await
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let hash = PasswordHash::new(&user.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &hash)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let login_session = state.login_sessions.create_session(user.id).await;
        Ok(Json(LoginResponse { login_session }))
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use crate::model::user::User;
    use crate::server::AppState;
    use crate::storage::in_memory::{
        InMemoryLoginSessionStorage, InMemoryPkceStorage, InMemoryUserStorage,
    };
    use crate::storage::UserStorage;
    use argon2::password_hash::rand_core::OsRng;
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};
    use axum::extract::{Json, State};
    use axum::http::StatusCode;
    use std::sync::Arc;

    async fn state_with_user(identifier: &str, password: &str) -> AppState {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let mut users = InMemoryUserStorage::new();
        users
            .save_user(User {
                identifier: identifier.to_string(),
                password: hash,
                ..User::default()
            })
            .await;

        AppState {
            pkce: InMemoryPkceStorage::new(300),
            users,
            login_sessions: InMemoryLoginSessionStorage::new(60),
            redirect_uri_allowlist: Arc::new(vec![]),
        }
    }

    #[tokio::test]
    async fn accepts_correct_credentials_and_returns_a_login_session() {
        let state = state_with_user("alice", "hunter2").await;
        let req = LoginRequest {
            identifier: "alice".to_string(),
            password: "hunter2".to_string(),
        };

        let Json(body) = login(State(state), Json(req)).await.unwrap();

        assert!(!body.login_session.is_empty());
    }

    #[tokio::test]
    async fn rejects_wrong_password() {
        let state = state_with_user("alice", "hunter2").await;
        let req = LoginRequest {
            identifier: "alice".to_string(),
            password: "wrong".to_string(),
        };

        let result = login(State(state), Json(req)).await;

        assert_eq!(result.err(), Some(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn rejects_unknown_identifier() {
        let state = state_with_user("alice", "hunter2").await;
        let req = LoginRequest {
            identifier: "bob".to_string(),
            password: "hunter2".to_string(),
        };

        let result = login(State(state), Json(req)).await;

        assert_eq!(result.err(), Some(StatusCode::UNAUTHORIZED));
    }
}