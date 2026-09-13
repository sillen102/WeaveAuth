pub(crate) use controller::login;
pub(crate) use controller::login_doc;

mod controller {
    use aide::transform::TransformOperation;
    use argon2::password_hash::phc::PasswordHash;
    use argon2::{PasswordHasher, PasswordVerifier};
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::Json;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use std::sync::LazyLock;
    use thiserror::Error;
    use common_macros::ErrorResponses;

    use crate::crypto::ARGON2;
    use crate::server::AppState;
    use crate::storage::{LoginSessionStorage, UserStorage};

    /// A valid Argon2 hash of a fixed, made-up password -- verified against on the
    /// "unknown identifier" path so it costs the same as the real
    /// hash-and-compare below, instead of returning instantly. Without this, an
    /// attacker can enumerate valid usernames purely from response timing (a
    /// known identifier with a wrong password pays for a full Argon2 hash before
    /// failing; an unknown one previously failed immediately).
    static DUMMY_PASSWORD_HASH: LazyLock<String> = LazyLock::new(|| {
        ARGON2
            .hash_password(b"not-a-real-password")
            .expect("hashing a fixed password never fails")
            .to_string()
    });

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

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum LoginError {
        #[error("invalid credentials")]
        #[error_response(StatusCode::UNAUTHORIZED, details = "invalid credentials")]
        InvalidCredentials,
        #[error("internal error")]
        #[error_response(StatusCode::INTERNAL_SERVER_ERROR)]
        UnexpectedError,
    }

    pub(crate) async fn login(
        State(mut state): State<AppState>,
        Json(req): Json<LoginRequest>,
    ) -> Result<Json<LoginResponse>, LoginError> {
        let user = state.users.get_user_by_identifier(&req.identifier).await;

        // Always hash, even for an unknown identifier (against a fixed dummy hash)
        // -- see DUMMY_PASSWORD_HASH. Both branches pay the same Argon2 cost, so
        // response timing can't be used to enumerate valid identifiers. Run it via
        // spawn_blocking: Argon2 is deliberately CPU-heavy, synchronous work, and
        // doing it inline would block this tokio worker thread from servicing any
        // other task while it hashes.
        let hash_str = user
            .as_ref()
            .map_or_else(|| DUMMY_PASSWORD_HASH.clone(), |u| u.password.clone());
        let password = req.password;
        let verified = tokio::task::spawn_blocking(move || -> Result<bool, ()> {
            let hash = PasswordHash::new(&hash_str).map_err(|_| ())?;
            Ok(ARGON2.verify_password(password.as_bytes(), &hash).is_ok())
        })
        .await
        .map_err(|_| LoginError::UnexpectedError)?
        .map_err(|_| LoginError::UnexpectedError)?;

        let user = user.filter(|_| verified).ok_or(LoginError::InvalidCredentials)?;

        let login_session = state.login_sessions.create_session(user.id).await;
        Ok(Json(LoginResponse { login_session }))
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
    use argon2::PasswordHasher;
    use axum::extract::{Json, State};
    use std::sync::Arc;

    use crate::crypto::ARGON2;

    async fn state_with_user(identifier: &str, password: &str) -> AppState {
        let hash = ARGON2
            .hash_password(password.as_bytes())
            .expect("hashing a test password never fails")
            .to_string();

        let mut users = InMemoryUserStorage::new();
        users
            .create_user(User {
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
            jwt_keys: crate::storage::in_memory::InMemoryJwkStorage::new().expect("RSA keygen for tests never fails"),
            access_token_ttl_secs: 900,
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

        assert_eq!(result.err(), Some(LoginError::InvalidCredentials));
    }

    #[tokio::test]
    async fn rejects_unknown_identifier() {
        let state = state_with_user("alice", "hunter2").await;
        let req = LoginRequest {
            identifier: "bob".to_string(),
            password: "hunter2".to_string(),
        };

        let result = login(State(state), Json(req)).await;

        assert_eq!(result.err(), Some(LoginError::InvalidCredentials));
    }

    #[tokio::test]
    async fn unknown_identifier_pays_the_same_argon2_cost_as_a_known_one() {
        // Regression guard for the username-enumeration timing hole: an unknown
        // identifier must still run a full Argon2 hash, not return instantly.
        // We don't assert a tight ratio against the known-identifier path (flaky
        // under load); an absolute floor is enough to catch a short-circuit.
        let state = state_with_user("alice", "hunter2").await;
        let req = LoginRequest {
            identifier: "no-such-user".to_string(),
            password: "whatever".to_string(),
        };

        let started = std::time::Instant::now();
        let result = login(State(state), Json(req)).await;
        let elapsed = started.elapsed();

        assert_eq!(result.err(), Some(LoginError::InvalidCredentials));
        assert!(
            elapsed > std::time::Duration::from_millis(1),
            "unknown-identifier login returned in {elapsed:?} -- looks like it short-circuited \
             before hashing, which reopens the username-enumeration timing hole"
        );
    }
}
