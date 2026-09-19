pub(crate) use controller::login;
pub(crate) use controller::login_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::Json;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;
    use common_macros::ErrorResponses;

    use crate::server::AppState;

    use super::service;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct LoginRequest {
        pub(super) email: String,
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

    impl From<service::LoginServiceError> for LoginError {
        fn from(err: service::LoginServiceError) -> Self {
            match err {
                service::LoginServiceError::InvalidCredentials => LoginError::InvalidCredentials,
                service::LoginServiceError::UnexpectedError => LoginError::UnexpectedError,
            }
        }
    }

    // OpenAPI documentation for this route.
    pub(crate) fn login_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("login")
            .summary("Authenticate a user")
            .description(
                "Checks email/password against stored users and, on success, returns a \
                 short-lived login_session token that /oauth/authorize requires before it will \
                 issue a code -- this is what makes authentication happen before authorization \
                 regardless of what order a caller invokes the two endpoints in",
            )
    }

    pub(crate) async fn login(
        State(mut state): State<AppState>,
        Json(req): Json<LoginRequest>,
    ) -> Result<Json<LoginResponse>, LoginError> {
        let login_session = service::login(&mut state, &req.email, req.password.into()).await?;
        Ok(Json(LoginResponse { login_session }))
    }
}

mod service {
    use secrecy::SecretString;
    use thiserror::Error;

    use crate::crypto;
    use crate::model::email::normalize_email;
    use crate::model::user::PasswordHash;
    use crate::server::AppState;
    use crate::storage::{LoginSessionStorage, UserStorage};

    /// A valid Argon2 hash of a fixed, made-up password -- verified against on the
    /// "unknown email" path so it costs the same as the real hash-and-compare
    /// below, instead of returning instantly. Without this, an attacker can
    /// enumerate registered emails purely from response timing (a known email
    /// with a wrong password pays for a full Argon2 hash before failing; an
    /// unknown one previously failed immediately).
    ///
    /// A fixed literal, not computed at startup: hashing is fallible in
    /// principle (clippy denies the `expect()` that would be needed to unwrap
    /// it), and there's no benefit to hashing a constant input at runtime --
    /// it always produces a hash with the same cost, whether computed once
    /// at build time or once at first request.
    const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$+asaoNd4judQBozzpttaCQ$WFrspw+VJ+HAPOXqRwravZFYap0GT3yyfgRf5ZVv6qc";

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum LoginServiceError {
        #[error("invalid credentials")]
        InvalidCredentials,
        #[error("internal error")]
        UnexpectedError,
    }

    pub(crate) async fn login(
        state: &mut AppState,
        email: &str,
        password: SecretString,
    ) -> Result<String, LoginServiceError> {
        let user = state.users.get_user_by_email(&normalize_email(email)).await;

        // Hash even for an unknown email (DUMMY_PASSWORD_HASH) so timing can't enumerate registered emails.
        let hash = user
            .as_ref()
            .and_then(|u| u.password.clone())
            .unwrap_or_else(|| PasswordHash::Argon2(DUMMY_PASSWORD_HASH.into()));
        match crypto::verify_password(hash, password.clone(), state.max_bcrypt_cost).await {
            Ok(crypto::PasswordVerifyOutcome::Verified) => {}
            Ok(crypto::PasswordVerifyOutcome::NotVerified) => return Err(LoginServiceError::InvalidCredentials),
            Err(_) => return Err(LoginServiceError::UnexpectedError),
        }

        let user = user.ok_or(LoginServiceError::InvalidCredentials)?;

        if matches!(user.password, Some(PasswordHash::Bcrypt(_))) {
            crate::server::api::upgrade_bcrypt_to_argon2(&mut state.users, user.id, password).await;
        }

        let login_session = state.login_sessions.create_session(user.id).await;
        Ok(login_session)
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use crate::model::user::{PasswordHash, User};
    use crate::server::AppState;
    use crate::storage::in_memory::{
        InMemoryLoginSessionStorage, InMemoryPkceStorage, InMemoryUserStorage,
    };
    use crate::storage::UserStorage;
    use argon2::PasswordHasher;
    use axum::extract::{Json, State};
    use std::sync::Arc;

    use crate::crypto::ARGON2;

    async fn state_with_user_password(email: &str, password_hash: PasswordHash) -> AppState {
        let mut users = InMemoryUserStorage::new();
        let _ = users
            .create_user(User {
                email: email.to_string(),
                password: Some(password_hash),
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
            refresh_tokens: crate::storage::in_memory::InMemoryRefreshTokenStorage::new(2_592_000),
            refresh_token_ttl_secs: 2_592_000,
            oidc_providers: std::sync::Arc::new(std::collections::HashMap::new()),
            oidc_state: crate::storage::in_memory::InMemoryOidcStateStorage::new(300),
            pending_oidc_links: crate::storage::in_memory::InMemoryPendingOidcLinkStorage::new(300),
            oidc_http_client: std::sync::Arc::new(openidconnect::reqwest::Client::new()),
            password_reset_tokens: crate::storage::in_memory::InMemoryPasswordResetTokenStorage::new(1_800),
            max_bcrypt_cost: 12,
            extra_data_handler: None,
        }
    }

    async fn state_with_user(email: &str, password: &str) -> AppState {
        let hash = ARGON2
            .hash_password(password.as_bytes())
            .expect("hashing a test password never fails")
            .to_string();
        state_with_user_password(email, PasswordHash::Argon2(hash.into())).await
    }

    #[tokio::test]
    async fn accepts_correct_credentials_and_returns_a_login_session() {
        let state = state_with_user("alice@example.com", "hunter2").await;
        let req = LoginRequest {
            email: "alice@example.com".to_string(),
            password: "hunter2".to_string(),
        };

        let Json(body) = login(State(state), Json(req)).await.unwrap();

        assert!(!body.login_session.is_empty());
    }

    #[tokio::test]
    async fn rejects_wrong_password() {
        let state = state_with_user("alice@example.com", "hunter2").await;
        let req = LoginRequest {
            email: "alice@example.com".to_string(),
            password: "wrong".to_string(),
        };

        let result = login(State(state), Json(req)).await;

        assert_eq!(result.err(), Some(LoginError::InvalidCredentials));
    }

    #[tokio::test]
    async fn rejects_unknown_email() {
        let state = state_with_user("alice@example.com", "hunter2").await;
        let req = LoginRequest {
            email: "bob@example.com".to_string(),
            password: "hunter2".to_string(),
        };

        let result = login(State(state), Json(req)).await;

        assert_eq!(result.err(), Some(LoginError::InvalidCredentials));
    }

    #[tokio::test]
    async fn unknown_email_pays_the_same_argon2_cost_as_a_known_one() {
        // Regression guard for the email-enumeration timing hole: an unknown
        // email must still run a full Argon2 hash, not return instantly.
        // We don't assert a tight ratio against the known-email path (flaky
        // under load); an absolute floor is enough to catch a short-circuit.
        let state = state_with_user("alice@example.com", "hunter2").await;
        let req = LoginRequest {
            email: "no-such-user@example.com".to_string(),
            password: "whatever".to_string(),
        };

        let started = std::time::Instant::now();
        let result = login(State(state), Json(req)).await;
        let elapsed = started.elapsed();

        assert_eq!(result.err(), Some(LoginError::InvalidCredentials));
        assert!(
            elapsed > std::time::Duration::from_millis(1),
            "unknown-email login returned in {elapsed:?} -- looks like it short-circuited \
             before hashing, which reopens the email-enumeration timing hole"
        );
    }

    #[tokio::test]
    async fn logging_in_with_an_imported_bcrypt_hash_unlocks_the_account_and_upgrades_it_to_argon2() {
        let bcrypt_hash = bcrypt::hash("hunter2", 4).expect("hashing a test password never fails");
        let state = state_with_user_password("alice@example.com", PasswordHash::Bcrypt(bcrypt_hash.into())).await;
        let req = LoginRequest {
            email: "alice@example.com".to_string(),
            password: "hunter2".to_string(),
        };

        let Json(body) = login(State(state.clone()), Json(req)).await.unwrap();
        assert!(!body.login_session.is_empty());

        let user = state.users.get_user_by_email("alice@example.com").await.expect("user exists");
        assert!(
            matches!(user.password, Some(PasswordHash::Argon2(_))),
            "expected the bcrypt hash to have been upgraded to argon2, got {:?}",
            user.password
        );
    }
}
