pub(crate) use controller::login;
pub(crate) use controller::login_doc;

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

    use crate::server::AppState;
    use crate::storage::VerificationSessionStorage;

    use super::service::{self, LoginOutcome};

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct LoginRequest {
        pub(super) email: String,
        pub(super) password: String,
    }

    /// `login_session` is the single-use proof of this authentication,
    /// required by `/oauth/authorize`. `verification_session` is only good for
    /// `/oauth/email-verification/*`, which trade it (plus the emailed code)
    /// for a `login_session`; `verification_session_ttl_secs` is how long it
    /// lasts, so a caller's cookie can live exactly as long.
    #[derive(Serialize, JsonSchema)]
    #[serde(untagged)]
    pub(crate) enum LoginResponse {
        /// The account's email is verified.
        Verified { login_session: String },
        /// Unverified account, but the deployment doesn't require verification.
        Unverified {
            login_session: String,
            verification_session: String,
            verification_session_ttl_secs: i64,
        },
        /// Unverified account and the deployment requires verification: no
        /// `login_session` until the emailed code is entered.
        VerificationRequired {
            verification_session: String,
            verification_session_ttl_secs: i64,
        },
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
            if let service::LoginServiceError::UnexpectedError(_) = &err {
                tracing::error!(%err, "login failed");
            }
            match err {
                service::LoginServiceError::InvalidCredentials => LoginError::InvalidCredentials,
                service::LoginServiceError::UnexpectedError(_) => LoginError::UnexpectedError,
            }
        }
    }

    pub(crate) fn login_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("login")
            .summary("Authenticate a user")
            .description(indoc! {"
                Checks email/password against stored users and, on success, returns a
                short-lived login_session token that /oauth/authorize requires before it will
                issue a code -- this is what makes authentication happen before authorization
                regardless of what order a caller invokes the two endpoints in. An account whose
                email isn't verified also gets a verification_session (good only for
                /oauth/email-verification/*); when the deployment requires verified emails that
                is all it gets, and the verification email is sent. The body is one of
                {login_session}, {login_session, verification_session,
                verification_session_ttl_secs} or {verification_session,
                verification_session_ttl_secs}."})
    }

    pub(crate) async fn login(
        State(mut state): State<AppState>,
        ApiJson(req): ApiJson<LoginRequest>,
    ) -> Result<Json<LoginResponse>, LoginError> {
        let outcome = service::login(&mut state, &req.email, req.password.into()).await?;
        let verification_session_ttl_secs = state.email_verification.sessions.ttl_secs();
        Ok(Json(match outcome {
            LoginOutcome::Verified { login_session } => LoginResponse::Verified { login_session },
            LoginOutcome::Unverified {
                login_session,
                verification_session,
            } => LoginResponse::Unverified {
                login_session,
                verification_session,
                verification_session_ttl_secs,
            },
            LoginOutcome::VerificationRequired {
                verification_session,
            } => LoginResponse::VerificationRequired {
                verification_session,
                verification_session_ttl_secs,
            },
        }))
    }
}

mod service {
    use secrecy::SecretString;
    use thiserror::Error;

    use crate::server::AppState;
    use crate::server::api::email_verification::send_verification_email;
    use crate::server::api::{AuthenticateError, authenticate_password};
    use crate::storage::{
        EmailVerificationCodeStorage, LoginSessionStorage, VerificationSessionStorage,
    };

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum LoginServiceError {
        #[error("invalid credentials")]
        InvalidCredentials,
        #[error("internal error: {0}")]
        UnexpectedError(String),
    }

    impl From<AuthenticateError> for LoginServiceError {
        fn from(err: AuthenticateError) -> Self {
            match err {
                AuthenticateError::InvalidCredentials => Self::InvalidCredentials,
                AuthenticateError::Unexpected(cause) => Self::UnexpectedError(cause),
            }
        }
    }

    pub(crate) enum LoginOutcome {
        Verified {
            login_session: String,
        },
        Unverified {
            login_session: String,
            verification_session: String,
        },
        VerificationRequired {
            verification_session: String,
        },
    }

    /// Checks the password. A verified account gets a `login_session`. An
    /// unverified one also gets a `verification_session`, and when the
    /// deployment requires verification *only* that (plus the code email), so
    /// it can't reach anything until the code is entered.
    pub(crate) async fn login(
        state: &mut AppState,
        email: &str,
        password: SecretString,
    ) -> Result<LoginOutcome, LoginServiceError> {
        let user = authenticate_password(state, email, password).await?;
        if user.email_verified {
            let login_session = state.login_sessions.create_session(user.id).await;
            return Ok(LoginOutcome::Verified { login_session });
        }

        let verification_session = state
            .email_verification
            .sessions
            .create_session(user.id)
            .await;
        if state.email_verification.required {
            if !state.email_verification.codes.has_live_code(user.id).await {
                drop(send_verification_email(state, user.id, &user.email).await);
            }
            return Ok(LoginOutcome::VerificationRequired {
                verification_session,
            });
        }
        let login_session = state.login_sessions.create_session(user.id).await;
        Ok(LoginOutcome::Unverified {
            login_session,
            verification_session,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use crate::model::user::{PasswordHash, User};
    use crate::server::AppState;
    use crate::server::api::email_verification::test_support::{
        Sent, assert_nothing_sent, install_recorder, next_sent,
    };
    use crate::storage::in_memory::{
        InMemoryLoginSessionStorage, InMemoryPkceStorage, InMemoryUserStorage,
    };
    use crate::storage::{EmailVerificationCodeStorage, UserStorage, VerificationSessionStorage};
    use argon2::PasswordHasher;
    use axum::extract::{Json, State};
    use common::extract::ApiJson;
    use std::sync::Arc;

    use crate::crypto::ARGON2;

    async fn state_with_user_password(email: &str, password_hash: PasswordHash) -> AppState {
        state_with_user_password_opt(email, Some(password_hash)).await
    }

    async fn state_with_user_password_opt(
        email: &str,
        password_hash: Option<PasswordHash>,
    ) -> AppState {
        let mut users = InMemoryUserStorage::new();
        let _ = users
            .create_user(User {
                email: email.to_string(),
                password: password_hash,
                ..User::default()
            })
            .await;

        AppState {
            pkce: InMemoryPkceStorage::new(300),
            users,
            login_sessions: InMemoryLoginSessionStorage::new(60),
            redirect_uri_allowlist: Arc::new(vec![]),
            jwt_keys: crate::storage::in_memory::InMemoryJwkStorage::new()
                .expect("RSA keygen for tests never fails"),
            access_token_ttl_secs: 900,
            refresh_tokens: crate::storage::in_memory::InMemoryRefreshTokenStorage::new(2_592_000),
            refresh_token_ttl_secs: 2_592_000,
            jwt_key_rotation_interval_secs: 2_592_000,
            issuer: "http://localhost:1983".into(),
            oidc_providers: std::sync::Arc::new(std::collections::HashMap::new()),
            oidc_extra_claims: Arc::new(Default::default()),
            oidc_scopes: Arc::new(Default::default()),
            oidc_display_names: Arc::new(Default::default()),
            oidc_profile_apis: Arc::new(Default::default()),
            oidc_state: crate::storage::in_memory::InMemoryOidcStateStorage::new(300),
            pending_oidc_links: crate::storage::in_memory::InMemoryPendingOidcLinkStorage::new(300),
            oidc_http_client: std::sync::Arc::new(openidconnect::reqwest::Client::new()),
            email_verification: crate::server::api::email_verification::EmailVerification::disabled(
            ),
            password_reset_tokens:
                crate::storage::in_memory::InMemoryPasswordResetTokenStorage::new(1_800),
            max_bcrypt_cost: 12,
            extra_data_handler: None,
            login_claims_handler: None,
        }
    }

    async fn state_with_user(email: &str, password: &str) -> AppState {
        let hash = ARGON2
            .hash_password(password.as_bytes())
            .expect("hashing a test password never fails")
            .to_string();
        state_with_user_password(email, PasswordHash::Argon2(hash.into())).await
    }

    async fn login_as(state: &AppState, password: &str) -> Result<LoginResponse, LoginError> {
        let req = LoginRequest {
            email: "alice@example.com".to_string(),
            password: password.to_string(),
        };
        login(State(state.clone()), ApiJson(req))
            .await
            .map(|Json(body)| body)
    }

    async fn verify_alice(state: &mut AppState) {
        let user = state
            .users
            .get_user_by_email("alice@example.com")
            .await
            .unwrap();
        assert_eq!(
            state.users.mark_email_verified(user.id).await,
            crate::storage::MarkVerifiedOutcome::Ok
        );
    }

    #[tokio::test]
    async fn a_verified_account_gets_a_login_session_only() {
        let mut state = state_with_user("alice@example.com", "hunter2").await;
        verify_alice(&mut state).await;

        let body = login_as(&state, "hunter2").await.unwrap();

        assert!(
            matches!(body, LoginResponse::Verified { login_session } if !login_session.is_empty())
        );
    }

    #[tokio::test]
    async fn an_unverified_account_gets_both_sessions_when_verification_is_optional() {
        let mut state = state_with_user("alice@example.com", "hunter2").await;
        state.email_verification.sessions =
            crate::storage::in_memory::InMemoryVerificationSessionStorage::new(4321);

        let body = login_as(&state, "hunter2").await.unwrap();

        assert!(matches!(
            body,
            LoginResponse::Unverified {
                verification_session_ttl_secs: 4321,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn requiring_verification_withholds_the_login_session_from_an_unverified_account() {
        let mut state = state_with_user("alice@example.com", "hunter2").await;
        state.email_verification.required = true;
        // Distinct from the code TTL, so swapping the two would be noticed.
        state.email_verification.sessions =
            crate::storage::in_memory::InMemoryVerificationSessionStorage::new(4321);

        let body = login_as(&state, "hunter2").await.unwrap();

        let (token, ttl) = match body {
            LoginResponse::VerificationRequired {
                verification_session,
                verification_session_ttl_secs,
            } => Some((verification_session, verification_session_ttl_secs)),
            _ => None,
        }
        .expect("a VerificationRequired response");
        assert_eq!(ttl, 4321);
        let user = state
            .users
            .get_user_by_email("alice@example.com")
            .await
            .unwrap();
        assert_eq!(
            state.email_verification.sessions.get_session(&token).await,
            Some(user.id)
        );
    }

    async fn required_state_with_recorder() -> (AppState, tokio::sync::mpsc::UnboundedReceiver<Sent>)
    {
        let mut state = state_with_user("alice@example.com", "hunter2").await;
        state.email_verification.required = true;
        let rx = install_recorder(&mut state, false);
        (state, rx)
    }

    #[tokio::test]
    async fn login_sends_a_code_when_the_account_has_no_live_one() {
        let (state, mut rx) = required_state_with_recorder().await;

        login_as(&state, "hunter2").await.unwrap();

        assert_eq!(next_sent(&mut rx).await.email, "alice@example.com");
    }

    #[tokio::test]
    async fn login_sends_nothing_while_the_account_has_a_live_code() {
        let (mut state, mut rx) = required_state_with_recorder().await;
        let user = state
            .users
            .get_user_by_email("alice@example.com")
            .await
            .unwrap();
        let _ = state.email_verification.codes.issue_code(user.id).await;

        login_as(&state, "hunter2").await.unwrap();

        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn requiring_verification_does_not_reveal_unverified_accounts_to_a_wrong_password() {
        let mut state = state_with_user("alice@example.com", "hunter2").await;
        state.email_verification.required = true;

        assert_eq!(
            login_as(&state, "wrong").await.err(),
            Some(LoginError::InvalidCredentials)
        );
    }

    #[tokio::test]
    async fn requiring_verification_lets_a_verified_account_in() {
        let mut state = state_with_user("alice@example.com", "hunter2").await;
        state.email_verification.required = true;
        verify_alice(&mut state).await;

        let body = login_as(&state, "hunter2").await.unwrap();

        assert!(matches!(body, LoginResponse::Verified { .. }));
    }

    #[test]
    fn responses_serialize_only_their_own_fields() {
        let keys = |r: LoginResponse| {
            let mut k: Vec<String> = serde_json::to_value(r)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            k.sort();
            k
        };

        assert_eq!(
            keys(LoginResponse::Verified {
                login_session: "l".into()
            }),
            ["login_session"]
        );
        assert_eq!(
            keys(LoginResponse::Unverified {
                login_session: "l".into(),
                verification_session: "v".into(),
                verification_session_ttl_secs: 1,
            }),
            [
                "login_session",
                "verification_session",
                "verification_session_ttl_secs"
            ]
        );
        assert_eq!(
            keys(LoginResponse::VerificationRequired {
                verification_session: "v".into(),
                verification_session_ttl_secs: 1,
            }),
            ["verification_session", "verification_session_ttl_secs"]
        );
    }

    #[tokio::test]
    async fn rejects_wrong_password() {
        let state = state_with_user("alice@example.com", "hunter2").await;
        let req = LoginRequest {
            email: "alice@example.com".to_string(),
            password: "wrong".to_string(),
        };

        let result = login(State(state), ApiJson(req)).await;

        assert_eq!(result.err(), Some(LoginError::InvalidCredentials));
    }

    #[tokio::test]
    async fn rejects_unknown_email() {
        let state = state_with_user("alice@example.com", "hunter2").await;
        let req = LoginRequest {
            email: "bob@example.com".to_string(),
            password: "hunter2".to_string(),
        };

        let result = login(State(state), ApiJson(req)).await;

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
        let result = login(State(state), ApiJson(req)).await;
        let elapsed = started.elapsed();

        assert_eq!(result.err(), Some(LoginError::InvalidCredentials));
        assert!(
            elapsed > std::time::Duration::from_millis(1),
            "unknown-email login returned in {elapsed:?} -- looks like it short-circuited \
             before hashing, which reopens the email-enumeration timing hole"
        );
    }

    #[tokio::test]
    async fn rejects_empty_password_for_an_oidc_only_user() {
        let state = state_with_user_password_opt("oidc-alice@example.com", None).await;
        let req = LoginRequest {
            email: "oidc-alice@example.com".to_string(),
            password: String::new(),
        };

        let result = login(State(state), ApiJson(req)).await;

        assert_eq!(result.err(), Some(LoginError::InvalidCredentials));
    }

    #[tokio::test]
    async fn logging_in_with_an_imported_bcrypt_hash_unlocks_the_account_and_upgrades_it_to_argon2()
    {
        let bcrypt_hash = bcrypt::hash("hunter2", 4).expect("hashing a test password never fails");
        let state = state_with_user_password(
            "alice@example.com",
            PasswordHash::Bcrypt(bcrypt_hash.into()),
        )
        .await;
        let req = LoginRequest {
            email: "alice@example.com".to_string(),
            password: "hunter2".to_string(),
        };

        let Json(body) = login(State(state.clone()), ApiJson(req)).await.unwrap();
        assert!(matches!(body, LoginResponse::Unverified { .. }));

        let user = state
            .users
            .get_user_by_email("alice@example.com")
            .await
            .expect("user exists");
        assert!(
            matches!(user.password, Some(PasswordHash::Argon2(_))),
            "expected the bcrypt hash to have been upgraded to argon2, got {:?}",
            user.password
        );
    }
}
