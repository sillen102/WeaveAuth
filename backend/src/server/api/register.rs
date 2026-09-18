pub(crate) use controller::register;
pub(crate) use controller::register_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::Json;
    use schemars::JsonSchema;
    use serde::Deserialize;
    use std::collections::HashMap;

    use crate::server::AppState;

    use super::service;
    pub(crate) use super::service::RegisterError;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct RegisterRequest {
        pub(super) email: String,
        pub(super) password: String,
        /// Anything beyond `email`/`password` -- forwarded to the deployer's
        /// configured extra-data handler (see `config::ExtraDataHandlerConfig`),
        /// never stored by WeaveAuth itself. Rejected with 400 if no handler
        /// is configured.
        #[serde(flatten)]
        pub(super) extra: HashMap<String, String>,
    }

    pub(crate) async fn register(
        State(mut state): State<AppState>,
        Json(req): Json<RegisterRequest>,
    ) -> Result<StatusCode, RegisterError> {
        service::register(&mut state, req.email, req.password.into(), req.extra).await?;
        Ok(StatusCode::CREATED)
    }

    // OpenAPI documentation for this route.
    pub(crate) fn register_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("register")
            .summary("Register a new user")
            .description(
                "Creates a user with a password hashed via Argon2; 400 if the email is not a \
                 valid address, 409 if it's already taken. Any fields beyond email/password are \
                 forwarded to the deployer's configured extra-data handler -- 400 if none is \
                 configured, 502 if the handler rejects the registration.",
            )
    }
}

mod service {
    use axum::http::StatusCode;
    use chrono::Utc;
    use email_address::EmailAddress;
    use std::collections::HashMap;
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
        #[error("extra registration fields are not supported by this deployment")]
        #[error_response(StatusCode::BAD_REQUEST, details = "extra registration fields are not supported by this deployment")]
        ExtraDataNotSupported,
        #[error("too many extra registration fields, or a field is too large")]
        #[error_response(StatusCode::BAD_REQUEST, details = "too many extra registration fields, or a field is too large")]
        ExtraDataTooLarge,
        #[error("downstream extra-data handler rejected the registration")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "downstream extra-data handler rejected the registration")]
        DownstreamServiceFailed,
        #[error("internal error")]
        #[error_response(StatusCode::INTERNAL_SERVER_ERROR)]
        UnexpectedError,
    }

    /// Bounds on extra registration fields, checked before anything else
    /// touches them (handler dispatch, storage) -- otherwise a single
    /// request could hand an unbounded number/size of fields to a webhook or
    /// WASM plugin, limited only by axum's default body-size cap.
    const MAX_EXTRA_FIELDS: usize = 50;
    const MAX_EXTRA_FIELD_LEN: usize = 4096;

    pub(crate) async fn register(
        state: &mut AppState,
        email: String,
        password: SecretString,
        extra: HashMap<String, String>,
    ) -> Result<(), RegisterError> {
        if extra.len() > MAX_EXTRA_FIELDS
            || extra.iter().any(|(key, value)| key.len() > MAX_EXTRA_FIELD_LEN || value.len() > MAX_EXTRA_FIELD_LEN)
        {
            return Err(RegisterError::ExtraDataTooLarge);
        }

        let email = normalize_email(&email);
        if !EmailAddress::is_valid(&email) {
            return Err(RegisterError::InvalidEmail);
        }

        let password_hash = crypto::hash_password(password).await.map_err(|_| RegisterError::UnexpectedError)?;

        // Generated up front (rather than left to storage) so it can be
        // handed to the extra-data handler before the user is created --
        // that call has to succeed first for registration to be atomic: no
        // user persisted unless the handler accepts the extra fields.
        let user_id = Uuid::new_v4();
        if !extra.is_empty() {
            // Without this, a caller could repeatedly POST an already-taken
            // email with extra fields: the handler would fire (and forward
            // whatever payload) every time, then `create_user` below would
            // reject it as taken -- an unlimited way to inject arbitrary
            // data into the deployer's webhook/plugin for someone else's
            // account. This narrows, but doesn't fully close, the race: two
            // concurrent requests for the same brand-new email can both pass
            // this check and both invoke the handler before either creates
            // the user; `create_user`'s atomic check-and-insert still
            // guarantees only one of them ends up with an account.
            if state.users.get_user_by_email(&email).await.is_some() {
                return Err(RegisterError::EmailTaken);
            }

            let handler = state.extra_data_handler.as_ref().ok_or(RegisterError::ExtraDataNotSupported)?;
            handler
                .handle(user_id, &email, &extra)
                .await
                .map_err(|_| RegisterError::DownstreamServiceFailed)?;
        }

        let now = Utc::now();
        let outcome = state
            .users
            .create_user(User {
                id: user_id,
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
    use crate::extra_data::{ExtraDataError, ExtraDataHandler};
    use crate::storage::in_memory::InMemoryUserStorage;
    use crate::storage::UserStorage;
    use crate::server::AppState;
    use axum::extract::{Json, State};
    use axum::http::StatusCode;
    use std::collections::HashMap;
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
            extra_data_handler: None,
        }
    }

    fn req(email: &str, password: &str) -> RegisterRequest {
        RegisterRequest {
            email: email.to_string(),
            password: password.to_string(),
            extra: HashMap::new(),
        }
    }

    // Symmetric to bff's `form_extractor_flattens_extra_fields_alongside_named_ones`:
    // proves `#[serde(flatten)] extra: HashMap<String, String>` deserializes
    // correctly from a real JSON body (via axum's actual `Json` extractor,
    // not a hand-built struct literal) alongside the named `email`/`password`
    // fields. `serde_json` doesn't share `serde_urlencoded`'s flatten bug,
    // but this pins that down as a verified fact rather than an assumption.
    #[tokio::test]
    async fn json_extractor_flattens_extra_fields_alongside_named_ones() {
        use axum::body::Bytes;
        use axum::extract::FromRequest;
        use axum::http::Request;

        let state = state();
        let request = Request::builder()
            .method("POST")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(Bytes::from(
                r#"{"email":"alice@example.com","password":"hunter2","company":"Acme","plan":"pro"}"#,
            )))
            .expect("valid request");

        let Json(req) = Json::<RegisterRequest>::from_request(request, &state)
            .await
            .expect("json deserializes");

        assert_eq!(req.email, "alice@example.com");
        assert_eq!(req.password, "hunter2");
        assert_eq!(
            req.extra,
            HashMap::from([("company".to_string(), "Acme".to_string()), ("plan".to_string(), "pro".to_string())])
        );
    }

    #[tokio::test]
    async fn registers_user_with_hashed_password() {
        let state = state();

        let result = register(State(state.clone()), Json(req("alice@example.com", "hunter2"))).await;

        assert_eq!(result, Ok(StatusCode::CREATED));
    }

    #[tokio::test]
    async fn rejects_an_invalid_email() {
        let state = state();

        let result = register(State(state), Json(req("not-an-email", "hunter2"))).await;

        assert_eq!(result, Err(RegisterError::InvalidEmail));
    }

    #[tokio::test]
    async fn rejects_a_taken_email() {
        let state = state();
        let first = req("alice@example.com", "hunter2");
        let second = req("alice@example.com", "different-password");

        let first_result = register(State(state.clone()), Json(first)).await;
        let second_result = register(State(state), Json(second)).await;

        assert_eq!(first_result, Ok(StatusCode::CREATED));
        assert_eq!(second_result, Err(RegisterError::EmailTaken));
    }

    #[tokio::test]
    async fn rejects_extra_fields_when_no_handler_is_configured() {
        let state = state();
        let mut req = req("alice@example.com", "hunter2");
        req.extra.insert("company".to_string(), "Acme".to_string());

        let result = register(State(state), Json(req)).await;

        assert_eq!(result, Err(RegisterError::ExtraDataNotSupported));
    }

    struct StubHandler {
        succeed: bool,
    }

    #[async_trait::async_trait]
    impl ExtraDataHandler for StubHandler {
        async fn handle(&self, _user_id: uuid::Uuid, _email: &str, _fields: &HashMap<String, String>) -> Result<(), ExtraDataError> {
            if self.succeed {
                Ok(())
            } else {
                Err(ExtraDataError)
            }
        }
    }

    #[tokio::test]
    async fn accepts_extra_fields_when_the_handler_succeeds() {
        let mut state = state();
        state.extra_data_handler = Some(Arc::new(StubHandler { succeed: true }));
        let mut req = req("alice@example.com", "hunter2");
        req.extra.insert("company".to_string(), "Acme".to_string());

        let result = register(State(state), Json(req)).await;

        assert_eq!(result, Ok(StatusCode::CREATED));
    }

    #[tokio::test]
    async fn does_not_create_the_user_when_the_handler_fails() {
        let mut state = state();
        state.extra_data_handler = Some(Arc::new(StubHandler { succeed: false }));
        let mut req = req("alice@example.com", "hunter2");
        req.extra.insert("company".to_string(), "Acme".to_string());

        let result = register(State(state.clone()), Json(req)).await;

        assert_eq!(result, Err(RegisterError::DownstreamServiceFailed));
        assert!(state.users.get_user_by_email("alice@example.com").await.is_none());
    }

    struct CountingHandler {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ExtraDataHandler for CountingHandler {
        async fn handle(&self, _user_id: uuid::Uuid, _email: &str, _fields: &HashMap<String, String>) -> Result<(), ExtraDataError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn does_not_invoke_the_handler_for_an_already_taken_email() {
        let mut state = state();
        let handler = Arc::new(CountingHandler { calls: std::sync::atomic::AtomicUsize::new(0) });
        state.extra_data_handler = Some(handler.clone());

        let first = register(State(state.clone()), Json(req("alice@example.com", "hunter2"))).await;
        assert_eq!(first, Ok(StatusCode::CREATED));
        assert_eq!(handler.calls.load(std::sync::atomic::Ordering::SeqCst), 0, "no extra fields on the first request");

        let mut second_req = req("alice@example.com", "different-password");
        second_req.extra.insert("company".to_string(), "Acme".to_string());
        let second = register(State(state), Json(second_req)).await;

        assert_eq!(second, Err(RegisterError::EmailTaken));
        assert_eq!(
            handler.calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "handler must not fire for an email that's already taken"
        );
    }

    // Positive control for `does_not_invoke_the_handler_for_an_already_taken_email`:
    // without this, dropping the handler dispatch entirely would still leave
    // that test (and the suite) green.
    #[tokio::test]
    async fn invokes_the_handler_once_for_a_new_email() {
        let mut state = state();
        let handler = Arc::new(CountingHandler { calls: std::sync::atomic::AtomicUsize::new(0) });
        state.extra_data_handler = Some(handler.clone());
        let mut req = req("alice@example.com", "hunter2");
        req.extra.insert("company".to_string(), "Acme".to_string());

        let result = register(State(state.clone()), Json(req)).await;

        assert_eq!(result, Ok(StatusCode::CREATED));
        assert_eq!(handler.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(state.users.get_user_by_email("alice@example.com").await.is_some());
    }

    #[tokio::test]
    async fn allows_exactly_the_max_number_of_extra_fields() {
        let mut state = state();
        state.extra_data_handler = Some(Arc::new(StubHandler { succeed: true }));
        let mut req = req("alice@example.com", "hunter2");
        for i in 0..50 {
            req.extra.insert(format!("field{i}"), "value".to_string());
        }

        let result = register(State(state), Json(req)).await;

        assert_eq!(result, Ok(StatusCode::CREATED));
    }

    #[tokio::test]
    async fn allows_extra_field_key_and_value_at_the_max_length() {
        let mut state = state();
        state.extra_data_handler = Some(Arc::new(StubHandler { succeed: true }));
        let mut req = req("alice@example.com", "hunter2");
        req.extra.insert("k".repeat(4096), "v".repeat(4096));

        let result = register(State(state), Json(req)).await;

        assert_eq!(result, Ok(StatusCode::CREATED));
    }

    #[tokio::test]
    async fn rejects_too_many_extra_fields() {
        let mut state = state();
        state.extra_data_handler = Some(Arc::new(StubHandler { succeed: true }));
        let mut req = req("alice@example.com", "hunter2");
        for i in 0..51 {
            req.extra.insert(format!("field{i}"), "value".to_string());
        }

        let result = register(State(state), Json(req)).await;

        assert_eq!(result, Err(RegisterError::ExtraDataTooLarge));
    }

    #[tokio::test]
    async fn rejects_an_oversized_extra_field_value() {
        let mut state = state();
        state.extra_data_handler = Some(Arc::new(StubHandler { succeed: true }));
        let mut req = req("alice@example.com", "hunter2");
        req.extra.insert("company".to_string(), "x".repeat(4097));

        let result = register(State(state), Json(req)).await;

        assert_eq!(result, Err(RegisterError::ExtraDataTooLarge));
    }
}
