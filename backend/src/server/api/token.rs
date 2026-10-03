pub(crate) use controller::issue_token;
pub(crate) use controller::issue_token_doc;
pub(crate) use login_claims::{LoginClaimsHandler, PluginHandler, WebhookHandler};

mod controller {
    use aide::transform::TransformOperation;
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiForm;
    use common::model::token::GrantType;
    use common_macros::ErrorResponses;
    use indoc::indoc;
    use schemars::JsonSchema;
    use serde::Deserialize;
    use thiserror::Error;

    use crate::server::AppState;

    pub(crate) use super::service::TokenResponse;
    use super::service::{self, AuthorizationCodeGrant, TokenServiceError};

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct TokenRequest {
        pub(super) grant_type: GrantType,
        pub(super) code: Option<String>,
        pub(super) code_verifier: Option<String>,
        pub(super) redirect_uri: Option<String>,
        pub(super) refresh_token: Option<String>,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum TokenError {
        #[error("invalid or expired code")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid or expired code")]
        InvalidCode,
        #[error("redirect uri does not match the one the code was issued for")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "redirect uri does not match the one the code was issued for"
        )]
        RedirectUriMismatch,
        #[error("code verifier does not match the code challenge")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "code verifier does not match the code challenge"
        )]
        InvalidCodeVerifier,
        #[error("required parameters for this grant_type are missing")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "required parameters for this grant_type are missing"
        )]
        MissingParameters,
        #[error("invalid or expired refresh token")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid or expired refresh token")]
        InvalidRefreshToken,
        #[error("downstream login-claims handler failed")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "downstream login-claims handler failed"
        )]
        DownstreamServiceFailed,
        #[error("downstream login-claims handler returned a reserved claim name")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "downstream login-claims handler returned a reserved claim name"
        )]
        ReservedClaimOverridden,
        #[error("internal error")]
        #[error_response(StatusCode::INTERNAL_SERVER_ERROR)]
        UnexpectedError,
    }

    impl From<TokenServiceError> for TokenError {
        fn from(err: TokenServiceError) -> Self {
            match &err {
                TokenServiceError::DownstreamServiceFailed(_)
                | TokenServiceError::ReservedClaimOverridden(_) => {
                    tracing::warn!(%err, "token request failed")
                }
                TokenServiceError::UnexpectedError(_) => {
                    tracing::error!(%err, "token request failed")
                }
                _ => {}
            }
            match err {
                TokenServiceError::InvalidCode => TokenError::InvalidCode,
                TokenServiceError::RedirectUriMismatch => TokenError::RedirectUriMismatch,
                TokenServiceError::InvalidCodeVerifier => TokenError::InvalidCodeVerifier,
                TokenServiceError::MissingParameters => TokenError::MissingParameters,
                TokenServiceError::InvalidRefreshToken => TokenError::InvalidRefreshToken,
                TokenServiceError::DownstreamServiceFailed(_) => {
                    TokenError::DownstreamServiceFailed
                }
                TokenServiceError::ReservedClaimOverridden(_) => {
                    TokenError::ReservedClaimOverridden
                }
                TokenServiceError::UnexpectedError(_) => TokenError::UnexpectedError,
            }
        }
    }

    // OpenAPI documentation for this route.
    pub(crate) fn issue_token_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("token")
            .summary("Exchange an authorization code for tokens")
            .description(indoc! {"
                Verifies code_verifier against the code_challenge stored at /oauth/authorize,
                and that redirect_uri matches the one the code was issued for."})
    }

    pub(crate) async fn issue_token(
        State(mut state): State<AppState>,
        ApiForm(req): ApiForm<TokenRequest>,
    ) -> Result<Json<TokenResponse>, TokenError> {
        let response = match req.grant_type {
            GrantType::AuthorizationCode => {
                let grant = match (req.code, req.code_verifier, req.redirect_uri) {
                    (Some(code), Some(code_verifier), Some(redirect_uri)) => {
                        Some(AuthorizationCodeGrant {
                            code,
                            code_verifier,
                            redirect_uri,
                        })
                    }
                    _ => None,
                };
                service::issue_token_for_authorization_code(&mut state, grant).await?
            }
            GrantType::RefreshToken => {
                service::issue_token_for_refresh_token(&mut state, req.refresh_token).await?
            }
        };
        Ok(Json(response))
    }
}

mod service {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::{DateTime, Duration, Utc};
    use common::model::token::TokenType;
    use jsonwebtoken::{Algorithm, Header};
    use rand::RngExt;
    use schemars::JsonSchema;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use thiserror::Error;
    use uuid::Uuid;

    use crate::server::AppState;
    use crate::storage::{
        JwkStorage, PkceStorage, RefreshTokenOutcome, RefreshTokenStorage, UserStorage,
    };

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum TokenServiceError {
        #[error("invalid or expired code")]
        InvalidCode,
        #[error("redirect uri does not match the one the code was issued for")]
        RedirectUriMismatch,
        #[error("code verifier does not match the code challenge")]
        InvalidCodeVerifier,
        #[error("required parameters for this grant_type are missing")]
        MissingParameters,
        #[error("invalid or expired refresh token")]
        InvalidRefreshToken,
        #[error("downstream login-claims handler failed: {0}")]
        DownstreamServiceFailed(String),
        #[error("downstream login-claims handler returned reserved claim name '{0}'")]
        ReservedClaimOverridden(String),
        #[error("internal error: {0}")]
        UnexpectedError(String),
    }

    /// Claim names this crate assigns itself -- a login-claims handler
    /// (`super::login_claims`) that returns one of these would let a
    /// downstream plugin/webhook spoof identity claims, so a collision fails
    /// the token request instead of silently overwriting one.
    /// `aud`/`nbf`/`jti` are never set here but still reserved: verifiers give
    /// registered claims meaning, and an injected `aud` could get a token
    /// accepted by a resource server it wasn't meant for.
    const RESERVED_CLAIM_NAMES: &[&str] = &[
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti",
        "email",
        "email_verified",
    ];

    /// Access token claims (RFC 7519), plus whatever the configured
    /// login-claims handler (see `super::login_claims`) added.
    #[derive(Serialize)]
    struct Claims {
        iss: String,
        sub: Uuid,
        /// The user's email at the time this token was issued -- callers that
        /// only see the token (not a fresh `/oauth/token` response) can still
        /// show/log something human-readable without a lookup back through
        /// backend. Not kept in sync if the email changes later;
        /// re-authenticate to get a token with the new one.
        email: String,
        email_verified: bool,
        iat: i64,
        exp: i64,
        #[serde(flatten)]
        extra: std::collections::HashMap<String, serde_json::Value>,
    }

    pub(crate) struct AuthorizationCodeGrant {
        pub(crate) code: String,
        pub(crate) code_verifier: String,
        pub(crate) redirect_uri: String,
    }

    #[derive(Serialize, JsonSchema)]
    pub(crate) struct TokenResponse {
        pub(crate) access_token: String,
        pub(crate) refresh_token: String,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
        pub(crate) refresh_expires_at: DateTime<Utc>,
        /// The user this token was issued to -- carried through from the
        /// `login_session` `/oauth/login` created, via the auth code.
        pub(crate) user_id: Uuid,
    }

    pub(crate) async fn issue_token_for_authorization_code(
        state: &mut AppState,
        grant: Option<AuthorizationCodeGrant>,
    ) -> Result<TokenResponse, TokenServiceError> {
        let AuthorizationCodeGrant {
            code,
            code_verifier,
            redirect_uri,
        } = grant.ok_or(TokenServiceError::MissingParameters)?;

        let (challenge, _method, issued_redirect_uri, user_id) = state
            .pkce
            .take_code_challenge(&code)
            .await
            .ok_or(TokenServiceError::InvalidCode)?;

        // Binds the code to the redirect_uri it was issued for (RFC 6749
        // 4.1.3) -- without this, a code obtained for one redirect_uri
        // could be redeemed while claiming a different one.
        if redirect_uri != issued_redirect_uri {
            return Err(TokenServiceError::RedirectUriMismatch);
        }

        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        if computed != challenge {
            return Err(TokenServiceError::InvalidCodeVerifier);
        }

        issue_tokens(state, user_id, Uuid::new_v4()).await
    }

    pub(crate) async fn issue_token_for_refresh_token(
        state: &mut AppState,
        refresh_token: Option<String>,
    ) -> Result<TokenResponse, TokenServiceError> {
        let refresh_token = refresh_token.ok_or(TokenServiceError::MissingParameters)?;

        match state
            .refresh_tokens
            .take_refresh_token(&refresh_token)
            .await
        {
            RefreshTokenOutcome::Valid { user_id, family_id } => {
                issue_tokens(state, user_id, family_id).await
            }
            // Already-used token: the storage layer has revoked the
            // whole family as a side effect. Wrong/unknown token: same
            // client-facing error either way, so the response doesn't
            // leak which case it was.
            RefreshTokenOutcome::Reused | RefreshTokenOutcome::NotFound => {
                Err(TokenServiceError::InvalidRefreshToken)
            }
        }
    }

    /// Mints an access token (JWT) and a fresh opaque refresh token in
    /// `family_id`, storing the latter so a later `grant_type=refresh_token`
    /// call can redeem it.
    async fn issue_tokens(
        state: &mut AppState,
        user_id: Uuid,
        family_id: Uuid,
    ) -> Result<TokenResponse, TokenServiceError> {
        let user = state.users.get_user_by_id(user_id).await.ok_or_else(|| {
            TokenServiceError::UnexpectedError(format!("user {user_id} not found"))
        })?;

        let extra = match &state.login_claims_handler {
            Some(handler) => {
                let claims = handler
                    .fetch(user_id, &user.email)
                    .await
                    .map_err(|error| TokenServiceError::DownstreamServiceFailed(error.0))?;
                if let Some(reserved) = claims
                    .keys()
                    .find(|key| RESERVED_CLAIM_NAMES.contains(&key.as_str()))
                {
                    return Err(TokenServiceError::ReservedClaimOverridden(reserved.clone()));
                }
                claims.into_iter().collect()
            }
            None => std::collections::HashMap::new(),
        };

        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(state.access_token_ttl_secs);
        let refresh_expires_at = issued_at + Duration::seconds(state.refresh_token_ttl_secs);
        let claims = Claims {
            iss: state.issuer.to_string(),
            sub: user_id,
            email: user.email,
            email_verified: user.email_verified,
            iat: issued_at.timestamp(),
            exp: expires_at.timestamp(),
            extra,
        };
        let signing_key = state.jwt_keys.active_key().await;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(signing_key.kid.clone());
        let access_token = jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key)
            .map_err(|error| {
                TokenServiceError::UnexpectedError(format!(
                    "signing the access token failed: {error}"
                ))
            })?;

        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);
        let refresh_token = URL_SAFE_NO_PAD.encode(token_bytes);
        state
            .refresh_tokens
            .save_refresh_token(refresh_token.clone(), user_id, family_id)
            .await;

        Ok(TokenResponse {
            access_token,
            refresh_token,
            token_type: TokenType::Bearer,
            expires_at,
            refresh_expires_at,
            user_id,
        })
    }
}

/// Where extra JWT claims are fetched from on every token mint, over the
/// generic plugin contract (`crate::plugin`) or a plain webhook. An error
/// from either kind fails the whole token request -- no token is ever issued
/// without the claims it's configured to carry.
mod login_claims {
    use std::time::Duration;

    use serde::Serialize;
    use uuid::Uuid;
    use weaveauth_plugin_sdk::PluginRequest;

    use crate::plugin::{self, PluginProcess};

    /// This hook's name on the generic plugin contract (`PluginRequest::hook`).
    const HOOK: &str = "login_claims";

    /// Why the handler couldn't produce claims. Handlers only return it; it
    /// is logged once, by the controller that turns it into a response.
    /// Fetching claims fails closed: an error here fails the token request,
    /// and no token is issued.
    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    pub(crate) struct LoginClaimsError(pub(crate) String);

    /// Implemented by whatever a deployer configures to supply extra JWT
    /// claims at token issuance (see `config::HandlerConfig`).
    /// Called on every token mint (both `authorization_code` and
    /// `refresh_token` grants). An error fails the whole request -- no token
    /// is issued.
    #[async_trait::async_trait]
    pub(crate) trait LoginClaimsHandler: Send + Sync {
        async fn fetch(
            &self,
            user_id: Uuid,
            email: &str,
        ) -> Result<serde_json::Map<String, serde_json::Value>, LoginClaimsError>;
    }

    /// Asks a deployer-supplied plugin process for extra JWT claims via the
    /// generic `Invoke` rpc's `"login_claims"` hook. The deployer can write it
    /// in any language with a gRPC server; WeaveAuth only needs the contract
    /// in `plugin-sdk/proto` on the way in and a `google.protobuf.Struct` on
    /// the way out.
    pub(crate) struct PluginHandler {
        plugin: PluginProcess,
    }

    impl PluginHandler {
        pub(crate) fn new(plugin: PluginProcess) -> Self {
            Self { plugin }
        }
    }

    #[async_trait::async_trait]
    impl LoginClaimsHandler for PluginHandler {
        async fn fetch(
            &self,
            user_id: Uuid,
            email: &str,
        ) -> Result<serde_json::Map<String, serde_json::Value>, LoginClaimsError> {
            let request = PluginRequest {
                hook: HOOK.to_string(),
                user_id: user_id.to_string(),
                email: email.to_string(),
                data: None,
            };

            let response = self.plugin.invoke(request).await.map_err(|status| {
                LoginClaimsError(format!(
                    "plugin rejected the login-claims request: {:?}: {}",
                    status.code(),
                    status.message()
                ))
            })?;

            Ok(response
                .data
                .map(plugin::struct_to_json)
                .unwrap_or_default())
        }
    }

    /// The JSON body posted to the webhook.
    #[derive(Serialize)]
    struct LoginClaimsPayload<'a> {
        user_id: Uuid,
        email: &'a str,
    }

    /// Asks a deployer-configured HTTP endpoint for extra JWT claims. The
    /// response body is expected to be a JSON object of claims to merge in;
    /// any transport error, non-2xx response, or non-object body fails the
    /// request.
    pub(crate) struct WebhookHandler {
        client: reqwest::Client,
        url: String,
    }

    impl WebhookHandler {
        pub(crate) fn new(url: String, timeout: Duration) -> anyhow::Result<Self> {
            crate::config::require_https_or_loopback("login-claims webhook url", &url)?;

            // No redirects: this is a server-to-server call to a
            // deployer-configured (should be internal-only) target, so
            // following a redirect elsewhere would be a request-forgery vector
            // -- same reasoning as `oidc_http_client` in `server::AppState::new`.
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(timeout)
                .build()?;
            Ok(Self { client, url })
        }
    }

    #[async_trait::async_trait]
    impl LoginClaimsHandler for WebhookHandler {
        async fn fetch(
            &self,
            user_id: Uuid,
            email: &str,
        ) -> Result<serde_json::Map<String, serde_json::Value>, LoginClaimsError> {
            let payload = LoginClaimsPayload { user_id, email };
            let response = self
                .client
                .post(&self.url)
                .json(&payload)
                .send()
                .await
                .map_err(|error| {
                    LoginClaimsError(format!(
                        "login-claims webhook request failed: {}",
                        common::error::cause_chain(&error.without_url())
                    ))
                })?;

            if !response.status().is_success() {
                return Err(LoginClaimsError(format!(
                    "login-claims webhook returned {}",
                    response.status()
                )));
            }

            match response.json::<serde_json::Value>().await {
                Ok(serde_json::Value::Object(claims)) => Ok(claims),
                Ok(_) => Err(LoginClaimsError(
                    "login-claims webhook did not return a JSON object".to_string(),
                )),
                Err(error) => Err(LoginClaimsError(format!(
                    "login-claims webhook response was not valid JSON: {}",
                    common::error::cause_chain(&error.without_url())
                ))),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const TIMEOUT: Duration = Duration::from_secs(5);

        #[tokio::test]
        async fn returns_the_claims_object_on_a_2xx_response() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/hook"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"roles": ["admin"]})),
                )
                .mount(&server)
                .await;
            let handler = WebhookHandler::new(format!("{}/hook", server.uri()), TIMEOUT)
                .expect("valid client");

            let claims = handler
                .fetch(Uuid::new_v4(), "alice@example.com")
                .await
                .expect("claims returned");

            assert_eq!(claims.get("roles"), Some(&serde_json::json!(["admin"])));
        }

        #[tokio::test]
        async fn fails_on_a_5xx_response() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/hook"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;
            let handler = WebhookHandler::new(format!("{}/hook", server.uri()), TIMEOUT)
                .expect("valid client");

            let result = handler.fetch(Uuid::new_v4(), "alice@example.com").await;

            assert!(result.is_err());
        }

        #[tokio::test]
        async fn fails_when_the_body_is_not_a_json_object() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/hook"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!(["not", "an", "object"])),
                )
                .mount(&server)
                .await;
            let handler = WebhookHandler::new(format!("{}/hook", server.uri()), TIMEOUT)
                .expect("valid client");

            let result = handler.fetch(Uuid::new_v4(), "alice@example.com").await;

            assert!(result.is_err());
        }

        #[tokio::test]
        async fn fails_when_the_endpoint_is_unreachable() {
            let handler = WebhookHandler::new("http://127.0.0.1:1".to_string(), TIMEOUT)
                .expect("valid client");

            let result = handler.fetch(Uuid::new_v4(), "alice@example.com").await;

            assert!(result.is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::Json;
    use axum::extract::State;
    use common::extract::ApiForm;
    use common::model::token::GrantType;

    use super::login_claims::{LoginClaimsError, LoginClaimsHandler};
    use crate::model::pkce::CodeChallengeMethod;
    use crate::model::user::User;
    use crate::server::AppState;
    use crate::storage::in_memory::InMemoryPkceStorage;
    use crate::storage::{PkceStorage, UserStorage};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use uuid::Uuid;

    /// A login-claims handler that always returns the same fixed claims,
    /// for tests that need the merge path without a real plugin/webhook.
    struct FixedClaimsHandler(serde_json::Map<String, serde_json::Value>);

    #[async_trait::async_trait]
    impl LoginClaimsHandler for FixedClaimsHandler {
        async fn fetch(
            &self,
            _user_id: Uuid,
            _email: &str,
        ) -> Result<serde_json::Map<String, serde_json::Value>, LoginClaimsError> {
            Ok(self.0.clone())
        }
    }

    /// A login-claims handler that always fails, for tests pinning down the
    /// fail-closed behavior.
    struct FailingClaimsHandler;

    #[async_trait::async_trait]
    impl LoginClaimsHandler for FailingClaimsHandler {
        async fn fetch(
            &self,
            _user_id: Uuid,
            _email: &str,
        ) -> Result<serde_json::Map<String, serde_json::Value>, LoginClaimsError> {
            Err(LoginClaimsError("stub failed".to_string()))
        }
    }

    fn state() -> AppState {
        AppState {
            pkce: InMemoryPkceStorage::new(300),
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

    /// `issue_tokens` looks the user back up to embed `email` in the access
    /// token, so tests exercising it need a real stored user rather than a
    /// bare random id.
    async fn state_with_user() -> (AppState, Uuid) {
        let mut state = state();
        let user = User {
            email: "alice@example.com".to_string(),
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        (state, user_id)
    }

    fn challenge_for(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    fn code_req(code: &str, code_verifier: &str, redirect_uri: &str) -> TokenRequest {
        TokenRequest {
            grant_type: GrantType::AuthorizationCode,
            code: Some(code.to_string()),
            code_verifier: Some(code_verifier.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            refresh_token: None,
        }
    }

    fn refresh_req(refresh_token: &str) -> TokenRequest {
        TokenRequest {
            grant_type: GrantType::RefreshToken,
            code: None,
            code_verifier: None,
            redirect_uri: None,
            refresh_token: Some(refresh_token.to_string()),
        }
    }

    #[tokio::test]
    async fn exchanges_valid_code_for_tokens() {
        let (mut state, user_id) = state_with_user().await;
        let verifier = "correct-verifier";
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for(verifier),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let req = code_req("code1", verifier, "http://redirect.test");

        let result = issue_token(State(state), ApiForm(req)).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn token_response_carries_the_user_id_the_code_was_issued_to() {
        let (mut state, user_id) = state_with_user().await;
        let verifier = "correct-verifier";
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for(verifier),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let req = code_req("code1", verifier, "http://redirect.test");

        let Json(body) = issue_token(State(state), ApiForm(req)).await.unwrap();

        assert_eq!(body.user_id, user_id);
    }

    #[tokio::test]
    async fn rejects_unknown_code() {
        let req = code_req("never-issued", "whatever", "http://redirect.test");

        let result = issue_token(State(state()), ApiForm(req)).await;

        assert_eq!(result.err(), Some(TokenError::InvalidCode));
    }

    #[tokio::test]
    async fn rejects_mismatched_redirect_uri() {
        let mut state = state();
        let verifier = "correct-verifier";
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for(verifier),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                uuid::Uuid::new_v4(),
            )
            .await;
        let req = code_req("code1", verifier, "http://other.test");

        let result = issue_token(State(state), ApiForm(req)).await;

        assert_eq!(result.err(), Some(TokenError::RedirectUriMismatch));
    }

    #[tokio::test]
    async fn rejects_wrong_code_verifier() {
        let mut state = state();
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for("correct-verifier"),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                uuid::Uuid::new_v4(),
            )
            .await;
        let req = code_req("code1", "wrong-verifier", "http://redirect.test");

        let result = issue_token(State(state), ApiForm(req)).await;

        assert_eq!(result.err(), Some(TokenError::InvalidCodeVerifier));
    }

    #[tokio::test]
    async fn code_is_single_use() {
        let (mut state, user_id) = state_with_user().await;
        let verifier = "correct-verifier";
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for(verifier),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let first_req = code_req("code1", verifier, "http://redirect.test");
        let _ = issue_token(State(state.clone()), ApiForm(first_req))
            .await
            .unwrap();

        let second_req = code_req("code1", verifier, "http://redirect.test");
        let result = issue_token(State(state), ApiForm(second_req)).await;

        assert_eq!(result.err(), Some(TokenError::InvalidCode));
    }

    #[tokio::test]
    async fn authorization_code_grant_rejects_missing_parameters() {
        let req = TokenRequest {
            grant_type: GrantType::AuthorizationCode,
            code: None,
            code_verifier: None,
            redirect_uri: None,
            refresh_token: None,
        };

        let result = issue_token(State(state()), ApiForm(req)).await;

        assert_eq!(result.err(), Some(TokenError::MissingParameters));
    }

    #[tokio::test]
    async fn issued_tokens_expire_in_the_future_not_the_past() {
        let (mut state, user_id) = state_with_user().await;
        let verifier = "correct-verifier";
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for(verifier),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let before = chrono::Utc::now();

        let Json(body) = issue_token(
            State(state),
            ApiForm(code_req("code1", verifier, "http://redirect.test")),
        )
        .await
        .unwrap();

        // Access-token expiry is a JWT claim, not a response field -- decode
        // the JWT's own payload (no signature check needed) to pin down that
        // `expires_at = issued_at + ttl`, not `- ttl`.
        let payload = body
            .access_token
            .split('.')
            .nth(1)
            .expect("JWT has a payload segment");
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("valid base64"))
                .expect("valid JSON");
        let exp = claims["exp"].as_i64().expect("exp claim");
        let iat = claims["iat"].as_i64().expect("iat claim");
        assert!(exp > iat, "access token must expire after it was issued");

        assert!(
            body.refresh_expires_at > before,
            "refresh token must expire in the future, not {} seconds in the past",
            (before - body.refresh_expires_at).num_seconds()
        );
    }

    #[tokio::test]
    async fn refresh_grant_rejects_missing_refresh_token() {
        let req = TokenRequest {
            grant_type: GrantType::RefreshToken,
            code: None,
            code_verifier: None,
            redirect_uri: None,
            refresh_token: None,
        };

        let result = issue_token(State(state()), ApiForm(req)).await;

        assert_eq!(result.err(), Some(TokenError::MissingParameters));
    }

    #[tokio::test]
    async fn refresh_grant_exchanges_a_valid_refresh_token_for_a_new_pair() {
        let (mut state, user_id) = state_with_user().await;
        let verifier = "correct-verifier";
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for(verifier),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let Json(first) = issue_token(
            State(state.clone()),
            ApiForm(code_req("code1", verifier, "http://redirect.test")),
        )
        .await
        .unwrap();

        let Json(second) = issue_token(State(state), ApiForm(refresh_req(&first.refresh_token)))
            .await
            .unwrap();

        assert_eq!(second.user_id, first.user_id);
        // The refresh token always rotates. The access token is a JWT over
        // `Claims`, which includes a timestamp -- if both calls land in the
        // same second it can legitimately come out byte-identical, so that's
        // not asserted here.
        assert_ne!(second.refresh_token, first.refresh_token);
    }

    #[tokio::test]
    async fn refresh_grant_rejects_unknown_refresh_token() {
        let result = issue_token(State(state()), ApiForm(refresh_req("never-issued"))).await;

        assert_eq!(result.err(), Some(TokenError::InvalidRefreshToken));
    }

    #[tokio::test]
    async fn reusing_a_rotated_refresh_token_revokes_the_whole_family() {
        let (mut state, user_id) = state_with_user().await;
        let verifier = "correct-verifier";
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for(verifier),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let Json(first) = issue_token(
            State(state.clone()),
            ApiForm(code_req("code1", verifier, "http://redirect.test")),
        )
        .await
        .unwrap();

        // Legitimate rotation: first.refresh_token -> second.refresh_token.
        let Json(second) = issue_token(
            State(state.clone()),
            ApiForm(refresh_req(&first.refresh_token)),
        )
        .await
        .unwrap();

        // The original token gets replayed -- reuse detected.
        let replay = issue_token(
            State(state.clone()),
            ApiForm(refresh_req(&first.refresh_token)),
        )
        .await;
        assert_eq!(replay.err(), Some(TokenError::InvalidRefreshToken));

        // The still-unused sibling from the same family is dead too.
        let sibling = issue_token(State(state), ApiForm(refresh_req(&second.refresh_token))).await;
        assert_eq!(sibling.err(), Some(TokenError::InvalidRefreshToken));
    }

    fn decode_claims(access_token: &str) -> serde_json::Value {
        let payload = access_token
            .split('.')
            .nth(1)
            .expect("JWT has a payload segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("valid base64"))
            .expect("valid JSON")
    }

    #[tokio::test]
    async fn merges_login_claims_handler_output_into_the_access_token() {
        let (mut state, user_id) = state_with_user().await;
        let claims = serde_json::Map::from_iter([(
            "roles".to_string(),
            serde_json::json!({"admin": ["user-1"]}),
        )]);
        state.login_claims_handler = Some(Arc::new(FixedClaimsHandler(claims)));
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for("correct-verifier"),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let req = code_req("code1", "correct-verifier", "http://redirect.test");

        let Json(body) = issue_token(State(state), ApiForm(req)).await.unwrap();

        let decoded = decode_claims(&body.access_token);
        assert_eq!(decoded["roles"]["admin"], serde_json::json!(["user-1"]));
    }

    // No handler configured: the merge path must be a no-op, not an error and
    // not a spurious `extra` key in the token.
    #[tokio::test]
    async fn issues_a_token_with_no_extra_claims_when_no_handler_is_configured() {
        let (mut state, user_id) = state_with_user().await;
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for("correct-verifier"),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let req = code_req("code1", "correct-verifier", "http://redirect.test");

        let Json(body) = issue_token(State(state), ApiForm(req)).await.unwrap();

        let decoded = decode_claims(&body.access_token);
        assert_eq!(
            decoded
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::HashSet<_>>(),
            std::collections::HashSet::from([
                "iss",
                "sub",
                "email",
                "email_verified",
                "iat",
                "exp"
            ])
        );
    }

    #[tokio::test]
    async fn access_token_is_issued_by_the_configured_issuer() {
        let (mut state, user_id) = state_with_user().await;
        state.issuer = "https://auth.internal".into();
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for("correct-verifier"),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let req = code_req("code1", "correct-verifier", "http://redirect.test");

        let Json(body) = issue_token(State(state), ApiForm(req)).await.unwrap();

        assert_eq!(
            decode_claims(&body.access_token)["iss"],
            "https://auth.internal"
        );
    }

    // Fail-closed: a login-claims handler configured but unreachable must
    // fail the request, not silently issue a token without the claims it was
    // configured to carry.
    #[tokio::test]
    async fn login_claims_handler_failure_fails_the_token_request() {
        let (mut state, user_id) = state_with_user().await;
        state.login_claims_handler = Some(Arc::new(FailingClaimsHandler));
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for("correct-verifier"),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let req = code_req("code1", "correct-verifier", "http://redirect.test");

        let result = issue_token(State(state), ApiForm(req)).await;

        assert_eq!(result.err(), Some(TokenError::DownstreamServiceFailed));
    }

    // A plugin/webhook that returns a reserved claim name (e.g. `sub`) could
    // otherwise spoof identity claims -- the request must fail instead of
    // silently letting the downstream value win or lose the merge.
    #[tokio::test]
    async fn a_reserved_claim_name_from_the_handler_fails_the_token_request() {
        for name in [
            "iss",
            "sub",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "email",
            "email_verified",
        ] {
            let (mut state, user_id) = state_with_user().await;
            let claims = serde_json::Map::from_iter([(
                name.to_string(),
                serde_json::json!("attacker-controlled"),
            )]);
            state.login_claims_handler = Some(Arc::new(FixedClaimsHandler(claims)));
            state
                .pkce
                .save_code_challenge(
                    "code1".to_string(),
                    challenge_for("correct-verifier"),
                    CodeChallengeMethod::S256,
                    "http://redirect.test".to_string(),
                    user_id,
                )
                .await;
            let req = code_req("code1", "correct-verifier", "http://redirect.test");

            let result = issue_token(State(state), ApiForm(req)).await;

            assert_eq!(
                result.err(),
                Some(TokenError::ReservedClaimOverridden),
                "{name}"
            );
        }
    }

    // "Every token mint" (the locked design decision): a refresh grant must
    // also go through the login-claims handler, not just the initial
    // authorization_code exchange.
    #[tokio::test]
    async fn refresh_grant_also_merges_login_claims_handler_output() {
        let (mut state, user_id) = state_with_user().await;
        let claims =
            serde_json::Map::from_iter([("roles".to_string(), serde_json::json!(["admin"]))]);
        state.login_claims_handler = Some(Arc::new(FixedClaimsHandler(claims)));
        state
            .pkce
            .save_code_challenge(
                "code1".to_string(),
                challenge_for("correct-verifier"),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let Json(first) = issue_token(
            State(state.clone()),
            ApiForm(code_req(
                "code1",
                "correct-verifier",
                "http://redirect.test",
            )),
        )
        .await
        .unwrap();

        let Json(second) = issue_token(State(state), ApiForm(refresh_req(&first.refresh_token)))
            .await
            .unwrap();

        let decoded = decode_claims(&second.access_token);
        assert_eq!(decoded["roles"], serde_json::json!(["admin"]));
    }
}
