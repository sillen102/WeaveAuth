pub(crate) use controller::oidc_callback;
pub(crate) use controller::oidc_callback_doc;
pub(crate) use controller::oidc_confirm_link;
pub(crate) use controller::oidc_confirm_link_doc;
pub(crate) use controller::oidc_login;
pub(crate) use controller::oidc_login_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::{Path, Query, State};
    use axum::response::Redirect;
    use axum::Json;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    use crate::server::AppState;

    use super::service;
    pub(crate) use super::service::OidcError;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct OidcCallbackQuery {
        pub(super) code: String,
        pub(super) state: String,
    }

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct OidcConfirmLinkRequest {
        pub(super) pending_link_token: String,
        pub(super) password: String,
    }

    #[derive(Serialize, JsonSchema)]
    pub(crate) struct OidcConfirmLinkResponse {
        /// Same shape as a successful `/oauth/login` response.
        pub(super) login_session: String,
    }

    pub(crate) async fn oidc_login(
        State(mut state): State<AppState>,
        Path(provider): Path<String>,
    ) -> Result<Redirect, OidcError> {
        let auth_url = service::oidc_login(&mut state, provider).await?;
        Ok(Redirect::to(&auth_url))
    }

    pub(crate) async fn oidc_callback(
        State(mut state): State<AppState>,
        Path(provider): Path<String>,
        Query(query): Query<OidcCallbackQuery>,
    ) -> Result<Json<service::OidcCallbackResponse>, OidcError> {
        let response = service::oidc_callback(&mut state, provider, query.code, query.state).await?;
        Ok(Json(response))
    }

    /// Finishes linking an OIDC identity that `oidc_callback` flagged as
    /// `PasswordConfirmationRequired`, once the caller has supplied the
    /// existing account's password.
    pub(crate) async fn oidc_confirm_link(
        State(mut state): State<AppState>,
        Json(req): Json<OidcConfirmLinkRequest>,
    ) -> Result<Json<OidcConfirmLinkResponse>, OidcError> {
        let login_session =
            service::oidc_confirm_link(&mut state, &req.pending_link_token, req.password.into()).await?;
        Ok(Json(OidcConfirmLinkResponse { login_session }))
    }

    pub(crate) fn oidc_login_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("oidc_login")
            .summary("Start a third-party OIDC login")
            .description(
                "Not meant to be called by the browser directly -- bff proxies this \
                 server-to-server and relays the redirect. `provider` is one of the keys \
                 configured under `oidc_providers`, e.g. \"google\".",
            )
    }

    pub(crate) fn oidc_callback_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("oidc_callback")
            .summary("Complete a third-party OIDC login")
            .description(
                "Not meant to be called by the provider directly -- backend isn't \
                 internet-exposed, so bff receives the provider's redirect at its own public \
                 URL and forwards code+state here server-to-server. Returns either an \
                 Authenticated login_session (same shape as a successful /oauth/login), or a \
                 PasswordConfirmationRequired response if this email matches an existing but \
                 unverified account -- see /oauth/oidc/confirm-link.",
            )
    }

    pub(crate) fn oidc_confirm_link_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("oidc_confirm_link")
            .summary("Finish linking an OIDC identity into an unverified account")
            .description(
                "Call after /oauth/oidc/{provider}/callback returns \
                 PasswordConfirmationRequired, supplying that account's password. On success, \
                 the account is marked email_verified and the identity is linked, exactly as if \
                 the email had already been verified at callback time.",
            )
    }
}

mod service {
    use axum::http::StatusCode;
    use openidconnect::core::CoreAuthenticationFlow;
    use openidconnect::{
        AuthorizationCode, CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier, Scope,
        TokenResponse,
    };
    use schemars::JsonSchema;
    use secrecy::{ExposeSecret, SecretString};
    use serde::Serialize;
    use thiserror::Error;
    use common_macros::ErrorResponses;

    use crate::crypto;
    use crate::model::user::PasswordHash;
    use crate::server::AppState;
    use crate::storage::{
        LoginSessionStorage, OidcLinkOutcome, OidcStateStorage, PendingOidcLinkStorage, UserStorage, VerifiedEmail,
    };

    #[derive(Serialize, JsonSchema)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub(crate) enum OidcCallbackResponse {
        /// Same shape as a successful `/oauth/login` response -- single-use
        /// proof of this authentication, required by `/oauth/authorize`.
        Authenticated { login_session: String },
        /// An account with this email already exists but isn't verified yet
        /// (see `UserStorage::resolve_oidc_login`). Submit that account's
        /// password to `/oauth/oidc/confirm-link` along with
        /// `pending_link_token` to finish linking; the OIDC login isn't
        /// authenticated yet.
        PasswordConfirmationRequired { pending_link_token: String, email: String },
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum OidcError {
        #[error("unknown oidc provider")]
        #[error_response(StatusCode::NOT_FOUND, details = "unknown oidc provider")]
        UnknownProvider,
        #[error("invalid or expired oidc state")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid or expired oidc state")]
        InvalidState,
        #[error("oidc token exchange or id token verification failed")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "oidc token exchange or id token verification failed"
        )]
        ExchangeFailed,
        /// Accounts are linked across providers by email (see
        /// `UserStorage::resolve_oidc_login`), so an id_token whose email
        /// isn't provider-confirmed can't be trusted for that -- rather than
        /// silently falling back to an unmerged identity, this fails loudly
        /// since it means either the provider doesn't verify emails
        /// (shouldn't happen for a provider deliberately configured here) or
        /// something is misconfigured (e.g. missing the `email` scope).
        #[error("oidc provider did not return a verified email")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "oidc provider did not return a verified email"
        )]
        EmailNotVerified,
        #[error("invalid or expired pending oidc link")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid or expired pending oidc link")]
        InvalidPendingLink,
        #[error("incorrect password")]
        #[error_response(StatusCode::UNAUTHORIZED, details = "incorrect password")]
        PasswordConfirmationFailed,
    }

    /// Starts a third-party OIDC login for `provider`, returning the
    /// provider's consent-screen URL to redirect the caller to.
    pub(crate) async fn oidc_login(state: &mut AppState, provider: String) -> Result<String, OidcError> {
        let client = state
            .oidc_providers
            .get(&provider)
            .ok_or(OidcError::UnknownProvider)?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        state
            .oidc_state
            .save_state(
                csrf_token.secret().clone(),
                provider,
                pkce_verifier.secret().clone(),
                nonce.secret().clone(),
            )
            .await;

        Ok(auth_url.to_string())
    }

    pub(crate) async fn oidc_callback(
        state: &mut AppState,
        provider: String,
        code: String,
        query_state: String,
    ) -> Result<OidcCallbackResponse, OidcError> {
        let login_state = state
            .oidc_state
            .take_state(&query_state)
            .await
            .filter(|s| s.provider == provider)
            .ok_or(OidcError::InvalidState)?;
        let stored_provider = login_state.provider;

        let client = state
            .oidc_providers
            .get(&stored_provider)
            .ok_or(OidcError::UnknownProvider)?;

        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(login_state.pkce_verifier.expose_secret().to_string()))
            .request_async(&*state.oidc_http_client)
            .await
            .map_err(|_| OidcError::ExchangeFailed)?;

        let id_token = token_response.id_token().ok_or(OidcError::ExchangeFailed)?;
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &Nonce::new(login_state.nonce.expose_secret().to_string()))
            .map_err(|_| OidcError::ExchangeFailed)?;

        // Accounts are linked across providers by matching this email against
        // existing users (see `resolve_oidc_login`), so it must be one the
        // provider has actually confirmed the user owns -- otherwise anyone
        // able to put an arbitrary "email" claim in an id_token could attach
        // themselves to any victim's account. Naming that proof here (rather
        // than a bare `if` guarding a later call) is what lets
        // `resolve_oidc_login` require a `VerifiedEmail` in its signature --
        // this is the only place in the codebase allowed to construct one
        // from an OIDC claim.
        let email = claims.email().ok_or(OidcError::EmailNotVerified)?.as_str().to_string();
        let verified_email =
            VerifiedEmail::new(email.clone(), claims.email_verified() == Some(true)).ok_or(OidcError::EmailNotVerified)?;
        let subject = claims.subject().as_str();

        let response = match state.users.resolve_oidc_login(&stored_provider, subject, &verified_email).await {
            OidcLinkOutcome::Resolved(user) => {
                let login_session = state.login_sessions.create_session(user.id).await;
                OidcCallbackResponse::Authenticated { login_session }
            }
            OidcLinkOutcome::RequiresPasswordConfirmation { existing_user_id } => {
                let pending_link_token = state
                    .pending_oidc_links
                    .save_pending_link(stored_provider, subject.to_string(), existing_user_id)
                    .await;
                OidcCallbackResponse::PasswordConfirmationRequired { pending_link_token, email }
            }
        };

        Ok(response)
    }

    /// Finishes linking an OIDC identity that `oidc_callback` flagged as
    /// `PasswordConfirmationRequired`, once the caller has supplied the
    /// existing account's password.
    pub(crate) async fn oidc_confirm_link(
        state: &mut AppState,
        pending_link_token: &str,
        password: SecretString,
    ) -> Result<String, OidcError> {
        let pending_link = state
            .pending_oidc_links
            .take_pending_link(pending_link_token)
            .await
            .ok_or(OidcError::InvalidPendingLink)?;

        let user = state
            .users
            .get_user_by_id(pending_link.existing_user_id)
            .await
            .ok_or(OidcError::InvalidPendingLink)?;
        let hash = user.password.ok_or(OidcError::PasswordConfirmationFailed)?;
        let is_legacy_bcrypt = matches!(hash, PasswordHash::Bcrypt(_));

        // No dummy-hash timing guard needed: pending_link_token already reveals the account exists.
        match crypto::verify_password(hash, password.clone(), state.max_bcrypt_cost).await {
            Ok(crypto::PasswordVerifyOutcome::Verified) => {}
            Ok(crypto::PasswordVerifyOutcome::NotVerified) | Err(_) => {
                return Err(OidcError::PasswordConfirmationFailed);
            }
        }

        if is_legacy_bcrypt {
            crate::server::api::upgrade_bcrypt_to_argon2(&mut state.users, user.id, password).await;
        }

        let user = state
            .users
            .link_verified_oidc_identity(pending_link.existing_user_id, &pending_link.provider, &pending_link.subject)
            .await
            .ok_or(OidcError::PasswordConfirmationFailed)?;
        let login_session = state.login_sessions.create_session(user.id).await;

        Ok(login_session)
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::extract::{Path, Query, State};
    use axum::Json;
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::model::user::{PasswordHash, User};
    use crate::server::AppState;
    use crate::storage::{OidcStateStorage, PendingOidcLinkStorage, UserStorage};

    async fn state_with_no_providers() -> AppState {
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
            oidc_providers: Arc::new(HashMap::new()),
            oidc_state: crate::storage::in_memory::InMemoryOidcStateStorage::new(300),
            pending_oidc_links: crate::storage::in_memory::InMemoryPendingOidcLinkStorage::new(300),
            oidc_http_client: Arc::new(openidconnect::reqwest::Client::new()),
            password_reset_tokens: crate::storage::in_memory::InMemoryPasswordResetTokenStorage::new(1_800),
            max_bcrypt_cost: 12,
            extra_data_handler: None,
        }
    }

    #[tokio::test]
    async fn login_rejects_unknown_provider() {
        let state = state_with_no_providers().await;

        let result = oidc_login(State(state), Path("google".to_string())).await;

        assert_eq!(result.err(), Some(OidcError::UnknownProvider));
    }

    #[tokio::test]
    async fn callback_rejects_missing_or_unknown_state() {
        let state = state_with_no_providers().await;
        let query = OidcCallbackQuery {
            code: "irrelevant".to_string(),
            state: "no-such-state".to_string(),
        };

        let result = oidc_callback(State(state), Path("google".to_string()), Query(query)).await;

        assert_eq!(result.err(), Some(OidcError::InvalidState));
    }

    #[tokio::test]
    async fn callback_rejects_state_issued_for_a_different_provider() {
        let mut state = state_with_no_providers().await;
        state
            .oidc_state
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;
        let query = OidcCallbackQuery {
            code: "irrelevant".to_string(),
            state: "csrf-token".to_string(),
        };

        let result = oidc_callback(
            State(state),
            Path("some-other-provider".to_string()),
            Query(query),
        )
        .await;

        assert_eq!(result.err(), Some(OidcError::InvalidState));
    }

    #[tokio::test]
    async fn callback_state_is_single_use() {
        let mut state = state_with_no_providers().await;
        state
            .oidc_state
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;
        let query = OidcCallbackQuery {
            code: "irrelevant".to_string(),
            state: "csrf-token".to_string(),
        };
        // First call consumes the state; provider is unknown here (no real
        // client configured in this test), so it fails past the state check
        // -- what matters is the state entry is gone afterwards.
        let _ = oidc_callback(State(state.clone()), Path("google".to_string()), Query(query)).await;

        let replay_query = OidcCallbackQuery {
            code: "irrelevant".to_string(),
            state: "csrf-token".to_string(),
        };
        let result = oidc_callback(State(state), Path("google".to_string()), Query(replay_query)).await;

        assert_eq!(result.err(), Some(OidcError::InvalidState));
    }

    /// Builds a real `OidcClient` (via discovery against a mocked issuer)
    /// plus a matching signed id_token, so `oidc_callback` can run its full
    /// exchange instead of stopping at the state/provider lookup like the
    /// other tests here.
    async fn provider_and_id_token(
        email: &str,
        email_verified: bool,
        nonce: &str,
    ) -> (String, std::sync::Arc<HashMap<String, crate::oidc::OidcClient>>, String) {
        use serde::Serialize;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let issuer = server.uri();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .mount(&server)
            .await;

        let signing_key = crate::crypto::JwtKeys::generate().expect("RSA keygen for tests never fails");

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(signing_key.jwk_set()))
            .mount(&server)
            .await;

        #[derive(Serialize)]
        struct IdTokenClaims<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: &'a str,
            exp: i64,
            iat: i64,
            nonce: &'a str,
            email: &'a str,
            email_verified: bool,
        }

        let now = chrono::Utc::now();
        let claims = IdTokenClaims {
            iss: &issuer,
            sub: "provider-subject",
            aud: "client-id",
            exp: (now + chrono::Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            nonce,
            email,
            email_verified,
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(signing_key.kid.clone());
        let id_token = jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key).expect("signing");

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "opaque-access-token",
                "token_type": "Bearer",
                "id_token": id_token,
            })))
            .mount(&server)
            .await;

        let mut configs = HashMap::new();
        configs.insert(
            "test-provider".to_string(),
            crate::config::OidcProviderConfig {
                issuer: issuer.clone(),
                client_id: "client-id".to_string(),
                client_secret: secrecy::SecretString::from("client-secret".to_string()),
                redirect_uri: "http://localhost/callback".to_string(),
            },
        );
        let http_client = openidconnect::reqwest::Client::new();
        let providers = crate::oidc::build_providers(&configs, &http_client)
            .await
            .expect("discovery succeeds");

        // The mock server must outlive the request that hits it -- returning
        // it (leaked, effectively) alongside the providers keeps it alive
        // for the caller's `oidc_callback` call.
        std::mem::forget(server);
        (issuer, std::sync::Arc::new(providers), id_token)
    }

    #[tokio::test]
    async fn callback_resolves_to_authenticated_when_the_provider_confirms_the_email() {
        let (_issuer, providers, _id_token) = provider_and_id_token("alice@example.com", true, "test-nonce").await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        state
            .oidc_state
            .save_state(
                "csrf-token".to_string(),
                "test-provider".to_string(),
                "verifier".to_string(),
                "test-nonce".to_string(),
            )
            .await;
        let query = OidcCallbackQuery { code: "irrelevant".to_string(), state: "csrf-token".to_string() };

        let result = oidc_callback(State(state), Path("test-provider".to_string()), Query(query)).await;

        let Json(super::service::OidcCallbackResponse::Authenticated { .. }) = result.expect("callback succeeds")
        else {
            unreachable!("expected Authenticated");
        };
    }

    #[tokio::test]
    async fn callback_rejects_an_id_token_whose_email_is_not_verified() {
        // The only reason this must fail is the provider's email_verified
        // claim being false -- everything else about the exchange (issuer,
        // audience, signature, nonce) is valid. Without this check, anyone
        // able to put an arbitrary "email" in an id_token could attach
        // themselves to any victim's account (see the comment at the call
        // site in `service::oidc_callback`).
        let (_issuer, providers, _id_token) = provider_and_id_token("alice@example.com", false, "test-nonce").await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        state
            .oidc_state
            .save_state(
                "csrf-token".to_string(),
                "test-provider".to_string(),
                "verifier".to_string(),
                "test-nonce".to_string(),
            )
            .await;
        let query = OidcCallbackQuery { code: "irrelevant".to_string(), state: "csrf-token".to_string() };

        let result = oidc_callback(State(state), Path("test-provider".to_string()), Query(query)).await;

        assert_eq!(result.err(), Some(OidcError::EmailNotVerified));
    }

    #[tokio::test]
    async fn confirm_link_rejects_missing_or_expired_token() {
        let state = state_with_no_providers().await;
        let req = OidcConfirmLinkRequest {
            pending_link_token: "no-such-token".to_string(),
            password: "whatever".to_string(),
        };

        let result = oidc_confirm_link(State(state), Json(req)).await;

        assert_eq!(result.err(), Some(OidcError::InvalidPendingLink));
    }

    #[tokio::test]
    async fn confirm_link_rejects_wrong_password() {
        use argon2::PasswordHasher;
        use crate::crypto::ARGON2;

        let mut state = state_with_no_providers().await;
        let hash = ARGON2
            .hash_password(b"correct-password")
            .expect("hashing a test password never fails")
            .to_string();
        let user = User {
            email: "squatter@example.com".to_string(),
            password: Some(PasswordHash::Argon2(hash.into())),
            email_verified: false,
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let token = state
            .pending_oidc_links
            .save_pending_link("google".to_string(), "sub-123".to_string(), user_id)
            .await;

        let req = OidcConfirmLinkRequest {
            pending_link_token: token,
            password: "wrong-password".to_string(),
        };
        let result = oidc_confirm_link(State(state.clone()), Json(req)).await;

        assert_eq!(result.err(), Some(OidcError::PasswordConfirmationFailed));
        // Untouched: still unverified, no identity linked.
        let still_unverified = state.users.get_user_by_email("squatter@example.com").await.unwrap();
        assert!(!still_unverified.email_verified);
    }

    #[tokio::test]
    async fn confirm_link_succeeds_with_correct_password_and_is_single_use() {
        use argon2::PasswordHasher;
        use crate::crypto::ARGON2;

        let mut state = state_with_no_providers().await;
        let hash = ARGON2
            .hash_password(b"correct-password")
            .expect("hashing a test password never fails")
            .to_string();
        let user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2(hash.into())),
            email_verified: false,
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let token = state
            .pending_oidc_links
            .save_pending_link("google".to_string(), "sub-123".to_string(), user_id)
            .await;

        let req = OidcConfirmLinkRequest {
            pending_link_token: token.clone(),
            password: "correct-password".to_string(),
        };
        let Json(body) = oidc_confirm_link(State(state.clone()), Json(req)).await.unwrap();
        assert!(!body.login_session.is_empty());

        let now_verified = state.users.get_user_by_email("alice@example.com").await.unwrap();
        assert!(now_verified.email_verified);

        // Single-use: the same token can't be redeemed twice.
        let replay = OidcConfirmLinkRequest {
            pending_link_token: token,
            password: "correct-password".to_string(),
        };
        let result = oidc_confirm_link(State(state), Json(replay)).await;
        assert_eq!(result.err(), Some(OidcError::InvalidPendingLink));
    }
}
