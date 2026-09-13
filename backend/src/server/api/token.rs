pub(crate) use controller::issue_token;
pub(crate) use controller::issue_token_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::Json;
    use axum::extract::{Form, State};
    use axum::http::StatusCode;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::{DateTime, Duration, Utc};
    use common::model::token::{GrantType, TokenType};
    use common_macros::ErrorResponses;
    use jsonwebtoken::{Algorithm, Header};
    use rand::RngExt;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use thiserror::Error;
    use uuid::Uuid;

    use crate::server::AppState;
    use crate::storage::{JwkStorage, PkceStorage, RefreshTokenOutcome, RefreshTokenStorage};

    /// Access token claims (RFC 7519).
    #[derive(Serialize)]
    struct Claims {
        sub: Uuid,
        iat: i64,
        exp: i64,
    }

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct TokenRequest {
        pub(super) grant_type: GrantType,
        pub(super) code: Option<String>,
        pub(super) code_verifier: Option<String>,
        pub(super) redirect_uri: Option<String>,
        pub(super) refresh_token: Option<String>,
    }

    #[derive(Serialize, JsonSchema)]
    pub(crate) struct TokenResponse {
        pub(super) access_token: String,
        pub(super) refresh_token: String,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
        pub(super) refresh_expires_at: DateTime<Utc>,
        /// The user this token was issued to -- carried through from the
        /// `login_session` `/oauth/login` created, via the auth code.
        pub(super) user_id: Uuid,
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
        #[error("internal error")]
        #[error_response(StatusCode::INTERNAL_SERVER_ERROR)]
        UnexpectedError,
    }

    pub(crate) async fn issue_token(
        State(mut state): State<AppState>,
        Form(req): Form<TokenRequest>,
    ) -> Result<Json<TokenResponse>, TokenError> {
        match req.grant_type {
            GrantType::AuthorizationCode => {
                let (code, code_verifier, redirect_uri) =
                    match (req.code, req.code_verifier, req.redirect_uri) {
                        (Some(code), Some(code_verifier), Some(redirect_uri)) => {
                            (code, code_verifier, redirect_uri)
                        }
                        _ => return Err(TokenError::MissingParameters),
                    };

                let (challenge, _method, issued_redirect_uri, user_id) = state
                    .pkce
                    .take_code_challenge(&code)
                    .await
                    .ok_or(TokenError::InvalidCode)?;

                // Binds the code to the redirect_uri it was issued for (RFC 6749
                // 4.1.3) -- without this, a code obtained for one redirect_uri
                // could be redeemed while claiming a different one.
                if redirect_uri != issued_redirect_uri {
                    return Err(TokenError::RedirectUriMismatch);
                }

                let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
                if computed != challenge {
                    return Err(TokenError::InvalidCodeVerifier);
                }

                issue_tokens(&mut state, user_id, Uuid::new_v4()).await
            }
            GrantType::RefreshToken => {
                let refresh_token = req.refresh_token.ok_or(TokenError::MissingParameters)?;

                match state.refresh_tokens.take_refresh_token(&refresh_token).await {
                    RefreshTokenOutcome::Valid { user_id, family_id } => {
                        issue_tokens(&mut state, user_id, family_id).await
                    }
                    // Already-used token: the storage layer has revoked the
                    // whole family as a side effect. Wrong/unknown token: same
                    // client-facing error either way, so the response doesn't
                    // leak which case it was.
                    RefreshTokenOutcome::Reused | RefreshTokenOutcome::NotFound => {
                        Err(TokenError::InvalidRefreshToken)
                    }
                }
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
    ) -> Result<Json<TokenResponse>, TokenError> {
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(state.access_token_ttl_secs);
        let refresh_expires_at = issued_at + Duration::seconds(state.refresh_token_ttl_secs);
        let claims = Claims {
            sub: user_id,
            iat: issued_at.timestamp(),
            exp: expires_at.timestamp(),
        };
        let signing_key = state.jwt_keys.active_key().await;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(signing_key.kid.clone());
        let access_token = jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key)
            .map_err(|_| TokenError::UnexpectedError)?;

        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);
        let refresh_token = URL_SAFE_NO_PAD.encode(token_bytes);
        state
            .refresh_tokens
            .save_refresh_token(refresh_token.clone(), user_id, family_id)
            .await;

        Ok(Json(TokenResponse {
            access_token,
            refresh_token,
            token_type: TokenType::Bearer,
            expires_at,
            refresh_expires_at,
            user_id,
        }))
    }

    // OpenAPI documentation for this route.
    pub(crate) fn issue_token_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("token")
            .summary("Exchange an authorization code for tokens")
            .description(
                "Verifies code_verifier against the code_challenge stored at /oauth/authorize, \
                 and that redirect_uri matches the one the code was issued for",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::Json;
    use axum::extract::{Form, State};
    use common::model::token::GrantType;

    use crate::model::pkce::CodeChallengeMethod;
    use crate::server::AppState;
    use crate::storage::PkceStorage;
    use crate::storage::in_memory::InMemoryPkceStorage;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

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
        }
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
        let req = code_req("code1", verifier, "http://redirect.test");

        let result = issue_token(State(state), Form(req)).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn token_response_carries_the_user_id_the_code_was_issued_to() {
        let mut state = state();
        let verifier = "correct-verifier";
        let user_id = uuid::Uuid::new_v4();
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

        let Json(body) = issue_token(State(state), Form(req)).await.unwrap();

        assert_eq!(body.user_id, user_id);
    }

    #[tokio::test]
    async fn rejects_unknown_code() {
        let req = code_req("never-issued", "whatever", "http://redirect.test");

        let result = issue_token(State(state()), Form(req)).await;

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

        let result = issue_token(State(state), Form(req)).await;

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

        let result = issue_token(State(state), Form(req)).await;

        assert_eq!(result.err(), Some(TokenError::InvalidCodeVerifier));
    }

    #[tokio::test]
    async fn code_is_single_use() {
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
        let first_req = code_req("code1", verifier, "http://redirect.test");
        let _ = issue_token(State(state.clone()), Form(first_req))
            .await
            .unwrap();

        let second_req = code_req("code1", verifier, "http://redirect.test");
        let result = issue_token(State(state), Form(second_req)).await;

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

        let result = issue_token(State(state()), Form(req)).await;

        assert_eq!(result.err(), Some(TokenError::MissingParameters));
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

        let result = issue_token(State(state()), Form(req)).await;

        assert_eq!(result.err(), Some(TokenError::MissingParameters));
    }

    #[tokio::test]
    async fn refresh_grant_exchanges_a_valid_refresh_token_for_a_new_pair() {
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
        let Json(first) = issue_token(
            State(state.clone()),
            Form(code_req("code1", verifier, "http://redirect.test")),
        )
        .await
        .unwrap();

        let Json(second) =
            issue_token(State(state), Form(refresh_req(&first.refresh_token)))
                .await
                .unwrap();

        assert_eq!(second.user_id, first.user_id);
        // The refresh token always rotates. The access token is a JWT over
        // {sub, iat, exp} -- if both calls land in the same second it can
        // legitimately come out byte-identical, so that's not asserted here.
        assert_ne!(second.refresh_token, first.refresh_token);
    }

    #[tokio::test]
    async fn refresh_grant_rejects_unknown_refresh_token() {
        let result = issue_token(State(state()), Form(refresh_req("never-issued"))).await;

        assert_eq!(result.err(), Some(TokenError::InvalidRefreshToken));
    }

    #[tokio::test]
    async fn reusing_a_rotated_refresh_token_revokes_the_whole_family() {
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
        let Json(first) = issue_token(
            State(state.clone()),
            Form(code_req("code1", verifier, "http://redirect.test")),
        )
        .await
        .unwrap();

        // Legitimate rotation: first.refresh_token -> second.refresh_token.
        let Json(second) = issue_token(
            State(state.clone()),
            Form(refresh_req(&first.refresh_token)),
        )
        .await
        .unwrap();

        // The original token gets replayed -- reuse detected.
        let replay = issue_token(State(state.clone()), Form(refresh_req(&first.refresh_token)))
            .await;
        assert_eq!(replay.err(), Some(TokenError::InvalidRefreshToken));

        // The still-unused sibling from the same family is dead too.
        let sibling = issue_token(State(state), Form(refresh_req(&second.refresh_token))).await;
        assert_eq!(sibling.err(), Some(TokenError::InvalidRefreshToken));
    }
}
