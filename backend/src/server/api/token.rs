pub(crate) use controller::issue_token;
pub(crate) use controller::issue_token_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::{Form, State};
    use axum::http::StatusCode;
    use axum::Json;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::{DateTime, Duration, Utc};
    use rand::RngExt;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use crate::server::AppState;
    use crate::storage::PkceStorage;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct TokenRequest {
        pub(super) code: String,
        pub(super) code_verifier: String,
        pub(super) redirect_uri: String,
    }

    #[derive(Serialize, JsonSchema)]
    #[serde(rename_all = "PascalCase")]
    pub(crate) enum TokenType {
        Bearer,
    }

    #[derive(Serialize, JsonSchema)]
    pub(crate) struct TokenResponse {
        access_token: String,
        refresh_token: String,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
        /// The user this token was issued to -- carried through from the
        /// `login_session` `/oauth/login` created, via the auth code.
        pub(super) user_id: Uuid,
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

    pub(crate) async fn issue_token(
        State(mut state): State<AppState>,
        Form(req): Form<TokenRequest>,
    ) -> Result<Json<TokenResponse>, StatusCode> {
        let (challenge, _method, issued_redirect_uri, user_id) = state
            .pkce
            .take_code_challenge(&req.code)
            .await
            .ok_or(StatusCode::BAD_REQUEST)?;

        // Binds the code to the redirect_uri it was issued for (RFC 6749 4.1.3) --
        // without this, a code obtained for one redirect_uri could be redeemed
        // while claiming a different one.
        if req.redirect_uri != issued_redirect_uri {
            return Err(StatusCode::BAD_REQUEST);
        }

        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(req.code_verifier.as_bytes()));
        if computed != challenge {
            return Err(StatusCode::BAD_REQUEST);
        }

        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);
        let access_token = URL_SAFE_NO_PAD.encode(token_bytes);
        rand::rng().fill(&mut token_bytes);
        let refresh_token = URL_SAFE_NO_PAD.encode(token_bytes);

        Ok(Json(TokenResponse {
            access_token,
            refresh_token,
            token_type: TokenType::Bearer,
            expires_at: Utc::now() + Duration::minutes(15),
            user_id,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::extract::{Form, State};
    use axum::http::StatusCode;
    use axum::Json;

    use crate::model::pkce::CodeChallengeMethod;
    use crate::server::AppState;
    use crate::storage::in_memory::InMemoryPkceStorage;
    use crate::storage::PkceStorage;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    fn state() -> AppState {
        AppState {
            pkce: InMemoryPkceStorage::new(300),
            users: crate::storage::in_memory::InMemoryUserStorage::new(),
            login_sessions: crate::storage::in_memory::InMemoryLoginSessionStorage::new(60),
            redirect_uri_allowlist: Arc::new(vec![]),
        }
    }

    fn challenge_for(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
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
        let req = TokenRequest {
            code: "code1".to_string(),
            code_verifier: verifier.to_string(),
            redirect_uri: "http://redirect.test".to_string(),
        };

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
        let req = TokenRequest {
            code: "code1".to_string(),
            code_verifier: verifier.to_string(),
            redirect_uri: "http://redirect.test".to_string(),
        };

        let Json(body) = issue_token(State(state), Form(req)).await.unwrap();

        assert_eq!(body.user_id, user_id);
    }

    #[tokio::test]
    async fn rejects_unknown_code() {
        let req = TokenRequest {
            code: "never-issued".to_string(),
            code_verifier: "whatever".to_string(),
            redirect_uri: "http://redirect.test".to_string(),
        };

        let result = issue_token(State(state()), Form(req)).await;

        assert_eq!(result.err(), Some(StatusCode::BAD_REQUEST));
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
        let req = TokenRequest {
            code: "code1".to_string(),
            code_verifier: verifier.to_string(),
            redirect_uri: "http://other.test".to_string(),
        };

        let result = issue_token(State(state), Form(req)).await;

        assert_eq!(result.err(), Some(StatusCode::BAD_REQUEST));
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
        let req = TokenRequest {
            code: "code1".to_string(),
            code_verifier: "wrong-verifier".to_string(),
            redirect_uri: "http://redirect.test".to_string(),
        };

        let result = issue_token(State(state), Form(req)).await;

        assert_eq!(result.err(), Some(StatusCode::BAD_REQUEST));
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
        let first_req = TokenRequest {
            code: "code1".to_string(),
            code_verifier: verifier.to_string(),
            redirect_uri: "http://redirect.test".to_string(),
        };
        let _ = issue_token(State(state.clone()), Form(first_req)).await.unwrap();

        let second_req = TokenRequest {
            code: "code1".to_string(),
            code_verifier: verifier.to_string(),
            redirect_uri: "http://redirect.test".to_string(),
        };
        let result = issue_token(State(state), Form(second_req)).await;

        assert_eq!(result.err(), Some(StatusCode::BAD_REQUEST));
    }
}
