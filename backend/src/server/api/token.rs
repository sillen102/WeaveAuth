pub(crate) use controller::issue_token;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::{Form, State};
    use axum::http::StatusCode;
    use axum::Json;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::{DateTime, Duration, Utc};
    use rand::RngExt;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use crate::server::AppState;
    use crate::storage::PkceStorage;

    #[derive(Deserialize)]
    pub(crate) struct TokenRequest {
        code: String,
        code_verifier: String,
        redirect_uri: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub(crate) enum TokenType {
        Bearer,
    }

    #[derive(Serialize)]
    pub(crate) struct TokenResponse {
        access_token: String,
        refresh_token: String,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
    }

    // OpenAPI documentation for this route.
    pub(crate) fn doc(op: TransformOperation) -> TransformOperation {
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
        let (challenge, _method, issued_redirect_uri) = state
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
        }))
    }
}
