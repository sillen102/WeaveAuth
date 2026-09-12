pub(crate) use controller::auth_authorize;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::{Query, State};
    use axum::http::StatusCode;
    use axum::response::Redirect;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::RngExt;
    use serde::Deserialize;

    use crate::model::pkce::CodeChallengeMethod;
    use crate::server::AppState;
    use crate::storage::PkceStorage;

    #[derive(Deserialize)]
    pub(crate) struct AuthorizeRequest {
        redirect_uri: String,
        code_challenge: String,
        code_challenge_method: CodeChallengeMethod,
        #[serde(default)]
        state: Option<String>,
    }

    // OpenAPI documentation for this route.
    pub(crate) fn doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("authorize")
            .summary("Issue an authorization code")
            .description("Binds a single-use auth_code to the given PKCE code_challenge")
    }

    pub(crate) async fn auth_authorize(
        State(mut state): State<AppState>,
        Query(req): Query<AuthorizeRequest>,
    ) -> Result<Redirect, StatusCode> {
        // TODO: require an authenticated session before issuing a code (see README TODO ledger).
        if !state
            .redirect_uri_allowlist
            .iter()
            .any(|allowed| allowed == &req.redirect_uri)
        {
            return Err(StatusCode::BAD_REQUEST);
        }

        let mut code_bytes = [0u8; 32];
        rand::rng().fill(&mut code_bytes);
        let auth_code = URL_SAFE_NO_PAD.encode(code_bytes);

        state
            .pkce
            .save_code_challenge(
                auth_code.clone(),
                req.code_challenge,
                req.code_challenge_method,
                req.redirect_uri.clone(),
            )
            .await;

        let location = match req.state {
            Some(s) => format!("{}?code={}&state={}", req.redirect_uri, auth_code, s),
            None => format!("{}?code={}", req.redirect_uri, auth_code),
        };
        Ok(Redirect::to(&location))
    }
}
