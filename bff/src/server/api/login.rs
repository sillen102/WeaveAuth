use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::model::session::SessionData;
use crate::server::AppState;
use crate::storage::SessionStorage;

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
pub(crate) struct LoginQuery {
    redirect_uri: String,
}

#[derive(Serialize)]
struct TokenExchangeRequest<'a> {
    grant_type: &'static str,
    code: &'a str,
    redirect_uri: String,
    code_verifier: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_at: DateTime<Utc>,
}

/// Drives the whole authorization-code + PKCE exchange server-to-server in one
/// request, so the browser only ever talks to bff and never sees backend. This
/// relies on backend's `/oauth/authorize` having no interactive step (anonymous
/// stub); real user authentication requiring a browser-visible step would need
/// this to be revisited (see README TODO ledger).
///
/// The `redirect_uri` a caller passes here (the final browser destination) is
/// sent as-is to backend's `/oauth/authorize`, which allowlist-checks it and
/// refuses to issue a code for anything not listed. bff never navigates the
/// browser there itself during this hop (redirects aren't followed), so
/// there's no open-redirect exposure in sending the real value through.
pub(crate) async fn start_login(
    State(mut state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, StatusCode> {
    let redirect_uri = query.redirect_uri;

    let mut verifier_bytes = [0u8; 32];
    rand::rng().fill(&mut verifier_bytes);
    let code_verifier = b64url(&verifier_bytes);
    let challenge = b64url(&Sha256::digest(code_verifier.as_bytes()));

    let qs = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();

    let authorize_resp = state
        .http_client
        .get(format!("{}/oauth/authorize?{}", state.config.backend_url, qs))
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    if authorize_resp.status() == StatusCode::BAD_REQUEST {
        // backend rejected redirect_uri (not allowlisted) -- a client error, not a
        // backend-connectivity problem.
        return Err(StatusCode::BAD_REQUEST);
    }
    if !authorize_resp.status().is_redirection() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let location = authorize_resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let code = url::Url::parse(location)
        .ok()
        .and_then(|u| u.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.into_owned()))
        .ok_or(StatusCode::BAD_GATEWAY)?;

    let token_req = TokenExchangeRequest {
        grant_type: "authorization_code",
        code: &code,
        redirect_uri: redirect_uri.clone(),
        code_verifier: &code_verifier,
        client_id: None,
        client_secret: None,
    };
    let token_resp = state
        .http_client
        .post(format!("{}/oauth/token", state.config.backend_url))
        .form(&token_req)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    if !token_resp.status().is_success() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let token: TokenResponse = token_resp.json().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

    let session_id = Uuid::new_v4().to_string();
    state
        .sessions
        .save_session(
            session_id.clone(),
            SessionData {
                access_token: token.access_token,
                refresh_token: token.refresh_token,
                expires_at: token.expires_at,
            },
        )
        .await;

    let max_age = (token.expires_at - Utc::now()).num_seconds().max(0);
    let cookie = format!(
        "{}={}; HttpOnly; Path=/; SameSite=Lax; Max-Age={}",
        state.config.session_cookie_name, session_id, max_age
    );

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, redirect_uri), (header::SET_COOKIE, cookie)],
        Body::empty(),
    )
        .into_response())
}
