use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_http::services::ServeDir;

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub login_url: String,
    pub backend_url: String,
    pub default_redirect_uri: String,
}

impl Config {
    pub fn load() -> Self {
        let port = env::var("WA_LOGIN_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);
        let login_url =
            env::var("WA_LOGIN_URL").unwrap_or_else(|_| "http://localhost:8080".into());
        let backend_url =
            env::var("WA_BACKEND_URL").unwrap_or_else(|_| "http://localhost:1983".into());
        let default_redirect_uri = env::var("WA_DEFAULT_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:1984".into());
        Self {
            port,
            login_url,
            backend_url,
            default_redirect_uri,
        }
    }
}

#[derive(Clone)]
pub struct PendingAuth {
    pub code_verifier: String,
    pub redirect_uri: String,
}

#[derive(Clone)]
pub struct AuthState {
    pub config: Config,
    pub pending: Arc<Mutex<HashMap<String, PendingAuth>>>,
}

impl AuthState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub fn app(config: Config) -> Router {
    app_with_state(AuthState::new(config))
}

pub fn app_with_state(state: AuthState) -> Router {
    let files = ServeDir::new(STATIC_DIR);
    Router::new()
        .route("/login", get(start_login))
        .route("/callback", get(handle_callback))
        .nest_service("/static", files.clone())
        .fallback_service(files)
        .with_state(state)
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
struct LoginQuery {
    #[serde(default)]
    redirect_uri: Option<String>,
}

async fn start_login(
    State(state): State<AuthState>,
    Query(query): Query<LoginQuery>,
) -> Result<axum::response::Redirect, StatusCode> {
    // TODO: validate redirect_uri against an allowlist (see README TODO ledger).
    let redirect_uri = query
        .redirect_uri
        .unwrap_or_else(|| state.config.default_redirect_uri.clone());

    let mut verifier_bytes = [0u8; 32];
    rand::rng().fill(&mut verifier_bytes);
    let code_verifier = b64url(&verifier_bytes);

    let mut state_bytes = [0u8; 32];
    rand::rng().fill(&mut state_bytes);
    let state_param = b64url(&state_bytes);

    let challenge = b64url(&Sha256::digest(code_verifier.as_bytes()));

    state.pending.lock().unwrap().insert(
        state_param.clone(),
        PendingAuth {
            code_verifier,
            redirect_uri: redirect_uri.clone(),
        },
    );

    let qs = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("redirect_uri",
            &format!("{}/callback", state.config.login_url),
        )
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state_param)
        .finish();

    let location = format!("{}/oauth/authorize?{}", state.config.backend_url, qs);
    Ok(axum::response::Redirect::to(&location))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

#[derive(Serialize)]
struct TokenRequest<'a> {
    grant_type: &'static str,
    code: &'a str,
    redirect_uri: String,
    code_verifier: &'a str,
}

async fn handle_callback(
    State(state): State<AuthState>,
    Query(query): Query<CallbackQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Json<serde_json::Value>)> {
    let code = query.code.ok_or_else(bad_request)?;
    let state_param = query.state.ok_or_else(bad_request)?;

    // TODO: mark state consumed before the exchange so a replayed state/code
    // pair fails (see README TODO ledger).
    let pending = state
        .pending
        .lock()
        .unwrap()
        .remove(&state_param)
        .ok_or_else(bad_request)?;

    let callback_url = format!("{}/callback", state.config.login_url);
    let token_req = TokenRequest {
        grant_type: "authorization_code",
        code: &code,
        redirect_uri: callback_url.clone(),
        code_verifier: &pending.code_verifier,
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/oauth/token", state.config.backend_url))
        .form(&token_req)
        .send()
        .await
        .map_err(|_| bad_request())?;
    let body: serde_json::Value = resp.json().await.map_err(|_| bad_request())?;

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(bad_request)?;

    // TODO: deliver the token via HttpOnly cookie or fragment, not a query
    // string (leaks into history, logs, Referer) — see README TODO ledger.
    let location = format!("{}?access_token={}", pending.redirect_uri, access_token);
    Ok(axum::response::Redirect::to(&location))
}

fn bad_request() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": "invalid_request" })),
    )
}