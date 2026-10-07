//! Stub Kratos and Hydra servers plus request helpers shared by the integration tests.
#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use weaveauth_login::Config;

pub const CSRF: &str = "csrf-token-value";

#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub body: String,
}

impl Seen {
    pub fn cookie(&self) -> Option<&str> {
        self.headers.get("cookie").and_then(|v| v.to_str().ok())
    }
}

/// What the stub answers; every field can be changed by a test while it runs.
pub struct StubState {
    pub seen: Mutex<Vec<Seen>>,
    pub flow: Mutex<(StatusCode, Value)>,
    pub error: Mutex<Value>,
    pub login_post: Mutex<(StatusCode, Option<String>)>,
    /// A `Set-Cookie` the login post answers with, as Kratos does once the credentials check out.
    pub login_post_cookie: Mutex<Option<String>>,
    pub logged_in: Mutex<bool>,
    /// Hydra's answers.
    pub logout_request: Mutex<(StatusCode, Value)>,
    pub accept_logout_status: Mutex<StatusCode>,
    pub consent_request: Mutex<Value>,
}

impl StubState {
    fn new() -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            flow: Mutex::new((StatusCode::OK, login_flow())),
            error: Mutex::new(
                json!({"id": "e1", "error": {"code": 400, "status": "Bad Request", "reason": "The request was malformed", "message": "bad things"}}),
            ),
            login_post: Mutex::new((
                StatusCode::SEE_OTHER,
                Some("http://login.test/login?flow=f2".to_string()),
            )),
            login_post_cookie: Mutex::new(None),
            logged_in: Mutex::new(true),
            logout_request: Mutex::new((
                StatusCode::OK,
                json!({"rp_initiated": true, "subject": "u1"}),
            )),
            accept_logout_status: Mutex::new(StatusCode::OK),
            consent_request: Mutex::new(consent_request("bff", &["openid", "offline_access"])),
        }
    }

    pub fn requests(&self, path_prefix: &str) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.path_and_query.starts_with(path_prefix))
            .cloned()
            .collect()
    }

    pub fn count(&self, method: &str, path_prefix: &str) -> usize {
        self.requests(path_prefix)
            .iter()
            .filter(|seen| seen.method == method)
            .count()
    }

    pub fn all(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|seen| format!("{} {}", seen.method, seen.path_and_query))
            .collect()
    }
}

pub fn consent_request(client_id: &str, scopes: &[&str]) -> Value {
    json!({
        "skip": false,
        "subject": "u1",
        "client": {"client_id": client_id, "audience": ["weaveauth"]},
        "requested_scope": scopes,
        "requested_access_token_audience": ["https://api.test"],
    })
}

/// One server playing both Kratos (public) and Hydra (admin); paths never overlap.
pub async fn stub() -> (String, Arc<StubState>) {
    let state = Arc::new(StubState::new());
    let router = Router::new().fallback(handle).with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), state)
}

async fn handle(State(state): State<Arc<StubState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let path = parts.uri.path().to_string();
    let method = parts.method.to_string();
    state.seen.lock().unwrap().push(Seen {
        method: method.clone(),
        path_and_query: parts.uri.path_and_query().unwrap().to_string(),
        headers: parts.headers.clone(),
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    let set_csrf = || {
        (
            header::SET_COOKIE,
            "csrf_token_abc=xyz; Path=/; HttpOnly; SameSite=Lax",
        )
    };

    match (method.as_str(), path.as_str()) {
        ("GET", p) if p.ends_with("/flows") => {
            let (status, flow) = state.flow.lock().unwrap().clone();
            (status, axum::Json(flow)).into_response()
        }
        ("GET", "/self-service/errors") => (
            StatusCode::OK,
            axum::Json(state.error.lock().unwrap().clone()),
        )
            .into_response(),
        ("GET", "/self-service/logout/browser") => {
            if *state.logged_in.lock().unwrap() {
                axum::Json(json!({"logout_url": "http://login.test/self-service/logout?token=tok", "logout_token": "tok"}))
                    .into_response()
            } else {
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
        ("GET", "/self-service/logout") => (
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, "/"),
                (header::SET_COOKIE, "ory_kratos_session=; Max-Age=0; Path=/"),
            ],
        )
            .into_response(),
        ("GET", p) if p.ends_with("/browser") => (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, "/login?flow=started"), set_csrf()],
            "",
        )
            .into_response(),
        ("POST", "/self-service/login") => {
            let (status, location) = state.login_post.lock().unwrap().clone();
            let mut response = (status, [set_csrf()], "").into_response();
            if let Some(location) = location {
                response
                    .headers_mut()
                    .insert(header::LOCATION, HeaderValue::from_str(&location).unwrap());
            }
            if let Some(cookie) = state.login_post_cookie.lock().unwrap().clone() {
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
            }
            response
        }
        ("GET", "/.well-known/ory/webauthn.js") => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/javascript"),
                (header::CACHE_CONTROL, "public, max-age=60"),
                (
                    header::HeaderName::from_static("x-kratos-secret-header"),
                    "leak",
                ),
            ],
            "/* webauthn */",
        )
            .into_response(),
        ("GET", "/admin/oauth2/auth/requests/logout") => {
            let (status, body) = state.logout_request.lock().unwrap().clone();
            (status, axum::Json(body)).into_response()
        }
        ("PUT", "/admin/oauth2/auth/requests/logout/accept") => {
            let status = *state.accept_logout_status.lock().unwrap();
            (
                status,
                axum::Json(json!({"redirect_to": "http://login.test/oauth2/sessions/logout?logout_verifier=v"})),
            )
                .into_response()
        }
        ("GET", "/admin/oauth2/auth/requests/consent") => {
            axum::Json(state.consent_request.lock().unwrap().clone()).into_response()
        }
        ("PUT", "/admin/oauth2/auth/requests/consent/accept") => {
            axum::Json(json!({"redirect_to": "http://login.test/oauth2/auth?consent_verifier=ok"}))
                .into_response()
        }
        ("PUT", "/admin/oauth2/auth/requests/consent/reject") => axum::Json(
            json!({"redirect_to": "http://login.test/oauth2/auth?consent_verifier=denied"}),
        )
        .into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

pub fn login_flow() -> Value {
    json!({
        "id": "f1",
        "type": "browser",
        "oauth2_login_challenge": "chal-1",
        "ui": {
            "action": "http://login.test/self-service/login?flow=f1",
            "method": "POST",
            "nodes": [
                {"type": "input", "group": "default", "attributes": {"name": "csrf_token", "type": "hidden", "value": CSRF, "required": true, "disabled": false, "node_type": "input"}, "messages": [], "meta": {}},
                {"type": "input", "group": "default", "attributes": {"name": "identifier", "type": "text", "value": "", "required": true, "disabled": false, "autocomplete": "username webauthn", "node_type": "input"}, "messages": [], "meta": {"label": {"id": 1070004, "text": "Email", "type": "info"}}},
                {"type": "input", "group": "password", "attributes": {"name": "password", "type": "password", "required": true, "disabled": false, "autocomplete": "current-password", "node_type": "input"}, "messages": [], "meta": {"label": {"id": 1070001, "text": "Password", "type": "info"}}},
                {"type": "input", "group": "password", "attributes": {"name": "method", "type": "submit", "value": "password", "disabled": false, "node_type": "input"}, "messages": [], "meta": {"label": {"id": 1010001, "text": "Sign in", "type": "info"}}},
                {"type": "input", "group": "oidc", "attributes": {"name": "provider", "type": "submit", "value": "google", "disabled": false, "node_type": "input"}, "messages": [], "meta": {"label": {"id": 1010002, "text": "Sign in with Google", "type": "info"}}},
                {"type": "input", "group": "passkey", "attributes": {"name": "passkey_challenge", "type": "hidden", "value": "{\"publicKey\":{\"challenge\":\"abc\"}}", "disabled": false, "node_type": "input"}, "messages": [], "meta": {}},
                {"type": "input", "group": "passkey", "attributes": {"name": "passkey_login", "type": "hidden", "value": "", "disabled": false, "node_type": "input"}, "messages": [], "meta": {}},
                {"type": "input", "group": "passkey", "attributes": {"name": "passkey_login_trigger", "type": "button", "disabled": false, "onclick": "window.__oryPasskeyLogin()", "onclickTrigger": "oryPasskeyLogin", "node_type": "input"}, "messages": [], "meta": {"label": {"id": 1010008, "text": "Sign in with a passkey", "type": "info"}}},
                {"type": "script", "group": "webauthn", "attributes": {"src": "http://login.test/.well-known/ory/webauthn.js", "async": true, "referrerpolicy": "no-referrer", "crossorigin": "anonymous", "integrity": "sha512-INTEGRITY", "type": "text/javascript", "id": "webauthn_script", "nonce": "kratos-nonce", "node_type": "script"}, "messages": [], "meta": {}}
            ],
            "messages": []
        }
    })
}

pub fn config(kratos_hydra: &str) -> Config {
    Config {
        bff_url: "http://bff.test".into(),
        own_origin: "http://login.test".into(),
        kratos_public_url: kratos_hydra.into(),
        hydra_admin_url: kratos_hydra.into(),
        // Limits no test trips by accident.
        rate_limit_max_attempts: 1000,
        rate_limit_proxy_max_attempts: 1000,
        ..Config::default()
    }
}

pub fn client(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), 4711)
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Reply {
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("no {name} header in {:?}", self.headers))
            .to_str()
            .unwrap()
    }

    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    /// The nonce the CSP header allows scripts with.
    pub fn csp_nonce(&self) -> String {
        let csp = self.header("content-security-policy");
        let start = csp
            .find("'nonce-")
            .unwrap_or_else(|| panic!("no nonce in {csp}"))
            + 7;
        csp[start..].split('\'').next().unwrap().to_string()
    }
}

pub async fn send(app: &Router, req: axum::http::Request<Body>, ip: &str) -> Reply {
    let mut req = req;
    req.extensions_mut().insert(ConnectInfo(client(ip)));
    let response = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

pub async fn get(app: &Router, uri: &str) -> Reply {
    send(
        app,
        axum::http::Request::get(uri).body(Body::empty()).unwrap(),
        "127.0.0.1",
    )
    .await
}

pub async fn get_with_cookie(app: &Router, uri: &str, cookie: &str) -> Reply {
    send(
        app,
        axum::http::Request::get(uri)
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1",
    )
    .await
}

pub async fn post_form(app: &Router, uri: &str, body: &str, ip: &str) -> Reply {
    send(
        app,
        axum::http::Request::post(uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap(),
        ip,
    )
    .await
}
