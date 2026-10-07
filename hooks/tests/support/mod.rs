//! In-process stand-ins for Kratos admin, Hydra admin, bff's internal
//! listener and the deployer's webhooks: axum servers on `127.0.0.1:0` that
//! record every call into one shared log, so a test can assert what was called
//! and in which order across services.

#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use weaveauth_hooks::config::{Config, ProfileApiConfig, WebhookConfig};

pub const HOOKS_KEY: &str = "hooks-key-for-tests";
pub const BFF_KEY: &str = "bff-key-for-tests";

#[derive(Debug, Clone)]
pub struct Call {
    pub service: &'static str,
    pub method: String,
    /// Path and query.
    pub uri: String,
    pub authorization: Option<String>,
    pub body: Value,
}

impl Call {
    pub fn path(&self) -> &str {
        self.uri.split('?').next().unwrap_or_default()
    }
}

#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<Call>>>);

impl Log {
    pub fn calls(&self) -> Vec<Call> {
        self.0.lock().unwrap().clone()
    }

    /// `"service METHOD uri"` per call, in order.
    pub fn lines(&self) -> Vec<String> {
        self.calls()
            .iter()
            .map(|call| format!("{} {} {}", call.service, call.method, call.uri))
            .collect()
    }

    pub fn of(&self, service: &str) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|call| call.service == service)
            .collect()
    }
}

pub type Responder = Arc<dyn Fn(&Call) -> (u16, Value) + Send + Sync>;

#[derive(Clone)]
struct StubState {
    service: &'static str,
    log: Log,
    responder: Responder,
}

pub struct Stub {
    pub url: String,
}

impl Stub {
    pub async fn start(
        service: &'static str,
        log: &Log,
        responder: impl Fn(&Call) -> (u16, Value) + Send + Sync + 'static,
    ) -> Self {
        let state = StubState {
            service,
            log: log.clone(),
            responder: Arc::new(responder),
        };
        let app = Router::new().fallback(record).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url }
    }
}

async fn record(State(state): State<StubState>, request: Request<Body>) -> impl IntoResponse {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let call = Call {
        service: state.service,
        method: parts.method.to_string(),
        uri: parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_default(),
        authorization: parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    };
    state.log.0.lock().unwrap().push(call.clone());
    let (status, body) = (state.responder)(&call);
    let status = StatusCode::from_u16(status).unwrap();
    if body.is_null() {
        status.into_response()
    } else {
        (status, axum::Json(body)).into_response()
    }
}

/// Answers 204 to every call.
pub fn no_content(_: &Call) -> (u16, Value) {
    (204, Value::Null)
}

/// A server that accepts connections and never answers.
pub async fn hanging_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    url
}

pub fn identity_json(id: &str, email: &str, verified: bool) -> Value {
    json!({
        "id": id,
        "schema_id": "default",
        "state": "active",
        "traits": {"email": email, "first_name": "Alice", "last_name": "Test", "phone_number": "+46701234567"},
        "verifiable_addresses": [{"value": email, "verified": verified}],
        "credentials": {"password": {"type": "password"}},
    })
}

pub struct Harness {
    pub log: Log,
    pub config: Config,
    pub kratos: Stub,
    pub hydra: Stub,
    pub bff: Stub,
}

impl Harness {
    /// Stubs that accept everything and a config pointing at them.
    pub async fn new() -> Self {
        Self::with(
            |call: &Call| {
                // Kratos: identities by id are found, lists are empty.
                if call.method == "GET" && call.path().ends_with("/sessions") {
                    (200, json!([]))
                } else if call.method == "GET" {
                    let id = call.path().rsplit('/').next().unwrap_or_default();
                    (200, identity_json(id, "alice@example.com", true))
                } else if call.method == "PUT" {
                    (200, json!({}))
                } else {
                    (204, Value::Null)
                }
            },
            no_content,
            no_content,
        )
        .await
    }

    pub async fn with(
        kratos: impl Fn(&Call) -> (u16, Value) + Send + Sync + 'static,
        hydra: impl Fn(&Call) -> (u16, Value) + Send + Sync + 'static,
        bff: impl Fn(&Call) -> (u16, Value) + Send + Sync + 'static,
    ) -> Self {
        let log = Log::default();
        let kratos = Stub::start("kratos", &log, kratos).await;
        let hydra = Stub::start("hydra", &log, hydra).await;
        let bff = Stub::start("bff", &log, bff).await;
        let config = Config {
            hooks_api_key: HOOKS_KEY.to_string().into(),
            bff_internal_api_key: BFF_KEY.to_string().into(),
            kratos_admin_url: kratos.url.clone(),
            hydra_admin_url: hydra.url.clone(),
            bff_internal_url: bff.url.clone(),
            upstream_timeout_secs: 2,
            request_timeout_secs: 5,
            ..Config::default()
        };
        Self {
            log,
            config,
            kratos,
            hydra,
            bff,
        }
    }

    pub async fn webhook(
        &self,
        service: &'static str,
        responder: impl Fn(&Call) -> (u16, Value) + Send + Sync + 'static,
    ) -> WebhookConfig {
        let stub = Stub::start(service, &self.log, responder).await;
        WebhookConfig {
            url: format!("{}/hook", stub.url),
            timeout_secs: 2,
            bearer_token: None,
        }
    }

    pub fn app(&self) -> Router {
        weaveauth_hooks::server::app(&self.config).unwrap()
    }

    /// POST `body` to `path` with the right API key.
    pub async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        send(self.app(), "POST", path, Some(HOOKS_KEY), body).await
    }
}

pub async fn send(
    app: Router,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("authorization", format!("Bearer {key}"));
    }
    let response = app
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub fn profile_api(
    url: String,
    claims: &[(&str, &str)],
    required: bool,
    scope: Option<&str>,
) -> ProfileApiConfig {
    ProfileApiConfig {
        url,
        claims: claims
            .iter()
            .map(|(field, pointer)| (field.to_string(), pointer.to_string()))
            .collect(),
        scope: scope.map(str::to_string),
        required,
    }
}

pub const ID: &str = "11111111-1111-4111-8111-111111111111";
pub const SESSION: &str = "22222222-2222-4222-8222-222222222222";

/// What Hydra posts to the token hook for `subject`.
pub fn token_hook_body(subject: &str) -> Value {
    json!({
        "session": {
            "id_token": {
                "id_token_claims": {"sub": subject, "ext": {}},
                "headers": {"extra": {}},
                "username": "",
                "subject": subject,
            },
            "extra": {},
            "client_id": "bff",
        },
        "request": {
            "client_id": "bff",
            "requested_scopes": ["openid", "offline_access"],
            "granted_scopes": [],
            "granted_audience": [],
            "grant_types": ["authorization_code"],
        },
    })
}
