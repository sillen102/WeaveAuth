//! The deployer's side: the webhooks hooks calls and the upstream service bff proxies to.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

pub struct Stubs {
    registrations: Mutex<Vec<Value>>,
    verifications: Mutex<Vec<Value>>,
    kratos_admin: String,
    http: reqwest::Client,
}

impl Stubs {
    /// `kratos_admin` is where the verification webhook looks the identity up, to record
    /// whether its address was already verified when it was called.
    pub fn new(kratos_admin: String) -> Self {
        Self {
            registrations: Mutex::default(),
            verifications: Mutex::default(),
            kratos_admin,
            http: reqwest::Client::new(),
        }
    }

    /// Every `{user_id, email, fields}` the registration webhook received.
    pub fn registrations(&self) -> Vec<Value> {
        self.registrations.lock().expect("stubs").clone()
    }

    /// Every `{user_id, email}` the verification webhook received, plus `verified_at_call`:
    /// whether Kratos already held that address as verified when the webhook was called.
    pub fn verifications(&self) -> Vec<Value> {
        self.verifications.lock().expect("stubs").clone()
    }
}

pub fn router(stubs: Arc<Stubs>) -> Router {
    Router::new()
        .route("/claims", post(claims))
        .route("/registration", post(registration))
        .route("/verification", post(verification))
        .route("/upstream/whoami", get(whoami))
        .with_state(stubs)
}

/// `roles` from the email: everyone is a `member`, `admin-*` addresses also `admin`. A
/// misbehaving handler (`evil-*`) tries to set the token's audience.
async fn claims(Json(request): Json<Value>) -> Json<Value> {
    let email = request["email"].as_str().unwrap_or_default();
    if email.starts_with("evil-") {
        return Json(json!({"aud": ["somewhere-else"]}));
    }
    let admin = email.starts_with("admin-");
    let roles = if admin {
        json!(["member", "admin"])
    } else {
        json!(["member"])
    };
    Json(json!({"roles": roles}))
}

async fn registration(State(stubs): State<Arc<Stubs>>, Json(request): Json<Value>) -> StatusCode {
    stubs.registrations.lock().expect("stubs").push(request);
    StatusCode::NO_CONTENT
}

async fn verification(
    State(stubs): State<Arc<Stubs>>,
    Json(mut request): Json<Value>,
) -> StatusCode {
    let url = format!(
        "{}/admin/identities/{}",
        stubs.kratos_admin,
        request["user_id"].as_str().unwrap_or_default()
    );
    let identity = match stubs
        .http
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
    {
        Ok(response) => response.json::<Value>().await.ok(),
        Err(_) => None,
    };
    request["verified_at_call"] = match identity {
        Some(identity) => json!(
            identity["verifiable_addresses"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|a| a["value"] == request["email"] && a["verified"] == true)
        ),
        None => json!("kratos lookup failed"),
    };
    stubs.verifications.lock().expect("stubs").push(request);
    StatusCode::NO_CONTENT
}

/// Echoes what bff forwarded: the bearer token, and whether any cookie leaked through.
async fn whoami(headers: HeaderMap) -> Json<Value> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    Json(json!({
        "authorization": header("authorization"),
        "cookie": headers.contains_key("cookie"),
    }))
}
