// Standalone test double for the deployer's user store, and the webhook target of weaveauth-hooks
// (see hooks/config.yaml). Users are kept in memory and written to $USERS_FILE (default
// users.json) so a restart keeps them; every route needs an Authorization header (401 without).
//
// POST /users         registration webhook `{user_id, email, email_verified, fields}`: stores `fields`
//                     (first_name, last_name, phone_number) under `user_id`. Any other JSON object is
//                     stored under a generated id. Answers 201 with the body and its `id`.
// POST /users/claims  login-claims webhook `{user_id, ...}`: answers the stored `fields` as token
//                     claims, 404 for a user it does not know (hooks then fails the login).
//
// Run: cargo run
// Port: $PORT, default 10002.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::extract::Json;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::post;
use serde_json::Value;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static USERS: Mutex<Option<HashMap<String, Value>>> = Mutex::new(None);

fn users_file() -> String {
    std::env::var("USERS_FILE").unwrap_or_else(|_| "users.json".into())
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(10002);

    let saved: Option<HashMap<String, Value>> = std::fs::read(users_file())
        .ok()
        .map(|bytes| serde_json::from_slice(&bytes).expect("users file is not valid JSON"));
    // Past ids are kept, so continue after the highest numeric one.
    let max_id = saved
        .iter()
        .flat_map(|users| users.keys().filter_map(|k| k.parse::<u64>().ok()))
        .max()
        .unwrap_or(0);
    NEXT_ID.store(max_id + 1, Ordering::SeqCst);
    *USERS.lock().unwrap() = saved;

    let app = Router::new()
        .route("/users", post(save_user))
        .route("/users/claims", post(claims));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap();
    println!("user-service listening on :{port}");
    axum::serve(listener, app).await.unwrap();
}

fn authorized(headers: &HeaderMap) -> Result<(), StatusCode> {
    headers
        .contains_key(header::AUTHORIZATION)
        .then_some(())
        .ok_or(StatusCode::UNAUTHORIZED)
}

async fn save_user(
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    authorized(&headers)?;
    let object = body.as_object_mut().ok_or(StatusCode::BAD_REQUEST)?;

    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    object.insert("id".to_string(), id.into());
    let (key, stored) = match (
        object.get("user_id").and_then(Value::as_str),
        object.get("fields"),
    ) {
        (Some(user_id), Some(fields)) => (user_id.to_string(), fields.clone()),
        _ => (id.to_string(), body.clone()),
    };
    let mut users = USERS.lock().unwrap();
    let users = users.get_or_insert_default();
    users.insert(key, stored);
    if let Err(e) = std::fs::write(users_file(), serde_json::to_vec_pretty(users).unwrap()) {
        eprintln!("{}: {e}", users_file());
    }

    Ok((StatusCode::CREATED, Json(body)))
}

async fn claims(headers: HeaderMap, Json(body): Json<Value>) -> Result<Json<Value>, StatusCode> {
    authorized(&headers)?;
    let user = body["user_id"]
        .as_str()
        .and_then(|id| USERS.lock().unwrap().as_ref()?.get(id).cloned());
    user.map(Json).ok_or(StatusCode::NOT_FOUND)
}
