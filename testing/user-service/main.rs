// Standalone test double: POST /users saves the request body in memory under
// a generated id and returns it. Requires an Authorization header (401 without
// one) so it can double as a downstream API behind the bff's proxy.
//
// Run: cargo run
// Port: $PORT, default 10002.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::Json;
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use serde_json::Value;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(10002);

    let app = Router::new().route("/users", post(save_user));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap();
    println!("user-service listening on :{port}");
    axum::serve(listener, app).await.unwrap();
}

async fn save_user(
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    if !headers.contains_key(header::AUTHORIZATION) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    body.as_object_mut()
        .ok_or(StatusCode::BAD_REQUEST)?
        .insert("id".to_string(), id.into());

    Ok((StatusCode::CREATED, Json(body)))
}
