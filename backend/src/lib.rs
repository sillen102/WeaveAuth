use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;

mod config;

pub use config::Config;

pub fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/oauth/login", get(oauth_login))
        .layer(TraceLayer::new_for_http())
}

async fn health() -> &'static str {
    "ok"
}

async fn oauth_login() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "authenticated": true }))
}
