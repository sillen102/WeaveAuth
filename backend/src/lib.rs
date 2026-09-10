use axum::{routing::get, Router};
use http::HeaderValue;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;

mod config;

pub use config::Config;

pub fn app() -> Router {
    app_with_cors(&[])
}

pub fn app_with_cors(origins: &[String]) -> Router {
    let cors = if origins.is_empty() {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let allowed: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(allowed))
            .allow_methods(Any)
            .allow_headers(Any)
    };

    Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/status", get(auth_status))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}

async fn health() -> &'static str {
    "ok"
}

async fn auth_status() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "authenticated": false }))
}
