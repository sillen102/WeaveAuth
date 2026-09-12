use crate::server::api::{login::start_login, proxy::proxy};
use crate::server::AppState;
use axum::routing::get;
use axum::Router;
use tower_http::trace::TraceLayer;

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/login", get(start_login))
        .fallback(proxy)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
