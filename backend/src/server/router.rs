use crate::server::api::{authorize::auth_authorize, login::login, token::issue_token};
use crate::server::AppState;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/oauth/login", get(login))
        .route("/oauth/authorize", get(auth_authorize))
        .route("/oauth/token", post(issue_token))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState::default())
}
async fn health() -> &'static str {
    "ok"
}