use crate::server::AppState;
use crate::server::api::{
    after_password_change::after_password_change, after_recovery::after_recovery,
    after_registration::after_registration, health::health, token_hook::token_hook,
};
use crate::server::auth::require_api_key;
use axum::Router;
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub(crate) fn router(state: AppState) -> Router {
    let hooks = Router::new()
        .route("/hydra/token-hook", post(token_hook))
        .route("/kratos/after-registration", post(after_registration))
        .route("/kratos/after-recovery", post(after_recovery))
        .route("/kratos/after-password-change", post(after_password_change))
        .route_layer(from_fn_with_state(state.clone(), require_api_key));

    Router::new()
        .route("/health", get(health))
        .merge(hooks)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            state.request_timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
