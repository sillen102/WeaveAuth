use crate::server::api::{health::health, login::start_login, proxy::proxy, register::start_register};
use crate::server::AppState;
use axum::routing::{get, post};
use axum::Router;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::trace::TraceLayer;

pub(crate) fn router(state: AppState) -> Router {
    // Per-IP rate limiting via `tower_governor` (a GCRA/leaky-bucket limiter
    // built on `governor`) -- allows a burst of `max_attempts`, then
    // replenishes one attempt every `window_secs / max_attempts` seconds,
    // approximating "max_attempts per window_secs" without a fixed-window
    // reset spike. Two independent buckets per client IP: one shared by the
    // auth endpoints (/login, /register), one shared by every proxied route
    // -- so a flood against one side can't burn the other's budget. /health
    // is exempt (cheap liveness check, commonly polled by infra that
    // shouldn't get caught in either bucket).
    let per_second =
        (state.config.rate_limit_window_secs / state.config.rate_limit_max_attempts as u64).max(1);
    let build_governor = || {
        std::sync::Arc::new(
            GovernorConfigBuilder::default()
                .burst_size(state.config.rate_limit_max_attempts)
                .per_second(per_second)
                .finish()
                .expect("valid governor rate-limit config"),
        )
    };

    let auth_routes = Router::new()
        .route("/login", post(start_login))
        .route("/register", post(start_register))
        .layer(GovernorLayer::new(build_governor()));

    let proxy_routes = Router::new()
        .fallback(proxy)
        .layer(GovernorLayer::new(build_governor()));

    Router::new()
        .route("/health", get(health))
        .merge(auth_routes)
        .merge(proxy_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
