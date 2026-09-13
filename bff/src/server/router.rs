use crate::server::api::{health::health, login::start_login, proxy::proxy_router, register::start_register};
use crate::server::AppState;
use axum::routing::{get, post};
use axum::Router;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::trace::TraceLayer;

pub(crate) fn router(state: AppState) -> anyhow::Result<Router> {
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
        let config = GovernorConfigBuilder::default()
            .burst_size(state.config.rate_limit_max_attempts.max(1))
            .per_second(per_second)
            .finish()
            .ok_or_else(|| anyhow::anyhow!("invalid governor rate-limit config"))?;
        Ok::<_, anyhow::Error>(std::sync::Arc::new(config))
    };

    let auth_routes = Router::new()
        .route("/login", post(start_login))
        .route("/register", post(start_register))
        .layer(GovernorLayer::new(build_governor()?))
        .with_state(state.clone());

    let proxy_governor = build_governor()?;
    let proxy_routes = proxy_router(state).layer(GovernorLayer::new(proxy_governor));

    Ok(Router::new()
        .route("/health", get(health))
        .merge(auth_routes)
        .merge(proxy_routes)
        .layer(TraceLayer::new_for_http()))
}
