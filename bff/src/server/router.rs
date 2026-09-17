use crate::server::api::{
    health::health, login::start_login, oidc::oidc_callback, oidc::oidc_confirm_link,
    oidc::start_oidc_login, proxy::proxy_router,
    register::{start_register, start_register_doc},
};
use crate::server::AppState;
use aide::axum::routing::post_with;
use aide::axum::ApiRouter;
use axum::routing::{get, post};
use axum::Router;
use common::docs::api_docs::api_docs_router;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::trace::TraceLayer;

pub(crate) fn router(state: AppState) -> anyhow::Result<Router> {
    // Per-IP rate limiting via `tower_governor` (a GCRA/leaky-bucket limiter
    // built on `governor`) -- allows a burst of `max_attempts`, then
    // replenishes one attempt every `window_secs / max_attempts` seconds,
    // approximating "max_attempts per window_secs" without a fixed-window
    // reset spike. Two independent buckets per client IP: one shared by every
    // route under `auth_routes` below (including the documented `/register`
    // route, pulled into its own `ApiRouter` for OpenAPI docs but sharing the
    // same governor instance so it doesn't get its own separate budget), one
    // shared by every proxied route -- so a flood against one side can't burn
    // the other's budget. /health is exempt (cheap liveness check, commonly
    // polled by infra that shouldn't get caught in either bucket).
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

    let auth_governor = build_governor()?;

    let auth_routes = Router::new()
        .route("/login", post(start_login))
        .route("/oidc/{provider}/login", get(start_oidc_login))
        .route("/oidc/{provider}/callback", get(oidc_callback))
        .route("/oidc/confirm-link", post(oidc_confirm_link))
        .layer(GovernorLayer::new(auth_governor.clone()))
        .with_state(state.clone());

    // `/register` gets OpenAPI docs (see `register.rs`'s `start_register_doc`
    // and `bff/AGENTS.md`) -- a plain `Router` can't carry aide's operation
    // metadata, so it's built as its own `ApiRouter` and run through the same
    // `api_docs_router` helper `backend` uses, rather than living in
    // `auth_routes` above.
    let register_routes = ApiRouter::new().api_route("/register", post_with(start_register, start_register_doc));
    let (documented_register_routes, docs) = api_docs_router("WeaveAuth BFF", register_routes);
    let documented_register_routes = documented_register_routes
        .layer(GovernorLayer::new(auth_governor))
        .with_state(state.clone());

    // Read before `state` is moved into `proxy_router` below.
    let docs_enabled = state.config.docs_enabled;

    let proxy_governor = build_governor()?;
    // Its own (third) bucket, not `auth_governor`'s: `/docs`/`/openapi.json`
    // are cheap, read-only, and legitimately fetched repeatedly by tooling,
    // so counting them against the same budget as login/register attempts
    // would let doc traffic starve real auth attempts (or vice versa). Still
    // metered, though -- publishing a schema is fine, leaving it as a free
    // unauthenticated, unlimited endpoint on the internet-facing side isn't.
    let docs_governor = build_governor()?;
    let docs = docs.layer(GovernorLayer::new(docs_governor));

    let proxy_routes = proxy_router(state).layer(GovernorLayer::new(proxy_governor));

    let mut app = Router::new()
        .route("/health", get(health))
        .merge(auth_routes)
        .merge(documented_register_routes)
        .merge(proxy_routes);

    // The `/register` route stays documented either way -- only the endpoints
    // that publish the schema are gated, so toggling this never changes how
    // the API itself behaves.
    if docs_enabled {
        app = app.merge(docs);
    }

    Ok(app.layer(TraceLayer::new_for_http()))
}
