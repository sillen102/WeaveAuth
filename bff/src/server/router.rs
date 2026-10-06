use crate::server::AppState;
use crate::server::api::{
    health::health,
    login::start_login,
    oidc::oidc_callback,
    oidc::oidc_confirm_link,
    oidc::oidc_providers,
    oidc::start_oidc_login,
    password_reset::{confirm_password_reset, request_password_reset},
    proxy::{proxy_cors, proxy_router},
    register::{start_register, start_register_doc},
    verify_email::{resend_verification, verify_email},
};
use aide::axum::ApiRouter;
use aide::axum::routing::post_with;
use axum::Router;
use axum::routing::{get, post};
use common::docs::api_docs::api_docs_router;
use tower_governor::GovernorLayer;
use tower_http::trace::TraceLayer;

pub(crate) fn router(state: AppState) -> Router {
    // Per-client rate limiting (`tower_governor`; see `RateLimits` for the
    // buckets and their sizing). /health is exempt: a cheap liveness check
    // infra polls, which shouldn't get caught in any bucket.
    let limits = state.rate_limits.clone();

    let auth_routes = Router::new()
        .route("/login", post(start_login))
        .route("/oidc/providers", get(oidc_providers))
        .route("/oidc/{provider}/login", get(start_oidc_login))
        .route("/oidc/{provider}/callback", get(oidc_callback))
        .route("/oidc/confirm-link", post(oidc_confirm_link))
        .route("/verify-email", post(verify_email))
        .route("/verify-email/resend", post(resend_verification))
        .route("/password-reset/request", post(request_password_reset))
        .route("/password-reset/confirm", post(confirm_password_reset))
        .layer(GovernorLayer::new(limits.auth.clone()))
        .with_state(state.clone());

    // `/register` gets OpenAPI docs (see `register.rs`'s `start_register_doc`
    // and `bff/AGENTS.md`) -- a plain `Router` can't carry aide's operation
    // metadata, so it's built as its own `ApiRouter` and run through the same
    // `api_docs_router` helper `backend` uses, rather than living in
    // `auth_routes` above.
    let register_routes =
        ApiRouter::new().api_route("/register", post_with(start_register, start_register_doc));
    let (documented_register_routes, docs) = api_docs_router("WeaveAuth BFF", register_routes);
    let documented_register_routes = documented_register_routes
        // The auth bucket, not one of its own: a documented route gets no extra budget.
        .layer(GovernorLayer::new(limits.auth))
        .with_state(state.clone());

    // Read before `state` is moved into `proxy_router` below.
    let docs_enabled = state.config.docs_enabled;

    let docs = docs.layer(GovernorLayer::new(limits.docs));

    let cors = proxy_cors(state.proxy_trusted_origins.clone());
    // CORS above the governor: a 429 stays readable cross-origin, but every `OPTIONS`
    // is answered by CORS before the session check, the governor and the upstream.
    let proxy_routes = proxy_router(state)
        .layer(GovernorLayer::new(limits.proxy))
        .layer(cors);

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

    app.layer(TraceLayer::new_for_http())
}
