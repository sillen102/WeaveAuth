use crate::server::AppState;
use crate::server::api::{
    authorize::authorize, authorize::authorize_doc, health::health, jwks::jwks, jwks::jwks_doc,
    login::login, login::login_doc, oidc::oidc_callback, oidc::oidc_callback_doc,
    oidc::oidc_confirm_link, oidc::oidc_confirm_link_doc, oidc::oidc_login, oidc::oidc_login_doc,
    register::register, register::register_doc, token::issue_token, token::issue_token_doc,
};
use aide::axum::ApiRouter;
use aide::axum::routing::{get_with, post_with};
use axum::Router;
use axum::routing::get;
use common::docs::api_docs::api_docs_router;
use tower_http::trace::TraceLayer;

pub(crate) fn router(state: AppState) -> Router {
    let oauth_routes = oauth_routes();
    let (documented_routes, docs) = api_docs_router("WeaveAuth Backend", oauth_routes);

    Router::new()
        .route("/health", get(health))
        .merge(documented_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
        .merge(docs)
}

fn oauth_routes() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route("/oauth/login", post_with(login, login_doc))
        .api_route("/oauth/authorize", get_with(authorize, authorize_doc))
        .api_route("/oauth/token", post_with(issue_token, issue_token_doc))
        .api_route("/register", post_with(register, register_doc))
        .api_route("/.well-known/jwks.json", get_with(jwks, jwks_doc))
        .api_route(
            "/oauth/oidc/{provider}/login",
            get_with(oidc_login, oidc_login_doc),
        )
        .api_route(
            "/oauth/oidc/{provider}/callback",
            get_with(oidc_callback, oidc_callback_doc),
        )
        .api_route(
            "/oauth/oidc/confirm-link",
            post_with(oidc_confirm_link, oidc_confirm_link_doc),
        )
}
