use crate::server::api::{
    authorize::auth_authorize, authorize::auth_authorize_doc, health::health, login::login,
    login::login_doc, register::register, register::register_doc, token::issue_token,
    token::issue_token_doc,
};
use crate::server::AppState;
use aide::axum::routing::{get_with, post_with};
use aide::axum::ApiRouter;
use axum::routing::get;
use axum::Router;
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
        .api_route(
            "/oauth/authorize",
            get_with(auth_authorize, auth_authorize_doc),
        )
        .api_route("/oauth/token", post_with(issue_token, issue_token_doc))
        .api_route("/register", post_with(register, register_doc))
}
