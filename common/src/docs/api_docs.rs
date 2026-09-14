use aide::axum::ApiRouter;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use scalar_api_reference::{get_asset_with_mime, scalar_html};

const DOCS_PATH: &str = "/docs";
const OPENAPI_PATH: &str = "/openapi.json";

/// Serve the Scalar JS bundle embedded in the binary.
async fn scalar_js() -> impl IntoResponse {
    match get_asset_with_mime("scalar.js") {
        Some((mime_type, content)) => (
            StatusCode::OK,
            [(http::header::CONTENT_TYPE, mime_type)],
            content,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Serve the OpenAPI spec as JSON.
async fn serve_openapi(
    axum::extract::Extension(api): axum::extract::Extension<aide::openapi::OpenApi>,
) -> axum::Json<aide::openapi::OpenApi> {
    axum::Json(api)
}

/// Set up documented API routes and the Scalar docs UI.
///
/// Creates an `OpenApi` spec titled `{title}`, calls `router.finish_api(api)`
/// to populate it, and returns a tuple of `(documented_routes, docs_router)`:
///
/// - `documented_routes` — the `Router<S>` from `finish_api`, for nesting under a path prefix
/// - `docs_router` — a stateless `Router<()>` with `/docs`, `/docs/scalar.js`,
///   and `/openapi.json` endpoints (self-hosted, no CDN)
///
/// Pass one or more `ApiRouter<S>` values — merge additional route groups
/// before passing, e.g. `public_routes.merge(admin_routes)`.
///
/// # Example
///
/// ```rust
/// use aide::axum::routing::{get_with, post_with};
/// use aide::axum::ApiRouter;
/// use aide::transform::TransformOperation;
/// use axum::extract::State;
/// use axum::Router;
/// use common::docs::api_docs::api_docs_router;
///
/// #[derive(Clone)]
/// struct AppState;
///
/// async fn login(State(_state): State<AppState>) {}
/// fn login_doc(op: TransformOperation) -> TransformOperation {
///     op.description("Log in")
/// }
///
/// async fn issue_token(State(_state): State<AppState>) {}
/// fn issue_token_doc(op: TransformOperation) -> TransformOperation {
///     op.description("Issue a token")
/// }
///
/// let state = AppState;
///
/// let routes = ApiRouter::new()
///     .api_route("/oauth/login", get_with(login, login_doc))
///     .api_route("/oauth/token", post_with(issue_token, issue_token_doc));
///
/// let (documented_routes, docs) = api_docs_router("WeaveAuth Backend", routes);
///
/// let _app: Router<()> = Router::new()
///     .nest("/api", documented_routes)
///     .with_state(state)
///     .merge(docs);
/// ```
pub fn api_docs_router<S: Clone + Send + Sync + 'static>(
    title: &str,
    router: ApiRouter<S>,
) -> (Router<S>, Router<()>) {
    let mut api = aide::openapi::OpenApi {
        info: aide::openapi::Info {
            title: title.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ..aide::openapi::Info::default()
        },
        ..aide::openapi::OpenApi::default()
    };

    let documented_routes = router.finish_api_with(&mut api, |api| {
        #[cfg(feature = "auth")]
        {
            api.security_scheme(
                crate::auth::COOKIE_AUTH_SCHEME,
                aide::openapi::SecurityScheme::ApiKey {
                    location: aide::openapi::ApiKeyLocation::Cookie,
                    name: crate::auth::ACCESS_COOKIE_NAME.to_string(),
                    description: Some("Session cookie for authenticated endpoints".to_string()),
                    extensions: Default::default(),
                },
            )
        }
        #[cfg(not(feature = "auth"))]
        {
            api
        }
    });

    let config = serde_json::json!({
        "url": OPENAPI_PATH,
        "pageTitle": format!("{title} API Docs"),
    });
    let js_path = format!("{DOCS_PATH}/scalar.js");
    let html = scalar_html(&config, Some(&js_path));
    let page_title = format!("{title} API Docs");
    let html = html.replace(
        "<title>Scalar API Reference</title>",
        &format!("<title>{page_title}</title>"),
    );

    let docs = Router::new()
        .route(DOCS_PATH, get(move || async move { Html(html) }))
        .route(&js_path, get(scalar_js))
        .route(OPENAPI_PATH, get(serve_openapi))
        .layer(axum::extract::Extension(api));

    (documented_routes, docs)
}
