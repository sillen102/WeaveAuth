//! The login host as the reverse proxy (Caddy in local-prod) presents it: `/oauth2/auth` and
//! `/oauth2/sessions/logout` go to Hydra's public port, everything else to login.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::response::Response;
use axum::routing::any;

#[derive(Clone)]
struct ToHydra {
    client: reqwest::Client,
    hydra_public: String,
}

pub fn router(login: Router, hydra_public: &str) -> Router {
    let state = ToHydra {
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("edge client"),
        hydra_public: hydra_public.to_string(),
    };
    Router::new()
        .route("/oauth2/auth", any(to_hydra))
        .route("/oauth2/sessions/logout", any(to_hydra))
        .with_state(state)
        .fallback_service(login)
}

async fn to_hydra(State(state): State<ToHydra>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let body = to_bytes(body, 1 << 20).await.unwrap_or_default();
    let mut upstream = state
        .client
        .request(parts.method, format!("{}{path}", state.hydra_public))
        .body(body);
    for (name, value) in &parts.headers {
        if name != "host" && name != "content-length" {
            upstream = upstream.header(name, value);
        }
    }
    let upstream = match upstream.send().await {
        Ok(upstream) => upstream,
        Err(error) => {
            return Response::builder()
                .status(502)
                .body(Body::from(error.to_string()))
                .expect("response");
        }
    };
    let mut response = Response::builder().status(upstream.status());
    for (name, value) in upstream.headers() {
        if name != "transfer-encoding" && name != "connection" {
            response = response.header(name, value);
        }
    }
    let bytes = upstream.bytes().await.unwrap_or_default();
    response.body(Body::from(bytes)).expect("response")
}
