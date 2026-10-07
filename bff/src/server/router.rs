use crate::server::AppState;
use crate::server::api::{
    backchannel_logout::backchannel_logout,
    callback::callback,
    health::health,
    internal_revoke::revoke,
    logged_out::logged_out,
    login::start_login,
    logout::logout,
    proxy::{proxy_cors, proxy_router},
};
use axum::Router;
use axum::http::{HeaderValue, Request, header};
use axum::routing::{get, post};
use tower_governor::GovernorLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

/// The routes the internet reaches: the login flow and the proxy.
pub(crate) fn public_router(state: AppState) -> Router {
    // Per-client rate limiting (`tower_governor`; see `RateLimits` for the
    // buckets and their sizing). /health is exempt: a cheap liveness check
    // infra polls, which shouldn't get caught in any bucket.
    let limits = state.rate_limits.clone();

    let auth_routes = Router::new()
        .route("/login", get(start_login))
        .route("/callback", get(callback))
        .route("/logout", post(logout))
        .route("/logged-out", get(logged_out))
        .layer(GovernorLayer::new(limits.auth))
        .with_state(state.clone());

    let cors = proxy_cors(state.trusted_origins.clone());
    // CORS above the governor: a 429 stays readable cross-origin, but every `OPTIONS`
    // is answered by CORS before the session check, the governor and the upstream.
    let proxy_routes = proxy_router(state)
        .layer(GovernorLayer::new(limits.proxy))
        .layer(cors);

    Router::new()
        .route("/health", get(health))
        .merge(auth_routes)
        .merge(proxy_routes)
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
}

/// The routes only Hydra and hooks may reach, on a listener that is never routed publicly.
/// No rate limit: the callers are services, authorized by a signed token or the API key.
pub(crate) fn internal_router(state: AppState) -> Router {
    Router::new()
        .route("/backchannel-logout", post(backchannel_logout))
        .route("/internal/revoke", post(revoke))
        .with_state(state)
        // Back-Channel Logout 1.0 2.8: the response is not to be cached.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
}

/// The span of a request: its method and path, never its query, which carries `/callback`'s
/// authorization `code` and `state`.
fn request_span<B>(request: &Request<B>) -> tracing::Span {
    tracing::debug_span!("request", method = %request.method(), path = request.uri().path())
}

#[cfg(test)]
mod tests {
    use super::request_span;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::format::FmtSpan;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_requests_span_names_its_path_and_never_its_query() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_span_events(FmtSpan::NEW)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let request = axum::http::Request::get("/callback?code=s3cret-code&state=s3cret-state")
            .body(())
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            let _span = request_span(&request).entered();
        });

        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("/callback"), "{logged}");
        assert!(logged.contains("GET"), "{logged}");
        assert!(!logged.contains("s3cret"), "{logged}");
    }
}
