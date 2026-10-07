pub(crate) use controller::{proxy_cors, proxy_router};

mod controller {
    use axum::Router;
    use axum::extract::{Request, State};
    use axum::http::header;
    use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
    use axum::middleware::{self, Next};
    use axum::response::Response;
    use axum_reverse_proxy::{ProxyPolicy, ReverseProxy, XForwardedFor};
    use common_macros::ErrorResponses;
    use percent_encoding::percent_decode_str;
    use secrecy::ExposeSecret;
    use std::sync::Arc;
    use std::time::Duration;
    use thiserror::Error;
    use tower_http::cors::{AllowMethods, AllowOrigin, CorsLayer};

    use crate::server::AppState;
    use crate::server::cookie::extract_cookie;
    use crate::server::origin_check::require_trusted_origin;

    use super::service::{self, ProxyServiceError};

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum ProxyError {
        #[error("path is not proxied")]
        #[error_response(StatusCode::NOT_FOUND, details = "not found")]
        PathNotProxied,
        #[error("missing or invalid session")]
        #[error_response(StatusCode::UNAUTHORIZED, details = "missing or invalid session")]
        Unauthenticated,
        #[error("session refresh failed")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "session refresh failed")]
        RefreshUnavailable,
        #[error("request did not come from a trusted origin")]
        #[error_response(
            StatusCode::FORBIDDEN,
            details = "request did not come from a trusted origin"
        )]
        UntrustedOrigin,
    }

    impl From<ProxyServiceError> for ProxyError {
        fn from(err: ProxyServiceError) -> Self {
            match &err {
                ProxyServiceError::Unauthenticated => {}
                ProxyServiceError::RefreshRefused { .. } => tracing::info!(%err),
                ProxyServiceError::RefreshUnavailable(
                    crate::hydra::HydraError::Misconfigured { .. },
                ) => {
                    tracing::error!(%err, "session refresh failed: hydra refused bff's client credentials");
                }
                ProxyServiceError::RefreshUnavailable(_) => {
                    tracing::warn!(%err, "session refresh failed");
                }
            }
            match err {
                ProxyServiceError::Unauthenticated | ProxyServiceError::RefreshRefused { .. } => {
                    ProxyError::Unauthenticated
                }
                ProxyServiceError::RefreshUnavailable(_) => ProxyError::RefreshUnavailable,
            }
        }
    }

    /// How long an upstream may take to start answering. Short under test so one can be
    /// made to hang.
    const UPSTREAM_TIMEOUT: Duration = if cfg!(test) {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(30)
    };

    /// The largest request body forwarded; a bigger one fails the upstream request.
    const MAX_REQUEST_BODY_BYTES: u64 = 10 * 1024 * 1024;

    /// Client headers an upstream receives, next to bff's `Authorization`.
    /// `Upgrade` stays out until `needs_trusted_origin` also gates WebSocket
    /// handshakes, which are `GET`s.
    const REQUEST_HEADERS: [HeaderName; 7] = [
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::ACCEPT_LANGUAGE,
        header::IF_MATCH,
        header::IF_NONE_MATCH,
        header::IF_MODIFIED_SINCE,
        header::IF_UNMODIFIED_SINCE,
    ];

    /// Upstream headers the browser receives: ones that only shape that one
    /// response, which an upstream needs to keep its content from running on
    /// bff's origin or being cached for someone else. Proxied content shares
    /// bff's origin, so most others (`Set-Cookie`, `Clear-Site-Data`,
    /// `Service-Worker-Allowed`, `Strict-Transport-Security`, `Alt-Svc`) would
    /// act on bff itself, beyond the upstream's `path_prefix`.
    const RESPONSE_HEADERS: [HeaderName; 11] = [
        header::CONTENT_TYPE,
        header::CONTENT_ENCODING,
        header::CONTENT_DISPOSITION,
        header::CONTENT_SECURITY_POLICY,
        header::CACHE_CONTROL,
        header::LOCATION,
        header::VARY,
        header::ETAG,
        header::LAST_MODIFIED,
        header::WWW_AUTHENTICATE,
        header::RETRY_AFTER,
    ];

    /// What a response with no `Content-Security-Policy` of its own gets: proxied content runs
    /// on bff's origin, so an upstream that serves a page must send a CSP to run scripts.
    const DEFAULT_CONTENT_SECURITY_POLICY: &str = "sandbox; frame-ancestors 'none'";

    /// `Cache-Control` directives that settle whether a shared cache may store
    /// a response to an `Authorization` request. Stricter than RFC 9111 §3.5:
    /// `must-revalidate` is left out, as upstreams send it on per-user data to
    /// mean "revalidate when stale".
    const SHARED_CACHE_DIRECTIVES: [&str; 4] = ["public", "s-maxage", "private", "no-store"];

    /// One `axum-reverse-proxy` service per configured route, gated by session auth. A route
    /// is mounted at its prefix by the router, which strips it (the proxy itself gets an
    /// empty path, so it strips nothing more); a `/` route is the router's fallback. bff
    /// decides the headers (see [`authenticate`]), so the proxy crate must not add
    /// forwarding headers of its own.
    pub(crate) fn proxy_router(state: AppState) -> Router {
        let policy = ProxyPolicy::default()
            .with_x_forwarded_for(XForwardedFor::Preserve)
            .with_upstream_timeout(UPSTREAM_TIMEOUT)
            .with_max_request_body_bytes(MAX_REQUEST_BODY_BYTES);
        let mut has_root_route = false;
        let mut routes = Router::new();
        for route in &state.config.routes {
            let upstream = ReverseProxy::new("", &route.upstream_url).with_policy(policy.clone());
            routes = if route.path_prefix == "/" {
                has_root_route = true;
                routes.fallback_service(upstream)
            } else {
                routes.nest_service(&route.path_prefix, upstream)
            };
        }

        let routes = routes.layer(middleware::from_fn_with_state(state, authenticate));
        if has_root_route {
            routes
        } else {
            routes.fallback(StatusCode::NOT_FOUND)
        }
    }

    /// CORS for the proxied routes, for exactly `origins` (see
    /// [`crate::server::origin_check::trusted_origins`]), with credentials. Methods are mirrored from the
    /// preflight; headers are limited to [`REQUEST_HEADERS`], the only ones bff
    /// forwards, so the browser fails a request that bff would strip a header from.
    /// A predicate, so the validated strings need no fallible `HeaderValue` conversion.
    /// `tower-http` answers every `OPTIONS` itself, trusted `Origin` or not.
    pub(crate) fn proxy_cors(origins: Arc<[String]>) -> CorsLayer {
        CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(move |origin, _| {
                origins.iter().any(|o| o.as_bytes() == origin.as_bytes())
            }))
            .allow_credentials(true)
            .allow_methods(AllowMethods::mirror_request())
            .allow_headers(REQUEST_HEADERS)
            .expose_headers([header::CONTENT_DISPOSITION])
            .max_age(Duration::from_secs(600))
    }

    /// A segment of only dots would let a request climb out of the route's `upstream_url`, and an
    /// encoded `/` or `\` would hide one from this check. Servlet containers read `..;x` as
    /// `..`, so path parameters (`;…`) are cut off before comparing, as are trailing dots and
    /// spaces (`...`); a segment is judged decoded and decoded twice, and control characters
    /// (`%00`) are refused.
    fn is_clean_path(path: &str) -> bool {
        !path.split('/').any(|segment| {
            let once = percent_decode_str(segment).decode_utf8_lossy();
            let twice = percent_decode_str(&once).decode_utf8_lossy();
            [once.as_ref(), twice.as_ref()].into_iter().any(|text| {
                let name = text.split(';').next().unwrap_or_default();
                let dots_only =
                    name.starts_with('.') && name.trim_end_matches(['.', ' ']).is_empty();
                dots_only || text.contains(['/', '\\']) || text.chars().any(char::is_control)
            })
        })
    }

    /// A cache in front of bff sees a cookie, not the `Authorization` the upstream
    /// answered, so it would store per-user responses RFC 9111 §3.5 keeps out of
    /// shared caches. No `Cache-Control` becomes `no-store`; one naming none of
    /// [`SHARED_CACHE_DIRECTIVES`] gets `private` added. A field-qualified
    /// `private="…"` doesn't count: it keeps only the named fields out of shared
    /// caches (RFC 9111 §5.2.2.7).
    fn keep_out_of_shared_caches(headers: &mut HeaderMap) {
        if !headers.contains_key(header::CACHE_CONTROL) {
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            return;
        }
        let settled = headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            // ponytail: no quoted strings; `no-cache="a, private, b"` reads as a bare `private`.
            .flat_map(|value| value.split(','))
            .map(|directive| match directive.split_once('=') {
                Some((name, _)) => (name.trim(), true),
                None => (directive.trim(), false),
            })
            .filter(|(name, has_argument)| !(*has_argument && name.eq_ignore_ascii_case("private")))
            .any(|(name, _)| {
                SHARED_CACHE_DIRECTIVES
                    .iter()
                    .any(|known| name.eq_ignore_ascii_case(known))
            });
        if !settled {
            headers.append(header::CACHE_CONTROL, HeaderValue::from_static("private"));
        }
    }

    fn allowed(headers: &HeaderMap, names: &[HeaderName]) -> HeaderMap {
        let mut kept = HeaderMap::new();
        for name in names {
            for value in headers.get_all(name) {
                kept.append(name.clone(), value.clone());
            }
        }
        kept
    }

    /// The browser attaches the session cookie to any same-site request, and
    /// bff turns it into a bearer token upstreams trust. So a non-safe method
    /// must come from a trusted origin, as `/login` must. `OPTIONS` never gets
    /// here while the CORS layer answers it first; it stays safe in case that changes.
    fn needs_trusted_origin(method: &Method) -> bool {
        !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
    }

    /// Guards the proxy: refuses a path that climbs, requires a trusted origin for anything
    /// that can change state, sends the upstream [`REQUEST_HEADERS`] plus `Authorization:
    /// Bearer <token>`, and passes only [`RESPONSE_HEADERS`] back, always with
    /// `X-Content-Type-Options: nosniff`, a CSP and the caching rules of
    /// [`keep_out_of_shared_caches`].
    async fn authenticate(
        State(mut state): State<AppState>,
        mut req: Request,
        next: Next,
    ) -> Result<Response, ProxyError> {
        if !is_clean_path(req.uri().path()) {
            return Err(ProxyError::PathNotProxied);
        }
        if needs_trusted_origin(req.method()) {
            require_trusted_origin(req.headers(), &state.trusted_origins).map_err(|error| {
                tracing::warn!(%error, "proxied request rejected");
                ProxyError::UntrustedOrigin
            })?;
        }
        let session_id = extract_cookie(req.headers(), &state.config.session_cookie())
            .ok_or(ProxyError::Unauthenticated)?;
        let access_token = service::resolve_bearer_token(&mut state, &session_id).await?;

        let auth_value = format!("Bearer {}", access_token.expose_secret())
            .parse()
            .map_err(|error| {
                tracing::warn!(%error, "session access token is not a valid header value");
                ProxyError::Unauthenticated
            })?;
        let mut upstream = allowed(req.headers(), &REQUEST_HEADERS);
        upstream.insert(header::AUTHORIZATION, auth_value);
        *req.headers_mut() = upstream;

        let mut response = next.run(req).await;
        let headers = response.headers_mut();
        *headers = allowed(headers, &RESPONSE_HEADERS);
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(DEFAULT_CONTENT_SECURITY_POLICY),
            );
        }
        keep_out_of_shared_caches(headers);
        Ok(response)
    }
}

mod service {
    use crate::hydra::HydraError;
    use crate::model::session::SessionData;
    use crate::server::AppState;
    use crate::storage::SessionStorage;
    use chrono::Utc;
    use secrecy::{ExposeSecret, SecretString};
    use thiserror::Error;

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum ProxyServiceError {
        #[error("missing or invalid session")]
        Unauthenticated,
        /// Hydra refused the session's refresh token: it is dead and the session is dropped.
        #[error("refresh token refused by {endpoint} with {status}, session ended")]
        RefreshRefused { endpoint: &'static str, status: u16 },
        #[error("session refresh failed: {0}")]
        RefreshUnavailable(#[from] HydraError),
    }

    /// Treat an access token as due for refresh this far before it actually
    /// expires. Without this, a token valid at the "is it expired" check
    /// could still expire in the time it takes to reach the upstream,
    /// turning an otherwise-successful proxied request into a spurious auth
    /// failure there instead of here.
    const ACCESS_TOKEN_REFRESH_LEEWAY: chrono::Duration = chrono::Duration::seconds(5);

    /// Resolves the given session cookie value into an access token to
    /// forward upstream, transparently refreshing it first if it has expired
    /// (or is about to) but the session's refresh token hasn't.
    pub(crate) async fn resolve_bearer_token(
        state: &mut AppState,
        session_id: &str,
    ) -> Result<SecretString, ProxyServiceError> {
        let session = state
            .sessions
            .get_session(session_id)
            .await
            .ok_or(ProxyServiceError::Unauthenticated)?;
        if session.ends_at() <= Utc::now() {
            return Err(ProxyServiceError::Unauthenticated);
        }
        if is_fresh(&session) {
            return Ok(session.access_token);
        }

        // One refresh per session at a time: Hydra rotates the refresh token, and presenting a
        // rotated one again revokes the whole chain. The guard drops on every way out of here,
        // a failed or cancelled refresh included.
        let _turn = state.refresh_locks.acquire(session_id).await;
        // Whoever held the turn before may have refreshed already (or logged the user out).
        let session = state
            .sessions
            .get_session(session_id)
            .await
            .ok_or(ProxyServiceError::Unauthenticated)?;
        if is_fresh(&session) {
            return Ok(session.access_token);
        }
        Ok(refresh_session(state, session_id, session)
            .await?
            .access_token)
    }

    fn is_fresh(session: &SessionData) -> bool {
        session.expires_at > Utc::now() + ACCESS_TOKEN_REFRESH_LEEWAY
    }

    /// Redeems the session's refresh token at Hydra for a fresh token pair and persists it
    /// under the same `session_id` (Hydra rotates the refresh token on every use, so the old
    /// one stops working the moment this succeeds). Hydra refusing the refresh token
    /// (`invalid_grant`, `token_inactive`, `access_denied`) means it is dead, so the session is
    /// dropped and `Unauthenticated`; a network error, `5xx`, rejected client credentials or
    /// unparseable body say nothing about the session and are `RefreshUnavailable`, with the
    /// session kept for the next try.
    async fn refresh_session(
        state: &mut AppState,
        session_id: &str,
        session: SessionData,
    ) -> Result<SessionData, ProxyServiceError> {
        let tokens = match state
            .hydra
            .refresh(session.refresh_token.expose_secret())
            .await
        {
            Ok(tokens) => tokens,
            Err(HydraError::Rejected { endpoint, status }) => {
                state.sessions.take_session(session_id).await;
                return Err(ProxyServiceError::RefreshRefused { endpoint, status });
            }
            Err(error) => return Err(error.into()),
        };

        // Without a rotated refresh token the old one lives on, with its old expiry.
        let (refresh_token, refresh_expires_at) = match tokens.refresh_token {
            Some(rotated) => (rotated, Utc::now() + state.hydra.refresh_ttl()),
            None => (session.refresh_token, session.refresh_expires_at),
        };
        // The id_token a refresh may return is not verified, so the login's is kept.
        let data = SessionData {
            access_token: tokens.access_token,
            refresh_token,
            id_token: session.id_token,
            expires_at: Utc::now() + tokens.expires_in,
            created_at: session.created_at,
            refresh_expires_at,
            user_id: session.user_id,
            sid: session.sid,
        };
        if state
            .sessions
            .update_session(session_id, data.clone())
            .await
            .is_err()
        {
            // Logged out while the refresh was in flight: the new tokens must not outlive that.
            if let Err(error) = state.hydra.revoke(data.refresh_token.expose_secret()).await {
                tracing::warn!(%error, "could not revoke the tokens of a session ended mid-refresh");
            }
            return Err(ProxyServiceError::Unauthenticated);
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    // `authenticate` itself needs a real `axum::middleware::Next`, which can
    // only be constructed by the middleware stack -- so it's covered
    // end-to-end via `bff/tests/proxy.rs` instead. `resolve_bearer_token` has no
    // such constraint and is worth pinning directly.
    use super::controller::proxy_router;
    use super::service::*;
    use crate::config::{Config, RouteConfig};
    use crate::model::session::SessionData;
    use crate::server::AppState;
    use crate::storage::SessionStorage;
    use chrono::{Duration, Utc};

    fn expired_session() -> SessionData {
        SessionData {
            access_token: "old-access".to_string().into(),
            refresh_token: "old-refresh".to_string().into(),
            id_token: "id".to_string().into(),
            expires_at: Utc::now() - Duration::minutes(1),
            created_at: Utc::now() - Duration::minutes(10),
            refresh_expires_at: Utc::now() + Duration::days(1),
            user_id: uuid::Uuid::new_v4(),
            sid: None,
        }
    }

    #[tokio::test]
    async fn an_unreachable_hydra_leaves_the_session_for_the_next_try_and_says_so() {
        let mut state = AppState::new(Config {
            hydra_internal_url: "http://127.0.0.1:1".into(),
            ..Config::default()
        })
        .expect("valid app state");
        state
            .sessions
            .save_session("session-1".into(), expired_session())
            .await;

        let result = resolve_bearer_token(&mut state, "session-1").await;

        assert!(matches!(
            result,
            Err(ProxyServiceError::RefreshUnavailable(_))
        ));
        assert!(state.sessions.get_session("session-1").await.is_some());
    }

    #[tokio::test]
    async fn a_dead_refresh_token_is_unauthenticated_without_asking_hydra() {
        let mut state = AppState::new(Config {
            hydra_internal_url: "http://127.0.0.1:1".into(),
            ..Config::default()
        })
        .expect("valid app state");
        let mut session = expired_session();
        session.refresh_expires_at = Utc::now() - Duration::seconds(1);
        state
            .sessions
            .save_session("session-1".into(), session)
            .await;

        let result = resolve_bearer_token(&mut state, "session-1").await;

        assert_eq!(result.err(), Some(ProxyServiceError::Unauthenticated));
    }

    #[tokio::test]
    async fn a_session_past_its_end_is_refused_even_while_its_access_token_is_fresh() {
        let mut state = AppState::new(Config::default()).expect("valid app state");
        let mut session = expired_session();
        session.expires_at = Utc::now() + Duration::hours(1);
        session.refresh_expires_at = Utc::now() - Duration::seconds(1);
        state
            .sessions
            .save_session("session-1".into(), session)
            .await;

        let result = resolve_bearer_token(&mut state, "session-1").await;

        assert_eq!(result.err(), Some(ProxyServiceError::Unauthenticated));
    }

    #[tokio::test]
    async fn a_session_past_its_absolute_lifetime_cannot_be_refreshed_however_alive_its_token() {
        let mut state = AppState::new(Config {
            hydra_internal_url: "http://127.0.0.1:1".into(),
            ..Config::default()
        })
        .expect("valid app state");
        let mut session = expired_session();
        session.created_at =
            Utc::now() - crate::model::session::MAX_SESSION_LIFETIME - Duration::seconds(1);
        state
            .sessions
            .save_session("session-1".into(), session)
            .await;

        let result = resolve_bearer_token(&mut state, "session-1").await;

        assert_eq!(result.err(), Some(ProxyServiceError::Unauthenticated));
    }

    #[tokio::test]
    async fn a_session_past_its_absolute_lifetime_is_refused_even_with_a_fresh_access_token() {
        let mut state = AppState::new(Config {
            hydra_internal_url: "http://127.0.0.1:1".into(),
            ..Config::default()
        })
        .expect("valid app state");
        let mut session = expired_session();
        session.expires_at = Utc::now() + Duration::minutes(10);
        session.created_at =
            Utc::now() - crate::model::session::MAX_SESSION_LIFETIME - Duration::seconds(1);
        state
            .sessions
            .save_session("session-1".into(), session)
            .await;

        let result = resolve_bearer_token(&mut state, "session-1").await;

        assert_eq!(result.err(), Some(ProxyServiceError::Unauthenticated));
    }

    #[tokio::test]
    async fn a_fresh_session_is_resolved_without_asking_hydra() {
        use secrecy::ExposeSecret;
        let mut state = AppState::new(Config {
            hydra_internal_url: "http://127.0.0.1:1".into(),
            ..Config::default()
        })
        .expect("valid app state");
        let mut session = expired_session();
        session.expires_at = Utc::now() + Duration::minutes(10);
        state
            .sessions
            .save_session("session-1".into(), session)
            .await;

        let token = resolve_bearer_token(&mut state, "session-1").await.unwrap();

        assert_eq!(token.expose_secret(), "old-access");
    }

    #[tokio::test]
    async fn an_upstream_that_never_answers_is_a_gateway_timeout() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}", listener.local_addr().unwrap());
        // Accepts and stays silent.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((connection, _)) = listener.accept().await {
                held.push(connection);
            }
        });
        let state = AppState::new(Config {
            routes: vec![RouteConfig {
                path_prefix: "/api".into(),
                upstream_url,
            }],
            ..Config::default()
        })
        .unwrap();
        let mut session = expired_session();
        session.expires_at = Utc::now() + Duration::minutes(10);
        state
            .sessions
            .clone()
            .save_session("s1".into(), session)
            .await;

        let request = Request::get("/api/x")
            .header("cookie", "wa_session=s1")
            .body(Body::empty())
            .unwrap();

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            proxy_router(state).oneshot(request),
        )
        .await
        .expect("bff gave up on the upstream")
        .unwrap();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }
}
