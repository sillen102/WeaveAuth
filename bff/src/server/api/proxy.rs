pub(crate) use controller::{proxy_cors, proxy_router, proxy_trusted_origins};

mod controller {
    use axum::Router;
    use axum::extract::{Request, State};
    use axum::http::header;
    use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
    use axum::middleware::{self, Next};
    use axum::response::Response;
    use axum_reverse_proxy::{ProxyPolicy, ReverseProxy, XForwardedFor};
    use common::model::token::TokenType;
    use common_macros::ErrorResponses;
    use secrecy::ExposeSecret;
    use std::sync::Arc;
    use std::time::Duration;
    use thiserror::Error;
    use tower_http::cors::{AllowMethods, AllowOrigin, CorsLayer};

    use crate::config::Config;
    use crate::server::AppState;
    use crate::server::cookie::extract_cookie;
    use crate::server::origin_check::require_trusted_origin;

    use super::service::{self, ProxyServiceError};

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum ProxyError {
        #[error("missing or invalid session")]
        #[error_response(StatusCode::UNAUTHORIZED, details = "missing or invalid session")]
        Unauthenticated,
        #[error("backend returned an unexpected response")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "backend returned an unexpected response"
        )]
        BackendUnavailable,
        #[error("request did not come from a trusted origin")]
        #[error_response(
            StatusCode::FORBIDDEN,
            details = "request did not come from a trusted origin"
        )]
        UntrustedOrigin,
    }

    impl From<ProxyServiceError> for ProxyError {
        fn from(err: ProxyServiceError) -> Self {
            if let ProxyServiceError::BackendUnavailable(_) = &err {
                tracing::warn!(%err, "session refresh failed");
            }
            match err {
                ProxyServiceError::Unauthenticated => ProxyError::Unauthenticated,
                ProxyServiceError::BackendUnavailable(_) => ProxyError::BackendUnavailable,
            }
        }
    }

    /// One `axum-reverse-proxy` service per configured route, merged, gated by
    /// session auth. The proxy crate handles path stripping and body
    /// forwarding; bff decides the headers (see [`authenticate`]), so the crate
    /// must not add forwarding headers of its own.
    pub(crate) fn proxy_router(state: AppState) -> Router {
        let routes = state
            .config
            .routes
            .iter()
            .fold(Router::new(), |router, route| {
                let upstream: Router = ReverseProxy::new(&route.path_prefix, &route.upstream_url)
                    .with_policy(
                        ProxyPolicy::default().with_x_forwarded_for(XForwardedFor::Preserve),
                    )
                    .into();
                router.merge(upstream)
            });

        routes
            .layer(middleware::from_fn_with_state(state, authenticate))
            .fallback(axum::http::StatusCode::NOT_FOUND)
    }

    /// The origins trusted to use the proxy from a browser: to send state-changing
    /// requests and to read its responses cross-origin (see [`proxy_cors`]). That is
    /// `trusted_origins` plus bff's own, for a frontend served through bff.
    pub(crate) fn proxy_trusted_origins(config: &Config) -> anyhow::Result<Arc<[String]>> {
        let bff_origin = url::Url::parse(&config.bff_url)?
            .origin()
            .ascii_serialization();
        Ok(config
            .trusted_origins
            .iter()
            .cloned()
            .chain([bff_origin])
            .collect())
    }

    /// CORS for the proxied routes, for exactly `origins` (see
    /// [`proxy_trusted_origins`]), with credentials. Methods are mirrored from the
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

    /// Client headers an upstream receives, next to bff's `Authorization`.
    /// `Upgrade` stays out until `needs_trusted_origin` also gates WebSocket
    /// handshakes, which are `GET`s.
    const REQUEST_HEADERS: [HeaderName; 1] = [header::CONTENT_TYPE];

    /// Upstream headers the browser receives: ones that only shape that one
    /// response, which an upstream needs to keep its content from running on
    /// bff's origin or being cached for someone else. Proxied content shares
    /// bff's origin, so most others (`Set-Cookie`, `Clear-Site-Data`,
    /// `Service-Worker-Allowed`, `Strict-Transport-Security`, `Alt-Svc`) would
    /// act on bff itself, beyond the upstream's `path_prefix`.
    const RESPONSE_HEADERS: [HeaderName; 4] = [
        header::CONTENT_TYPE,
        header::CONTENT_DISPOSITION,
        header::CONTENT_SECURITY_POLICY,
        header::CACHE_CONTROL,
    ];

    /// Guards the proxy: requires a trusted origin for anything that can change
    /// state, sends the upstream [`REQUEST_HEADERS`] plus `Authorization: Bearer
    /// <token>`, and passes only [`RESPONSE_HEADERS`] back, always with
    /// `X-Content-Type-Options: nosniff` and the caching rules of
    /// [`keep_out_of_shared_caches`].
    async fn authenticate(
        State(mut state): State<AppState>,
        mut req: Request,
        next: Next,
    ) -> Result<Response, ProxyError> {
        if needs_trusted_origin(req.method()) {
            require_trusted_origin(req.headers(), &state.proxy_trusted_origins).map_err(
                |error| {
                    tracing::warn!(%error, "proxied request rejected");
                    ProxyError::UntrustedOrigin
                },
            )?;
        }
        let session_id = extract_cookie(req.headers(), &state.config.session_cookie_name)
            .ok_or(ProxyServiceError::Unauthenticated)?;
        let access_token = service::resolve_bearer_token(&mut state, &session_id).await?;

        let auth_value = format!("{} {}", TokenType::Bearer, access_token.expose_secret())
            .parse()
            .map_err(|error| {
                tracing::warn!(%error, "session access token is not a valid header value");
                ProxyServiceError::Unauthenticated
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
        keep_out_of_shared_caches(headers);
        Ok(response)
    }

    /// `Cache-Control` directives that settle whether a shared cache may store
    /// a response to an `Authorization` request. Stricter than RFC 9111 §3.5:
    /// `must-revalidate` is left out, as upstreams send it on per-user data to
    /// mean "revalidate when stale".
    const SHARED_CACHE_DIRECTIVES: [&str; 4] = ["public", "s-maxage", "private", "no-store"];

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
}

mod service {
    use crate::model::session::SessionData;
    use crate::server::AppState;
    use crate::storage::SessionStorage;
    use chrono::{DateTime, Utc};
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Serialize};
    use thiserror::Error;
    use uuid::Uuid;

    /// Treat an access token as due for refresh this far before it actually
    /// expires. Without this, a token valid at the "is it expired" check
    /// could still expire in the time it takes to reach backend over the
    /// network, turning an otherwise-successful proxied request into a
    /// spurious auth failure there instead of here.
    const ACCESS_TOKEN_REFRESH_LEEWAY: chrono::Duration = chrono::Duration::seconds(5);

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum ProxyServiceError {
        #[error("missing or invalid session")]
        Unauthenticated,
        #[error("backend returned an unexpected response: {0}")]
        BackendUnavailable(String),
    }

    #[derive(Serialize)]
    struct RefreshTokenRequest<'a> {
        grant_type: &'static str,
        refresh_token: &'a str,
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: String,
        expires_at: DateTime<Utc>,
        refresh_expires_at: DateTime<Utc>,
        user_id: Uuid,
    }

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

        let session = if session.expires_at > Utc::now() + ACCESS_TOKEN_REFRESH_LEEWAY {
            session
        } else if session.refresh_expires_at > Utc::now() {
            refresh_session(state, session_id, session.refresh_token.expose_secret()).await?
        } else {
            return Err(ProxyServiceError::Unauthenticated);
        };

        Ok(session.access_token)
    }

    /// Redeems `session.refresh_token` for a fresh token pair against
    /// backend's `/oauth/token` refresh grant, and persists it under the same
    /// `session_id` (backend rotates the refresh token on every use, so the
    /// old one stops working the moment this succeeds). A `4xx` from backend
    /// means the refresh token is dead, so the session is `Unauthenticated`;
    /// a network error, `5xx` or unparseable body says nothing about the
    /// session and is `BackendUnavailable`.
    ///
    /// Known limitation, not worth building around here: if several requests
    /// race in while the access token is expired, each calls this
    /// concurrently; backend's refresh tokens are single-use, so only one of
    /// these wins and the rest fail closed (a spurious 401) instead of
    /// queueing behind the winner.
    pub(crate) async fn refresh_session(
        state: &mut AppState,
        session_id: &str,
        refresh_token: &str,
    ) -> Result<SessionData, ProxyServiceError> {
        let resp = state
            .http_client
            .post(format!("{}/oauth/token", state.config.backend_url))
            .form(&RefreshTokenRequest {
                grant_type: "refresh_token",
                refresh_token,
            })
            .send()
            .await
            .map_err(|error| {
                ProxyServiceError::BackendUnavailable(format!(
                    "refresh request failed: {}",
                    common::error::cause_chain(&error.without_url())
                ))
            })?;
        if resp.status().is_client_error() {
            return Err(ProxyServiceError::Unauthenticated);
        }
        if !resp.status().is_success() {
            return Err(ProxyServiceError::BackendUnavailable(format!(
                "refresh returned {}",
                resp.status()
            )));
        }
        let token: TokenResponse = resp.json().await.map_err(|error| {
            ProxyServiceError::BackendUnavailable(format!(
                "refresh response unreadable: {}",
                common::error::cause_chain(&error.without_url())
            ))
        })?;

        let data = SessionData {
            access_token: token.access_token.into(),
            refresh_token: token.refresh_token.into(),
            expires_at: token.expires_at,
            refresh_expires_at: token.refresh_expires_at,
            user_id: token.user_id,
        };
        state
            .sessions
            .save_session(session_id.to_string(), data.clone())
            .await;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    // `authenticate` itself needs a real `axum::middleware::Next`, which can
    // only be constructed by the middleware stack -- so it's covered
    // end-to-end via `bff/tests/proxy.rs` instead. `refresh_session` has no
    // such constraint and is worth pinning directly: it's the one piece of
    // this file that's a plain, directly-callable async fn.
    use super::controller::proxy_trusted_origins;
    use super::service::*;
    use crate::config::Config;
    use crate::server::AppState;

    fn trusted(origins: &[&str]) -> anyhow::Result<Vec<String>> {
        let config = Config {
            bff_url: "https://bff.test".into(),
            trusted_origins: origins.iter().map(|o| o.to_string()).collect(),
            ..Config::default()
        };
        Ok(proxy_trusted_origins(&config)?.to_vec())
    }

    #[test]
    fn trusted_origins_gain_bffs_own() {
        assert_eq!(
            trusted(&["https://app.test", "http://localhost:3000"]).unwrap(),
            [
                "https://app.test",
                "http://localhost:3000",
                "https://bff.test"
            ]
        );
    }

    fn state_with_backend(backend_url: &str) -> AppState {
        AppState::new(Config {
            port: 8080,
            bff_url: "http://bff.test".into(),
            backend_url: backend_url.into(),
            session_cookie_name: "wa_session".into(),
            routes: vec![],
            trusted_origins: vec![],
            rate_limit_max_attempts: 1000,
            rate_limit_proxy_max_attempts: 1000,
            trusted_proxies: vec![],
            docs_enabled: false,
            login_public_url: "http://login.test".into(),
        })
        .expect("valid app state")
    }

    #[tokio::test]
    async fn refresh_session_is_backend_unavailable_when_backend_is_unreachable() {
        let mut state = state_with_backend("http://127.0.0.1:1");

        let result = refresh_session(&mut state, "session-1", "refresh-token").await;

        assert!(matches!(
            result,
            Err(ProxyServiceError::BackendUnavailable(_))
        ));
    }
}
