pub(crate) use controller::proxy_router;

mod controller {
    use crate::server::AppState;
    use crate::storage::SessionStorage;
    use axum::Router;
    use axum::extract::{Request, State};
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::middleware::{self, Next};
    use axum::response::Response;
    use axum_reverse_proxy::ReverseProxy;
    use common::model::token::TokenType;
    use common_macros::ErrorResponses;
    use thiserror::Error;

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum ProxyError {
        #[error("missing or invalid session")]
        #[error_response(StatusCode::UNAUTHORIZED, details = "missing or invalid session")]
        Unauthenticated,
    }

    pub(super) fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
        let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
        cookie_header.split(';').find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == cookie_name).then(|| value.to_string())
        })
    }

    /// Swaps the session cookie for the upstream `Authorization: Bearer <token>`
    /// header before handing the request to the reverse proxy.
    async fn authenticate(
        State(state): State<AppState>,
        mut req: Request,
        next: Next,
    ) -> Result<Response, ProxyError> {
        let session_id = extract_cookie(req.headers(), &state.config.session_cookie_name)
            .ok_or(ProxyError::Unauthenticated)?;
        let session = state
            .sessions
            .get_session(&session_id)
            .await
            .ok_or(ProxyError::Unauthenticated)?;

        req.headers_mut().remove(header::COOKIE);
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("{} {}", TokenType::Bearer, session.access_token)
                .parse()
                .expect("bearer token is a valid header value"),
        );

        Ok(next.run(req).await)
    }

    /// One `axum-reverse-proxy` service per configured route, merged, gated by
    /// session auth. The proxy crate handles path stripping, header/body
    /// forwarding, and hop-by-hop header removal.
    pub(crate) fn proxy_router(state: AppState) -> Router {
        let routes = state
            .config
            .routes
            .iter()
            .fold(Router::new(), |router, route| {
                let upstream: Router = ReverseProxy::new(&route.path_prefix, &route.upstream_url).into();
                router.merge(upstream)
            });

        routes
            .layer(middleware::from_fn_with_state(state, authenticate))
            .fallback(StatusCode::NOT_FOUND)
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::http::{HeaderMap, HeaderValue, header};

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn extract_cookie_returns_none_without_a_cookie_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_cookie(&headers, "wa_session"), None);
    }

    #[test]
    fn extract_cookie_finds_the_named_cookie_among_several() {
        let headers = headers_with_cookie("other=1; wa_session=abc123; another=2");
        assert_eq!(extract_cookie(&headers, "wa_session"), Some("abc123".to_string()));
    }

    #[test]
    fn extract_cookie_returns_none_when_name_is_absent() {
        let headers = headers_with_cookie("other=1; another=2");
        assert_eq!(extract_cookie(&headers, "wa_session"), None);
    }

    #[test]
    fn extract_cookie_handles_a_single_cookie_with_no_semicolons() {
        let headers = headers_with_cookie("wa_session=only-one");
        assert_eq!(extract_cookie(&headers, "wa_session"), Some("only-one".to_string()));
    }
}
