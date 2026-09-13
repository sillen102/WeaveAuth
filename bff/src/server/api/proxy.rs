pub(crate) use controller::proxy_router;

mod controller {
    use crate::model::session::SessionData;
    use crate::server::AppState;
    use crate::storage::SessionStorage;
    use axum::Router;
    use axum::extract::{Request, State};
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::middleware::{self, Next};
    use axum::response::Response;
    use axum_reverse_proxy::ReverseProxy;
    use chrono::{DateTime, Utc};
    use common::model::token::TokenType;
    use common_macros::ErrorResponses;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;
    use uuid::Uuid;

    /// Treat an access token as due for refresh this far before it actually
    /// expires. Without this, a token valid at the "is it expired" check
    /// could still expire in the time it takes to reach backend over the
    /// network, turning an otherwise-successful proxied request into a
    /// spurious auth failure there instead of here.
    const ACCESS_TOKEN_REFRESH_LEEWAY: chrono::Duration = chrono::Duration::seconds(5);

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum ProxyError {
        #[error("missing or invalid session")]
        #[error_response(StatusCode::UNAUTHORIZED, details = "missing or invalid session")]
        Unauthenticated,
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

    /// Swaps the session cookie for the upstream `Authorization: Bearer <token>`
    /// header before handing the request to the reverse proxy. If the access
    /// token has expired but the refresh token hasn't, transparently redeems
    /// it via `refresh_session` first -- the caller never sees the expiry.
    async fn authenticate(
        State(mut state): State<AppState>,
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

        let session = if session.expires_at > Utc::now() + ACCESS_TOKEN_REFRESH_LEEWAY {
            session
        } else if session.refresh_expires_at > Utc::now() {
            refresh_session(&mut state, &session_id, &session.refresh_token)
                .await
                .ok_or(ProxyError::Unauthenticated)?
        } else {
            return Err(ProxyError::Unauthenticated);
        };

        let auth_value = format!("{} {}", TokenType::Bearer, session.access_token)
            .parse()
            .map_err(|_| ProxyError::Unauthenticated)?;
        req.headers_mut().remove(header::COOKIE);
        req.headers_mut().insert(header::AUTHORIZATION, auth_value);

        Ok(next.run(req).await)
    }

    /// Redeems `session.refresh_token` for a fresh token pair against
    /// backend's `/oauth/token` refresh grant, and persists it under the same
    /// `session_id` (backend rotates the refresh token on every use, so the
    /// old one stops working the moment this succeeds). Returns `None` on any
    /// failure -- network error, non-2xx, or an unparseable body -- leaving
    /// the caller to treat that the same as "no valid session".
    ///
    /// Known limitation, not worth building around here: if several requests
    /// race in while the access token is expired, each calls this
    /// concurrently; backend's refresh tokens are single-use, so only one of
    /// these wins and the rest fail closed (a spurious 401) instead of
    /// queueing behind the winner.
    async fn refresh_session(
        state: &mut AppState,
        session_id: &str,
        refresh_token: &str,
    ) -> Option<SessionData> {
        let resp = state
            .http_client
            .post(format!("{}/oauth/token", state.config.backend_url))
            .form(&RefreshTokenRequest {
                grant_type: "refresh_token",
                refresh_token,
            })
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let token: TokenResponse = resp.json().await.ok()?;

        let data = SessionData {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_at: token.expires_at,
            refresh_expires_at: token.refresh_expires_at,
            user_id: token.user_id,
        };
        state
            .sessions
            .save_session(session_id.to_string(), data.clone())
            .await;
        Some(data)
    }

    pub(super) fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
        let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
        cookie_header.split(';').find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == cookie_name).then(|| value.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::http::{HeaderMap, HeaderValue, header};

    fn headers_with_cookie(value: &str) -> anyhow::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(value)?);
        Ok(headers)
    }

    #[test]
    fn extract_cookie_returns_none_without_a_cookie_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_cookie(&headers, "wa_session"), None);
    }

    #[test]
    fn extract_cookie_finds_the_named_cookie_among_several() -> anyhow::Result<()> {
        let headers = headers_with_cookie("other=1; wa_session=abc123; another=2")?;
        assert_eq!(extract_cookie(&headers, "wa_session"), Some("abc123".to_string()));
        Ok(())
    }

    #[test]
    fn extract_cookie_returns_none_when_name_is_absent() -> anyhow::Result<()> {
        let headers = headers_with_cookie("other=1; another=2")?;
        assert_eq!(extract_cookie(&headers, "wa_session"), None);
        Ok(())
    }

    #[test]
    fn extract_cookie_handles_a_single_cookie_with_no_semicolons() -> anyhow::Result<()> {
        let headers = headers_with_cookie("wa_session=only-one")?;
        assert_eq!(extract_cookie(&headers, "wa_session"), Some("only-one".to_string()));
        Ok(())
    }
}
