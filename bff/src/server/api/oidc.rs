pub(crate) use controller::oidc_callback;
pub(crate) use controller::start_oidc_login;

mod controller {
    use axum::body::Body;
    use axum::extract::{Path, Query, State};
    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use axum::response::{AppendHeaders, IntoResponse, Response};
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;

    use crate::server::api::complete_login::{complete_login, CompleteLoginError};
    use crate::server::cookie::{build_cookie, clear_cookie, extract_cookie};
    use crate::server::AppState;

    /// Path the flow cookies are scoped to -- covers every provider's
    /// `/oidc/{provider}/login` and `/oidc/{provider}/callback`.
    const FLOW_COOKIE_PATH: &str = "/oidc";
    const FLOW_COOKIE_TTL_SECS: i64 = 300;
    const REDIRECT_URI_COOKIE: &str = "wa_oidc_redirect_uri";
    const NEXT_COOKIE: &str = "wa_oidc_next";

    #[derive(Deserialize)]
    pub(crate) struct OidcLoginRequest {
        pub(super) redirect_uri: String,
        /// Where to bounce the browser back to if the flow fails -- the login
        /// page's own URL, supplied by its own link, not user-typed input.
        pub(super) next: String,
    }

    #[derive(Deserialize)]
    pub(crate) struct OidcCallbackRequest {
        pub(super) code: String,
        pub(super) state: String,
    }

    #[derive(Deserialize)]
    struct LoginSessionResponse {
        login_session: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum OidcLoginError {
        #[error("unknown oidc provider")]
        #[error_response(StatusCode::NOT_FOUND, details = "unknown oidc provider")]
        UnknownProvider,
        #[error("backend returned an unexpected response")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "backend returned an unexpected response")]
        BackendUnavailable,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum OidcCallbackError {
        /// The flow cookies set by `start_oidc_login` are gone (expired, or
        /// this callback was hit without going through that first) -- there's
        /// nowhere known-safe to bounce the browser back to, so this is a
        /// bare error rather than a friendly redirect.
        #[error("missing or expired oidc flow state")]
        #[error_response(StatusCode::BAD_REQUEST, details = "missing or expired oidc flow state")]
        MissingFlowState,
    }

    /// Starts a third-party OIDC login: fetches the provider's consent-screen
    /// URL from backend server-to-server (backend isn't internet-exposed, so
    /// the browser can't be sent there directly to ask), then relays that
    /// redirect to the browser. `redirect_uri`/`next` are stashed in
    /// short-lived cookies scoped to `/oidc` so `oidc_callback` -- reached via
    /// a top-level navigation the provider initiates, not a link this app
    /// controls -- can recover them.
    pub(crate) async fn start_oidc_login(
        State(state): State<AppState>,
        Path(provider): Path<String>,
        Query(req): Query<OidcLoginRequest>,
    ) -> Result<Response, OidcLoginError> {
        let backend_resp = state
            .http_client
            .get(format!("{}/oauth/oidc/{provider}/login", state.config.backend_url))
            .send()
            .await
            .map_err(|_| OidcLoginError::BackendUnavailable)?;

        if backend_resp.status() == StatusCode::NOT_FOUND {
            return Err(OidcLoginError::UnknownProvider);
        }
        if !backend_resp.status().is_redirection() {
            return Err(OidcLoginError::BackendUnavailable);
        }
        let provider_auth_url = backend_resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(OidcLoginError::BackendUnavailable)?
            .to_string();

        let redirect_uri_cookie =
            build_cookie(REDIRECT_URI_COOKIE, &req.redirect_uri, FLOW_COOKIE_PATH, FLOW_COOKIE_TTL_SECS);
        let next_cookie = build_cookie(NEXT_COOKIE, &req.next, FLOW_COOKIE_PATH, FLOW_COOKIE_TTL_SECS);
        let cookies = [
            (
                header::SET_COOKIE,
                HeaderValue::from_str(&redirect_uri_cookie).map_err(|_| OidcLoginError::BackendUnavailable)?,
            ),
            (
                header::SET_COOKIE,
                HeaderValue::from_str(&next_cookie).map_err(|_| OidcLoginError::BackendUnavailable)?,
            ),
        ];

        Ok((
            StatusCode::SEE_OTHER,
            AppendHeaders(cookies),
            [(header::LOCATION, provider_auth_url)],
            Body::empty(),
        )
            .into_response())
    }

    /// Where the provider redirects the browser back to. Forwards `code` and
    /// `state` to backend server-to-server to complete the exchange, then
    /// finishes the login exactly like a password login would (PKCE
    /// authorization-code exchange against backend, session cookie), landing
    /// on the `redirect_uri` stashed by `start_oidc_login`. Any failure along
    /// the way bounces to `next` with `?error=1`, same as a failed password
    /// login -- except a missing/expired flow cookie, which has no known-safe
    /// destination to bounce to.
    pub(crate) async fn oidc_callback(
        State(mut state): State<AppState>,
        Path(provider): Path<String>,
        Query(req): Query<OidcCallbackRequest>,
        headers: HeaderMap,
    ) -> Result<Response, OidcCallbackError> {
        let redirect_uri =
            extract_cookie(&headers, REDIRECT_URI_COOKIE).ok_or(OidcCallbackError::MissingFlowState)?;
        let next = extract_cookie(&headers, NEXT_COOKIE).ok_or(OidcCallbackError::MissingFlowState)?;

        let clear_flow_cookies = [
            (header::SET_COOKIE, clear_cookie(REDIRECT_URI_COOKIE, FLOW_COOKIE_PATH)),
            (header::SET_COOKIE, clear_cookie(NEXT_COOKIE, FLOW_COOKIE_PATH)),
        ];
        let error_redirect = |next: &str| -> Response {
            let sep = if next.contains('?') { '&' } else { '?' };
            (
                StatusCode::SEE_OTHER,
                AppendHeaders(clear_flow_cookies.clone()),
                [(header::LOCATION, format!("{next}{sep}error=1"))],
            )
                .into_response()
        };

        let backend_resp = match state
            .http_client
            .get(format!("{}/oauth/oidc/{provider}/callback", state.config.backend_url))
            .query(&[("code", &req.code), ("state", &req.state)])
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => resp,
            _ => return Ok(error_redirect(&next)),
        };
        let Ok(login_session) = backend_resp.json::<LoginSessionResponse>().await else {
            return Ok(error_redirect(&next));
        };

        let session_cookie = match complete_login(&mut state, &login_session.login_session, &redirect_uri).await {
            Ok(cookie) => cookie,
            Err(CompleteLoginError::InvalidRedirectUri | CompleteLoginError::TokenExchangeFailed | CompleteLoginError::BackendUnavailable) => {
                return Ok(error_redirect(&next));
            }
        };

        let mut set_cookies = clear_flow_cookies.to_vec();
        set_cookies.push((header::SET_COOKIE, session_cookie));

        Ok((
            StatusCode::SEE_OTHER,
            AppendHeaders(set_cookies),
            [(header::LOCATION, redirect_uri)],
            Body::empty(),
        )
            .into_response())
    }
}
