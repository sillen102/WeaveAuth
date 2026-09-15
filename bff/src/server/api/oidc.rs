pub(crate) use controller::oidc_callback;
pub(crate) use controller::oidc_confirm_link;
pub(crate) use controller::start_oidc_login;

mod controller {
    use axum::body::Body;
    use axum::extract::{Path, Query, State};
    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use axum::response::{AppendHeaders, IntoResponse, Response};
    use axum::Form;
    use common_macros::ErrorResponses;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::server::api::complete_login::{complete_login, CompleteLoginError};
    use crate::server::cookie::{build_cookie, clear_cookie, extract_cookie};
    use crate::server::origin_check::{is_safe_redirect_target, require_trusted_origin};
    use crate::server::AppState;

    /// Path the flow cookies are scoped to -- covers every provider's
    /// `/oidc/{provider}/login` and `/oidc/{provider}/callback`.
    const FLOW_COOKIE_PATH: &str = "/oidc";
    const FLOW_COOKIE_TTL_SECS: i64 = 300;
    const REDIRECT_URI_COOKIE: &str = "wa_oidc_redirect_uri";
    const NEXT_COOKIE: &str = "wa_oidc_next";

    /// `provider` is interpolated into the backend URL below; axum
    /// percent-decodes path params, so without this check a value like
    /// `..%2Fhealth` could steer the server-to-server request at arbitrary
    /// backend GET routes.
    fn is_valid_provider(provider: &str) -> bool {
        !provider.is_empty() && provider.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    }

    #[derive(Deserialize)]
    pub(crate) struct OidcLoginRequest {
        pub(super) redirect_uri: String,
        /// Where to bounce the browser back to if the flow fails. Arrives as a
        /// plain query param on a GET link anyone can send a victim, so it's
        /// checked with `is_safe_redirect_target` before use -- see
        /// `OidcLoginError::InvalidNext`.
        pub(super) next: String,
    }

    #[derive(Deserialize)]
    pub(crate) struct OidcCallbackRequest {
        pub(super) code: String,
        pub(super) state: String,
    }

    /// Mirrors backend's `OidcCallbackResponse` -- either a completed login
    /// (same shape as a password login) or a signal that this email matches
    /// an existing, unverified account and needs `oidc_confirm_link` before
    /// the identity is actually linked.
    #[derive(Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    enum OidcCallbackResponse {
        Authenticated { login_session: String },
        PasswordConfirmationRequired { pending_link_token: String, email: String },
    }

    #[derive(Deserialize)]
    pub(crate) struct OidcConfirmLinkRequest {
        pub(super) pending_link_token: String,
        pub(super) password: String,
        pub(super) redirect_uri: String,
        /// Where to bounce the browser back to if confirmation fails. Checked
        /// with `is_safe_redirect_target` -- see `OidcConfirmLinkError::InvalidNext`.
        pub(super) next: String,
    }

    #[derive(Serialize)]
    struct ConfirmLinkBackendRequest<'a> {
        pending_link_token: &'a str,
        password: &'a str,
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
        #[error("next is not a same-origin path or a trusted origin")]
        #[error_response(StatusCode::BAD_REQUEST, details = "next is not a same-origin path or a trusted origin")]
        InvalidNext,
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
        #[error("unknown oidc provider")]
        #[error_response(StatusCode::NOT_FOUND, details = "unknown oidc provider")]
        UnknownProvider,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum OidcConfirmLinkError {
        #[error("request did not come from a trusted origin")]
        #[error_response(StatusCode::FORBIDDEN, details = "request did not come from a trusted origin")]
        UntrustedOrigin,
        #[error("backend returned an unexpected response")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "backend returned an unexpected response")]
        BackendUnavailable,
        #[error("next is not a same-origin path or a trusted origin")]
        #[error_response(StatusCode::BAD_REQUEST, details = "next is not a same-origin path or a trusted origin")]
        InvalidNext,
    }

    impl From<CompleteLoginError> for OidcConfirmLinkError {
        fn from(err: CompleteLoginError) -> Self {
            match err {
                CompleteLoginError::InvalidRedirectUri
                | CompleteLoginError::TokenExchangeFailed
                | CompleteLoginError::BackendUnavailable => OidcConfirmLinkError::BackendUnavailable,
            }
        }
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
        if !is_safe_redirect_target(&req.next, &state.config.trusted_origins) {
            return Err(OidcLoginError::InvalidNext);
        }
        if !is_valid_provider(&provider) {
            return Err(OidcLoginError::UnknownProvider);
        }

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
        if !is_valid_provider(&provider) {
            return Err(OidcCallbackError::UnknownProvider);
        }
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
        let Ok(callback_response) = backend_resp.json::<OidcCallbackResponse>().await else {
            return Ok(error_redirect(&next));
        };

        let login_session = match callback_response {
            OidcCallbackResponse::Authenticated { login_session } => login_session,
            OidcCallbackResponse::PasswordConfirmationRequired { pending_link_token, email } => {
                // Not a failure -- the login page renders a "confirm your
                // password to link this account" form for this case, so it
                // needs these on its own URL rather than a friendly error.
                let sep = if next.contains('?') { '&' } else { '?' };
                let location = format!(
                    "{next}{sep}pending_link_token={}&email={}",
                    url::form_urlencoded::byte_serialize(pending_link_token.as_bytes()).collect::<String>(),
                    url::form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>(),
                );
                return Ok((
                    StatusCode::SEE_OTHER,
                    AppendHeaders(clear_flow_cookies),
                    [(header::LOCATION, location)],
                    Body::empty(),
                )
                    .into_response());
            }
        };

        let session_cookie = match complete_login(&mut state, &login_session, &redirect_uri).await {
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

    /// Finishes an OIDC login that `oidc_callback` flagged as needing
    /// password confirmation, once the caller has resupplied the existing
    /// account's password. Forwards to backend's `/oauth/oidc/confirm-link`,
    /// then completes the login exactly like a password login would --
    /// mirroring `start_login` (trusted-origin check, `complete_login`,
    /// session cookie, redirect to `redirect_uri`).
    pub(crate) async fn oidc_confirm_link(
        State(mut state): State<AppState>,
        headers: HeaderMap,
        Form(req): Form<OidcConfirmLinkRequest>,
    ) -> Result<Response, OidcConfirmLinkError> {
        require_trusted_origin(&headers, &state.config.trusted_origins)
            .map_err(|_| OidcConfirmLinkError::UntrustedOrigin)?;
        if !is_safe_redirect_target(&req.next, &state.config.trusted_origins) {
            return Err(OidcConfirmLinkError::InvalidNext);
        }

        let backend_resp = state
            .http_client
            .post(format!("{}/oauth/oidc/confirm-link", state.config.backend_url))
            .json(&ConfirmLinkBackendRequest {
                pending_link_token: &req.pending_link_token,
                password: &req.password,
            })
            .send()
            .await
            .map_err(|_| OidcConfirmLinkError::BackendUnavailable)?;

        if backend_resp.status() == StatusCode::UNAUTHORIZED || backend_resp.status() == StatusCode::BAD_REQUEST {
            // Wrong password, or the (single-use) pending-link token is
            // already dead -- either way there's nothing to retry with, so
            // send the browser back to the plain login page rather than
            // re-showing a confirm-link form that can no longer succeed.
            let sep = if req.next.contains('?') { '&' } else { '?' };
            return Ok((
                StatusCode::SEE_OTHER,
                [(header::LOCATION, format!("{}{sep}error=link_failed", req.next))],
            )
                .into_response());
        }
        if !backend_resp.status().is_success() {
            return Err(OidcConfirmLinkError::BackendUnavailable);
        }
        let login_session = backend_resp
            .json::<LoginSessionResponse>()
            .await
            .map_err(|_| OidcConfirmLinkError::BackendUnavailable)?
            .login_session;

        let cookie = complete_login(&mut state, &login_session, &req.redirect_uri).await?;

        Ok((
            StatusCode::SEE_OTHER,
            [(header::LOCATION, req.redirect_uri), (header::SET_COOKIE, cookie)],
            Body::empty(),
        )
            .into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, HeaderValue};
    use axum::Form;

    use crate::config::Config;
    use crate::server::api::complete_login::CompleteLoginError;
    use crate::server::AppState;

    fn state_with_trusted_origins(trusted_origins: Vec<String>) -> AppState {
        AppState::new(Config {
            port: 8080,
            bff_url: "http://bff.test".into(),
            backend_url: "http://unused.test".into(),
            session_cookie_name: "wa_session".into(),
            routes: vec![],
            trusted_origins,
            rate_limit_max_attempts: 1000,
            rate_limit_window_secs: 60,
        })
        .expect("valid app state")
    }

    #[tokio::test]
    async fn confirm_link_rejects_an_untrusted_origin_before_contacting_backend() {
        // backend_url above is unreachable -- a FORBIDDEN result (rather than a
        // BAD_GATEWAY from trying to reach it) proves the origin check runs first.
        let state = state_with_trusted_origins(vec!["http://login.test".to_string()]);
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("http://evil.test"));
        let req = OidcConfirmLinkRequest {
            pending_link_token: "tok".to_string(),
            password: "hunter2".to_string(),
            redirect_uri: "http://admin.test/".to_string(),
            next: "http://login.test/".to_string(),
        };

        let result = oidc_confirm_link(State(state), headers, Form(req)).await;

        assert_eq!(result.err(), Some(OidcConfirmLinkError::UntrustedOrigin));
    }

    #[tokio::test]
    async fn login_rejects_a_path_traversal_provider_before_contacting_backend() {
        let state = state_with_trusted_origins(vec!["http://login.test".to_string()]);
        let req = OidcLoginRequest {
            redirect_uri: "http://login.test/".to_string(),
            next: "http://login.test/".to_string(),
        };

        let result = start_oidc_login(State(state), Path("../health".to_string()), Query(req)).await;

        assert_eq!(result.err(), Some(OidcLoginError::UnknownProvider));
    }

    #[tokio::test]
    async fn callback_rejects_a_path_traversal_provider_before_reading_flow_cookies() {
        let state = state_with_trusted_origins(vec!["http://login.test".to_string()]);
        let req = OidcCallbackRequest { code: "c".to_string(), state: "s".to_string() };

        let result =
            oidc_callback(State(state), Path("../health".to_string()), Query(req), HeaderMap::new()).await;

        assert_eq!(result.err(), Some(OidcCallbackError::UnknownProvider));
    }

    #[test]
    fn every_complete_login_error_maps_to_backend_unavailable() {
        for err in [
            CompleteLoginError::InvalidRedirectUri,
            CompleteLoginError::TokenExchangeFailed,
            CompleteLoginError::BackendUnavailable,
        ] {
            assert_eq!(OidcConfirmLinkError::from(err), OidcConfirmLinkError::BackendUnavailable);
        }
    }
}
