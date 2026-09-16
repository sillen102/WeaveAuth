pub(crate) use controller::oidc_callback;
pub(crate) use controller::oidc_confirm_link;
pub(crate) use controller::start_oidc_login;

mod controller {
    use axum::body::Body;
    use axum::extract::{Path, Query, State};
    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use axum::response::{AppendHeaders, IntoResponse, Response};
    use axum::Form;
    use serde::Deserialize;

    use crate::server::cookie::{build_cookie, build_cross_site_cookie, clear_cookie, extract_cookie};
    use crate::server::origin_check::{is_safe_redirect_target, require_trusted_origin};
    use crate::server::AppState;

    use super::service::{self, ConfirmLinkOutcome, OidcCallbackOutcome};
    pub(crate) use super::service::{OidcCallbackError, OidcConfirmLinkError, OidcLoginError};

    /// Path the flow cookies are scoped to -- covers every provider's
    /// `/oidc/{provider}/login` and `/oidc/{provider}/callback`.
    const FLOW_COOKIE_PATH: &str = "/oidc";
    const FLOW_COOKIE_TTL_SECS: i64 = 300;
    const REDIRECT_URI_COOKIE: &str = "wa_oidc_redirect_uri";
    const NEXT_COOKIE: &str = "wa_oidc_next";
    const STATE_COOKIE: &str = "wa_oidc_state";
    /// Carries `pending_link_token` from `oidc_callback` to `oidc_confirm_link`
    /// instead of the URL -- it's half a credential (paired with the account
    /// password), and a URL leaks into browser history, Referer headers, and
    /// access logs in a way a short-lived HttpOnly cookie doesn't.
    ///
    /// `oidc_confirm_link` is reached by the login page's own form POSTing
    /// to this service, which is cross-site whenever login and bff aren't
    /// deployed same-site -- so this is the one flow cookie built with
    /// `build_cross_site_cookie` (`SameSite=None`) instead of `build_cookie`
    /// (`SameSite=Lax`), which browsers withhold from a cross-site POST.
    const PENDING_LINK_TOKEN_COOKIE: &str = "wa_oidc_pending_link_token";

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
        /// Absent when the provider redirects back with `?error=...` instead
        /// (e.g. user declined consent) -- optional so that case still
        /// deserializes into a friendly `next` bounce instead of axum
        /// rejecting the query with a raw 422 before the handler (and its
        /// flow-cookie cleanup) ever runs.
        pub(super) code: Option<String>,
        pub(super) state: Option<String>,
    }

    #[derive(Deserialize)]
    pub(crate) struct OidcConfirmLinkRequest {
        pub(super) password: String,
        pub(super) redirect_uri: String,
        /// Where to bounce the browser back to if confirmation fails. Checked
        /// with `is_safe_redirect_target` -- see `OidcConfirmLinkError::InvalidNext`.
        pub(super) next: String,
    }

    /// Starts a third-party OIDC login. `redirect_uri`/`next` are stashed in
    /// short-lived cookies scoped to `/oidc` so `oidc_callback` -- reached via
    /// a top-level navigation the provider initiates, not a link this app
    /// controls -- can recover them.
    pub(crate) async fn start_oidc_login(
        State(mut state): State<AppState>,
        Path(provider): Path<String>,
        Query(req): Query<OidcLoginRequest>,
    ) -> Result<Response, OidcLoginError> {
        if !is_safe_redirect_target(&req.next, &state.config.trusted_origins) {
            return Err(OidcLoginError::InvalidNext);
        }

        let started = service::start_oidc_login(&mut state, &provider).await?;

        let secure = state.config.secure_cookies();
        let redirect_uri_cookie = build_cookie(
            REDIRECT_URI_COOKIE,
            &req.redirect_uri,
            FLOW_COOKIE_PATH,
            FLOW_COOKIE_TTL_SECS,
            secure,
        );
        let next_cookie = build_cookie(NEXT_COOKIE, &req.next, FLOW_COOKIE_PATH, FLOW_COOKIE_TTL_SECS, secure);
        let state_cookie = build_cookie(STATE_COOKIE, &started.csrf_state, FLOW_COOKIE_PATH, FLOW_COOKIE_TTL_SECS, secure);
        let cookies = [
            (
                header::SET_COOKIE,
                HeaderValue::from_str(&redirect_uri_cookie).map_err(|_| OidcLoginError::BackendUnavailable)?,
            ),
            (
                header::SET_COOKIE,
                HeaderValue::from_str(&next_cookie).map_err(|_| OidcLoginError::BackendUnavailable)?,
            ),
            (
                header::SET_COOKIE,
                HeaderValue::from_str(&state_cookie).map_err(|_| OidcLoginError::BackendUnavailable)?,
            ),
        ];

        Ok((
            StatusCode::SEE_OTHER,
            AppendHeaders(cookies),
            [(header::LOCATION, started.provider_auth_url)],
            Body::empty(),
        )
            .into_response())
    }

    /// Where the provider redirects the browser back to. Forwards `code` and
    /// `state` to backend server-to-server to complete the exchange, then
    /// finishes the login exactly like a password login would, landing on
    /// the `redirect_uri` stashed by `start_oidc_login`. Any failure along
    /// the way bounces to `next` with `?error=1`, same as a failed password
    /// login -- except a missing/expired flow cookie, which has no known-safe
    /// destination to bounce to.
    pub(crate) async fn oidc_callback(
        State(mut state): State<AppState>,
        Path(provider): Path<String>,
        Query(req): Query<OidcCallbackRequest>,
        headers: HeaderMap,
    ) -> Result<Response, OidcCallbackError> {
        if !service::is_valid_provider(&provider) {
            return Err(OidcCallbackError::UnknownProvider);
        }
        let secure = state.config.secure_cookies();
        let clear_flow_cookies = [
            (header::SET_COOKIE, clear_cookie(REDIRECT_URI_COOKIE, FLOW_COOKIE_PATH, secure)),
            (header::SET_COOKIE, clear_cookie(NEXT_COOKIE, FLOW_COOKIE_PATH, secure)),
            (header::SET_COOKIE, clear_cookie(STATE_COOKIE, FLOW_COOKIE_PATH, secure)),
        ];

        // These bail with the flow cookies cleared rather than `?` straight
        // to `OidcCallbackError` -- otherwise the stale redirect_uri/next/state
        // survive for the rest of `FLOW_COOKIE_TTL_SECS` and get reused by the
        // next callback attempt.
        let with_cleared_cookies = |err: OidcCallbackError| -> Response {
            let mut resp = err.into_response();
            for (name, value) in &clear_flow_cookies {
                if let Ok(value) = HeaderValue::from_str(value) {
                    resp.headers_mut().append(name, value);
                }
            }
            resp
        };

        let (Some(redirect_uri), Some(next), Some(flow_state)) = (
            extract_cookie(&headers, REDIRECT_URI_COOKIE),
            extract_cookie(&headers, NEXT_COOKIE),
            extract_cookie(&headers, STATE_COOKIE),
        ) else {
            return Ok(with_cleared_cookies(OidcCallbackError::MissingFlowState));
        };

        let error_redirect = |next: &str| -> Response {
            let sep = if next.contains('?') { '&' } else { '?' };
            (
                StatusCode::SEE_OTHER,
                AppendHeaders(clear_flow_cookies.clone()),
                [(header::LOCATION, format!("{next}{sep}error=1"))],
            )
                .into_response()
        };

        // Provider declined (e.g. `?error=access_denied`) or otherwise
        // skipped `code`/`state` -- no exchange to attempt, bounce friendly.
        let (Some(code), Some(req_state)) = (req.code.as_ref(), req.state.as_ref()) else {
            return Ok(error_redirect(&next));
        };

        // Constant-time-ness doesn't matter here -- `state` isn't a secret
        // the attacker lacks, it's a binding check that this browser is the
        // one that started the flow. A plain compare is fine.
        if *req_state != flow_state {
            return Ok(with_cleared_cookies(OidcCallbackError::StateMismatch));
        }

        match service::complete_oidc_callback(&mut state, &provider, code, req_state, &redirect_uri).await {
            OidcCallbackOutcome::Failed => Ok(error_redirect(&next)),
            OidcCallbackOutcome::PasswordConfirmationRequired { pending_link_token, email } => {
                // `email` (not sensitive, and also what the login page gates
                // the confirm-link form on) goes on the URL, but
                // `pending_link_token` (half a credential) goes in a
                // short-lived cookie instead -- see PENDING_LINK_TOKEN_COOKIE.
                let sep = if next.contains('?') { '&' } else { '?' };
                let location = format!(
                    "{next}{sep}email={}",
                    url::form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>(),
                );
                let pending_link_cookie = build_cross_site_cookie(
                    PENDING_LINK_TOKEN_COOKIE,
                    &pending_link_token,
                    FLOW_COOKIE_PATH,
                    FLOW_COOKIE_TTL_SECS,
                    secure,
                );
                let mut set_cookies = clear_flow_cookies.to_vec();
                set_cookies.push((header::SET_COOKIE, pending_link_cookie));
                Ok((
                    StatusCode::SEE_OTHER,
                    AppendHeaders(set_cookies),
                    [(header::LOCATION, location)],
                    Body::empty(),
                )
                    .into_response())
            }
            OidcCallbackOutcome::Authenticated { cookie } => {
                let mut set_cookies = clear_flow_cookies.to_vec();
                set_cookies.push((header::SET_COOKIE, cookie));
                Ok((
                    StatusCode::SEE_OTHER,
                    AppendHeaders(set_cookies),
                    [(header::LOCATION, redirect_uri)],
                    Body::empty(),
                )
                    .into_response())
            }
        }
    }

    /// Finishes an OIDC login that `oidc_callback` flagged as needing
    /// password confirmation, once the caller has resupplied the existing
    /// account's password. Mirrors `start_login` (trusted-origin check,
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

        // Single-use regardless of outcome, so it's cleared on every path
        // below rather than only on success.
        let clear_pending_link_cookie = (
            header::SET_COOKIE,
            clear_cookie(PENDING_LINK_TOKEN_COOKIE, FLOW_COOKIE_PATH, state.config.secure_cookies()),
        );

        // `req.next` is already validated above, so both a missing/expired
        // pending-link cookie (nothing to bounce back to but the login page)
        // and a wrong password bounce there with `error=link_failed`, instead
        // of the former surfacing as a bare 400.
        let link_failed_redirect = || -> Response {
            let sep = if req.next.contains('?') { '&' } else { '?' };
            (
                StatusCode::SEE_OTHER,
                [clear_pending_link_cookie.clone()],
                [(header::LOCATION, format!("{}{sep}error=link_failed", req.next))],
            )
                .into_response()
        };

        let Some(pending_link_token) = extract_cookie(&headers, PENDING_LINK_TOKEN_COOKIE) else {
            return Ok(link_failed_redirect());
        };

        match service::confirm_oidc_link(&mut state, &pending_link_token, &req.password, &req.redirect_uri).await? {
            ConfirmLinkOutcome::Failed => {
                // Send the browser back to the plain login page rather than
                // re-showing a confirm-link form that can no longer succeed.
                Ok(link_failed_redirect())
            }
            ConfirmLinkOutcome::Authenticated { cookie } => Ok((
                StatusCode::SEE_OTHER,
                AppendHeaders([clear_pending_link_cookie, (header::SET_COOKIE, cookie)]),
                [(header::LOCATION, req.redirect_uri)],
                Body::empty(),
            )
                .into_response()),
        }
    }
}

mod service {
    use axum::http::{header, StatusCode};
    use common_macros::ErrorResponses;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::server::api::complete_login::{complete_login, CompleteLoginError};
    use crate::server::AppState;

    #[derive(Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub(crate) enum OidcCallbackResponse {
        Authenticated { login_session: String },
        PasswordConfirmationRequired { pending_link_token: String, email: String },
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
        /// The `state` query param the provider sent back doesn't match the
        /// value stashed in the flow cookie at `start_oidc_login` -- this
        /// browser never started this flow (classic login-CSRF: an attacker
        /// with their own valid code+state gets a victim's browser to hit
        /// this callback and land logged in as the attacker).
        #[error("oidc state does not match the browser's flow cookie")]
        #[error_response(StatusCode::BAD_REQUEST, details = "oidc state does not match the browser's flow cookie")]
        StateMismatch,
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

    /// `provider` is interpolated into the backend URL; without this check a
    /// value like `..%2Fhealth` could steer the server-to-server request at
    /// arbitrary backend GET routes.
    pub(crate) fn is_valid_provider(provider: &str) -> bool {
        !provider.is_empty() && provider.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    }

    pub(crate) struct StartedOidcLogin {
        pub(crate) provider_auth_url: String,
        pub(crate) csrf_state: String,
    }

    /// Fetches the provider's consent-screen URL from backend
    /// server-to-server (backend isn't internet-exposed, so the browser can't
    /// be sent there directly to ask), along with the CSRF state backend
    /// generated for the flow -- pulled back out of the redirect so it can be
    /// bound to this browser via a cookie (backend only keeps the CSRF state
    /// server-side, so without this the state token proves "some flow was
    /// started", not "this browser started it").
    pub(crate) async fn start_oidc_login(state: &mut AppState, provider: &str) -> Result<StartedOidcLogin, OidcLoginError> {
        if !is_valid_provider(provider) {
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
        let csrf_state = url::Url::parse(&provider_auth_url)
            .ok()
            .and_then(|url| url.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()))
            .ok_or(OidcLoginError::BackendUnavailable)?;

        Ok(StartedOidcLogin { provider_auth_url, csrf_state })
    }

    pub(crate) enum OidcCallbackOutcome {
        Authenticated { cookie: String },
        /// Not a failure -- the login page renders a "confirm your password
        /// to link this account" form for this case.
        PasswordConfirmationRequired { pending_link_token: String, email: String },
        /// Provider exchange or the final login completion failed; the
        /// caller bounces to `next` with `?error=1`.
        Failed,
    }

    /// Server-to-server half of the code exchange: hands `code`/`state` to
    /// backend, and on a completed login drives the same PKCE exchange
    /// `start_login` uses to finish it.
    pub(crate) async fn complete_oidc_callback(
        state: &mut AppState,
        provider: &str,
        code: &str,
        req_state: &str,
        redirect_uri: &str,
    ) -> OidcCallbackOutcome {
        let Some(callback_response) = fetch_callback_response(state, provider, code, req_state).await else {
            return OidcCallbackOutcome::Failed;
        };

        match callback_response {
            OidcCallbackResponse::Authenticated { login_session } => {
                match complete_login(state, &login_session, redirect_uri).await {
                    Ok(cookie) => OidcCallbackOutcome::Authenticated { cookie },
                    Err(CompleteLoginError::InvalidRedirectUri | CompleteLoginError::TokenExchangeFailed | CompleteLoginError::BackendUnavailable) => {
                        OidcCallbackOutcome::Failed
                    }
                }
            }
            OidcCallbackResponse::PasswordConfirmationRequired { pending_link_token, email } => {
                OidcCallbackOutcome::PasswordConfirmationRequired { pending_link_token, email }
            }
        }
    }

    /// Hands `code`/`state` to backend and parses its response. `None`
    /// covers every failure mode (network, non-2xx, bad body) since the
    /// caller treats them all the same way.
    async fn fetch_callback_response(
        state: &AppState,
        provider: &str,
        code: &str,
        req_state: &str,
    ) -> Option<OidcCallbackResponse> {
        let resp = state
            .http_client
            .get(format!("{}/oauth/oidc/{provider}/callback", state.config.backend_url))
            .query(&[("code", code), ("state", req_state)])
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json().await.ok()
    }

    pub(crate) enum ConfirmLinkOutcome {
        Authenticated { cookie: String },
        /// Wrong password, or the (single-use) pending-link token is already
        /// dead -- either way there's nothing to retry with.
        Failed,
    }

    /// Finishes an OIDC login that `complete_oidc_callback` flagged as
    /// needing password confirmation, once the caller has resupplied the
    /// existing account's password. Forwards to backend's
    /// `/oauth/oidc/confirm-link`, then completes the login exactly like a
    /// password login would.
    pub(crate) async fn confirm_oidc_link(
        state: &mut AppState,
        pending_link_token: &str,
        password: &str,
        redirect_uri: &str,
    ) -> Result<ConfirmLinkOutcome, OidcConfirmLinkError> {
        let backend_resp = state
            .http_client
            .post(format!("{}/oauth/oidc/confirm-link", state.config.backend_url))
            .json(&ConfirmLinkBackendRequest { pending_link_token, password })
            .send()
            .await
            .map_err(|_| OidcConfirmLinkError::BackendUnavailable)?;

        if backend_resp.status() == StatusCode::UNAUTHORIZED || backend_resp.status() == StatusCode::BAD_REQUEST {
            return Ok(ConfirmLinkOutcome::Failed);
        }
        if !backend_resp.status().is_success() {
            return Err(OidcConfirmLinkError::BackendUnavailable);
        }
        let login_session = backend_resp
            .json::<LoginSessionResponse>()
            .await
            .map_err(|_| OidcConfirmLinkError::BackendUnavailable)?
            .login_session;

        let cookie = complete_login(state, &login_session, redirect_uri).await?;
        Ok(ConfirmLinkOutcome::Authenticated { cookie })
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
    use crate::server::api::oidc::service::OidcConfirmLinkError;
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
            expiry_sweep_interval_secs: 60,
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
        let req = OidcCallbackRequest {
            code: Some("c".to_string()),
            state: Some("s".to_string()),
        };

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
