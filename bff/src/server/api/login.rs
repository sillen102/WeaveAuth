pub(crate) use controller::start_login;

mod controller {
    use axum::body::Body;
    use axum::extract::State;
    use axum::Form;
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use common_macros::ErrorResponses;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::server::api::complete_login::{complete_login, CompleteLoginError};
    use crate::server::origin_check::require_trusted_origin;
    use crate::server::AppState;

    #[derive(Deserialize)]
    pub(crate) struct LoginRequest {
        pub(super) email: String,
        pub(super) password: String,
        pub(super) redirect_uri: String,
        /// Where to bounce the browser back to on wrong credentials -- the login
        /// page's own URL, supplied by its form, not user-typed input.
        pub(super) next: String,
    }

    #[derive(Serialize)]
    struct VerifyLoginRequest<'a> {
        email: &'a str,
        password: &'a str,
    }

    #[derive(Deserialize)]
    struct LoginSessionResponse {
        login_session: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum LoginError {
        #[error("request did not come from a trusted origin")]
        #[error_response(StatusCode::FORBIDDEN, details = "request did not come from a trusted origin")]
        UntrustedOrigin,
        #[error("redirect_uri is not allowed")]
        #[error_response(StatusCode::BAD_REQUEST, details = "redirect_uri is not allowed")]
        InvalidRedirectUri,
        #[error("token exchange failed")]
        #[error_response(StatusCode::BAD_REQUEST, details = "token exchange failed")]
        TokenExchangeFailed,
        #[error("backend returned an unexpected response")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "backend returned an unexpected response")]
        BackendUnavailable,
    }

    impl From<CompleteLoginError> for LoginError {
        fn from(err: CompleteLoginError) -> Self {
            match err {
                CompleteLoginError::InvalidRedirectUri => LoginError::InvalidRedirectUri,
                CompleteLoginError::TokenExchangeFailed => LoginError::TokenExchangeFailed,
                CompleteLoginError::BackendUnavailable => LoginError::BackendUnavailable,
            }
        }
    }

    /// Verifies the submitted credentials against backend's `/oauth/login`, then
    /// drives the whole authorization-code + PKCE exchange server-to-server in
    /// one request, so the browser only ever talks to bff and never sees backend
    /// (it POSTs its login form straight to bff's absolute URL, so the session
    /// cookie below ends up scoped to bff's origin, not the login page's).
    ///
    /// Per RFC 6749 4.1.1, authenticating the resource owner happens before a
    /// code is issued: `/oauth/login`'s response carries a single-use
    /// `login_session` that `/oauth/authorize` requires, so backend itself
    /// enforces this order for any caller -- not just bff.
    ///
    /// The `redirect_uri` a caller passes here (the final browser destination) is
    /// sent as-is to backend's `/oauth/authorize`, which allowlist-checks it and
    /// refuses to issue a code for anything not listed. bff never navigates the
    /// browser there itself during this hop (redirects aren't followed), so
    /// there's no open-redirect exposure in sending the real value through.
    pub(crate) async fn start_login(
        State(mut state): State<AppState>,
        headers: HeaderMap,
        Form(req): Form<LoginRequest>,
    ) -> Result<Response, LoginError> {
        require_trusted_origin(&headers, &state.config.trusted_origins)
            .map_err(|_| LoginError::UntrustedOrigin)?;

        let redirect_uri = req.redirect_uri;

        let verify_resp = state
            .http_client
            .post(format!("{}/oauth/login", state.config.backend_url))
            .json(&VerifyLoginRequest {
                email: &req.email,
                password: &req.password,
            })
            .send()
            .await
            .map_err(|_| LoginError::BackendUnavailable)?;
        if verify_resp.status() == StatusCode::UNAUTHORIZED {
            // A plain form POST, not a fetch -- so a friendly bounce back to the
            // login page (rather than a bare 401 body) is what the browser shows.
            let sep = if req.next.contains('?') { '&' } else { '?' };
            return Ok((
                StatusCode::SEE_OTHER,
                [(header::LOCATION, format!("{}{sep}error=1", req.next))],
            )
                .into_response());
        }
        if !verify_resp.status().is_success() {
            return Err(LoginError::BackendUnavailable);
        }
        let login_session = verify_resp
            .json::<LoginSessionResponse>()
            .await
            .map_err(|_| LoginError::BackendUnavailable)?
            .login_session;

        let cookie = complete_login(&mut state, &login_session, &redirect_uri).await?;

        Ok((
            StatusCode::SEE_OTHER,
            [(header::LOCATION, redirect_uri), (header::SET_COOKIE, cookie)],
            Body::empty(),
        )
            .into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue};
    use axum::Form;

    use crate::config::Config;
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
    async fn rejects_an_untrusted_origin_before_contacting_backend() {
        // backend_url above is unreachable -- a FORBIDDEN result (rather than a
        // BAD_GATEWAY from trying to reach it) proves the origin check runs first.
        let state = state_with_trusted_origins(vec!["http://login.test".to_string()]);
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("http://evil.test"));
        let req = LoginRequest {
            email: "alice".to_string(),
            password: "hunter2".to_string(),
            redirect_uri: "http://admin.test/".to_string(),
            next: "http://login.test/".to_string(),
        };

        let result = start_login(State(state), headers, Form(req)).await;

        assert_eq!(result.err(), Some(LoginError::UntrustedOrigin));
    }
}
