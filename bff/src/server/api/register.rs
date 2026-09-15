pub(crate) use controller::start_register;

mod controller {
    use axum::extract::State;
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::Form;
    use common_macros::ErrorResponses;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::server::api::complete_login::complete_login;
    use crate::server::origin_check::require_trusted_origin;
    use crate::server::AppState;

    #[derive(Deserialize)]
    pub(crate) struct RegisterRequest {
        pub(super) email: String,
        pub(super) password: String,
        /// Where to land once registered and auto-logged-in.
        pub(super) redirect_uri: String,
        /// Where to send the browser back to if registration itself fails --
        /// supplied by the login page's own form, not user-typed input.
        pub(super) next: String,
    }

    #[derive(Serialize)]
    struct BackendCredentials<'a> {
        email: &'a str,
        password: &'a str,
    }

    #[derive(Deserialize)]
    struct LoginSessionResponse {
        login_session: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum RegisterError {
        #[error("request did not come from a trusted origin")]
        #[error_response(StatusCode::FORBIDDEN, details = "request did not come from a trusted origin")]
        UntrustedOrigin,
        #[error("backend returned an unexpected response")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "backend returned an unexpected response")]
        BackendUnavailable,
    }

    /// Forwards registration to backend's `/register`, then -- since the
    /// credentials were just typed in and verified by backend -- immediately
    /// logs the new user in the same way `start_login` would, landing on
    /// `redirect_uri` with a session cookie already set instead of bouncing
    /// back to the login page to ask for the same password again.
    ///
    /// Registration failing (bad/taken email) bounces to `next` (the
    /// registration page) with `?error=1`, as before. If registration
    /// succeeds but the auto-login step fails for some other reason, the
    /// account still exists -- rather than surface a confusing error, this
    /// falls back to `next` without `?error=1` so the user can just sign in
    /// manually.
    pub(crate) async fn start_register(
        State(mut state): State<AppState>,
        headers: HeaderMap,
        Form(req): Form<RegisterRequest>,
    ) -> Result<Response, RegisterError> {
        require_trusted_origin(&headers, &state.config.trusted_origins)
            .map_err(|_| RegisterError::UntrustedOrigin)?;

        let resp = state
            .http_client
            .post(format!("{}/register", state.config.backend_url))
            .json(&BackendCredentials {
                email: &req.email,
                password: &req.password,
            })
            .send()
            .await
            .map_err(|_| RegisterError::BackendUnavailable)?;

        if resp.status().is_client_error() {
            let sep = if req.next.contains('?') { '&' } else { '?' };
            let location = format!("{}{sep}error=1", req.next);
            return Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response());
        }
        if !resp.status().is_success() {
            return Err(RegisterError::BackendUnavailable);
        }

        Ok(auto_login(&mut state, &req).await.unwrap_or_else(|| {
            (StatusCode::SEE_OTHER, [(header::LOCATION, req.next.clone())]).into_response()
        }))
    }

    /// Verifies the just-registered credentials against backend's
    /// `/oauth/login`, then drives the same PKCE exchange `start_login` uses.
    /// `None` on any failure -- the caller falls back to sending the user to
    /// the login page instead.
    async fn auto_login(state: &mut AppState, req: &RegisterRequest) -> Option<Response> {
        let verify_resp = state
            .http_client
            .post(format!("{}/oauth/login", state.config.backend_url))
            .json(&BackendCredentials {
                email: &req.email,
                password: &req.password,
            })
            .send()
            .await
            .ok()?;
        if !verify_resp.status().is_success() {
            return None;
        }
        let login_session = verify_resp.json::<LoginSessionResponse>().await.ok()?.login_session;

        let cookie = complete_login(state, &login_session, &req.redirect_uri).await.ok()?;

        Some(
            (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, req.redirect_uri.clone()), (header::SET_COOKIE, cookie)],
            )
                .into_response(),
        )
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
            expiry_sweep_interval_secs: 60,
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
        let req = RegisterRequest {
            email: "alice".to_string(),
            password: "hunter2".to_string(),
            redirect_uri: "http://admin.test/".to_string(),
            next: "http://login.test/".to_string(),
        };

        let result = start_register(State(state), headers, Form(req)).await;

        assert_eq!(result.err(), Some(RegisterError::UntrustedOrigin));
    }
}
