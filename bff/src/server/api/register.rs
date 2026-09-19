pub(crate) use controller::start_register;
pub(crate) use controller::start_register_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::State;
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::Form;
    use schemars::JsonSchema;
    use serde::Deserialize;
    use std::collections::HashMap;
    use thiserror::Error;
    use common_macros::ErrorResponses;

    use crate::server::origin_check::require_trusted_origin;
    use crate::server::AppState;

    use super::service::{self, RegisterOutcome, RegisterServiceError};

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct RegisterRequest {
        pub(super) email: String,
        pub(super) password: String,
        /// Where to land once registered and auto-logged-in.
        pub(super) redirect_uri: String,
        /// Where to send the browser back to if registration itself fails --
        /// supplied by the login page's own form, not user-typed input.
        pub(super) next: String,
        /// Anything beyond the fields above -- e.g. extra `<input>`s a
        /// deployer added to `register.html`. Forwarded to backend as-is;
        /// backend decides (via its own configured extra-data handler)
        /// whether these are accepted at all.
        #[serde(flatten)]
        pub(super) extra: HashMap<String, String>,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum RegisterError {
        #[error("request did not come from a trusted origin")]
        #[error_response(StatusCode::FORBIDDEN, details = "request did not come from a trusted origin")]
        UntrustedOrigin,
        #[error("backend returned an unexpected response")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "backend returned an unexpected response")]
        BackendUnavailable,
    }

    impl From<RegisterServiceError> for RegisterError {
        fn from(err: RegisterServiceError) -> Self {
            match err {
                RegisterServiceError::BackendUnavailable => RegisterError::BackendUnavailable,
            }
        }
    }

    // OpenAPI documentation for this route.
    pub(crate) fn start_register_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("register")
            .summary("Register a new user and log them in")
            .description(
                "Forwards to backend's /register, then auto-logs the new user in. Any fields \
                 beyond email/password/redirect_uri/next are forwarded to backend as-is, which \
                 in turn forwards them to its own configured extra-data handler.",
            )
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

        match service::register(&mut state, &req.email, &req.password, req.extra).await? {
            RegisterOutcome::Rejected => {
                let sep = if req.next.contains('?') { '&' } else { '?' };
                let location = format!("{}{sep}error=1", req.next);
                Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
            }
            RegisterOutcome::Created => {
                let response = match service::auto_login(&mut state, &req.email, &req.password, &req.redirect_uri).await {
                    Some(cookie) => {
                        (StatusCode::SEE_OTHER, [(header::LOCATION, req.redirect_uri), (header::SET_COOKIE, cookie)])
                            .into_response()
                    }
                    None => (StatusCode::SEE_OTHER, [(header::LOCATION, req.next)]).into_response(),
                };
                Ok(response)
            }
        }
    }
}

mod service {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use thiserror::Error;

    use crate::server::api::complete_login::complete_login;
    use crate::server::AppState;

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum RegisterServiceError {
        #[error("backend returned an unexpected response")]
        BackendUnavailable,
    }

    #[derive(Serialize)]
    struct BackendCredentials<'a> {
        email: &'a str,
        password: &'a str,
        #[serde(flatten)]
        extra: HashMap<String, String>,
    }

    #[derive(Deserialize)]
    struct LoginSessionResponse {
        login_session: String,
    }

    pub(crate) enum RegisterOutcome {
        Created,
        /// Backend rejected the registration -- bad/taken email, or (since
        /// backend now also validates extra fields) unsupported/rejected
        /// extra data. Every case bounces to the same `?error=1` page today;
        /// distinguishing them would need backend's error code threaded
        /// through, which register.html's static copy doesn't support yet.
        Rejected,
    }

    /// Forwards registration to backend's `/register`.
    pub(crate) async fn register(
        state: &mut AppState,
        email: &str,
        password: &str,
        extra: HashMap<String, String>,
    ) -> Result<RegisterOutcome, RegisterServiceError> {
        let resp = state
            .http_client
            .post(format!("{}/register", state.config.backend_url))
            .json(&BackendCredentials { email, password, extra })
            .send()
            .await
            .map_err(|_| RegisterServiceError::BackendUnavailable)?;

        if resp.status().is_client_error() {
            return Ok(RegisterOutcome::Rejected);
        }
        if !resp.status().is_success() {
            return Err(RegisterServiceError::BackendUnavailable);
        }

        Ok(RegisterOutcome::Created)
    }

    /// Verifies the just-registered credentials against backend's
    /// `/oauth/login`, then drives the same PKCE exchange `start_login` uses.
    /// `None` on any failure -- the caller falls back to sending the user to
    /// the login page instead. Returns the `Set-Cookie` header value for the
    /// new session.
    pub(crate) async fn auto_login(state: &mut AppState, email: &str, password: &str, redirect_uri: &str) -> Option<String> {
        let verify_resp = state
            .http_client
            .post(format!("{}/oauth/login", state.config.backend_url))
            .json(&BackendCredentials { email, password, extra: HashMap::new() })
            .send()
            .await
            .ok()?;
        if !verify_resp.status().is_success() {
            return None;
        }
        let login_session = verify_resp.json::<LoginSessionResponse>().await.ok()?.login_session;

        complete_login(state, &login_session, redirect_uri).await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue};
    use axum::Form;
    use std::collections::HashMap;

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
            docs_enabled: false,
        })
        .expect("valid app state")
    }

    // Named fields + `#[serde(flatten)] extra: HashMap<String, String>` was
    // suspected of hitting a long-standing `serde_urlencoded` bug (flatten
    // into a map alongside other named fields silently fails) -- checked
    // empirically and found not to reproduce on the version this workspace
    // resolves to. This is that check, kept as a regression test: it drives
    // the real `Form` extractor (not a hand-rolled deserialize call), so a
    // future dependency bump reintroducing the bug fails here directly
    // instead of surfacing as a confusing `extra` field silently going empty.
    #[tokio::test]
    async fn form_extractor_flattens_extra_fields_alongside_named_ones() {
        use axum::body::Body;
        use axum::extract::FromRequest;
        use axum::http::Request;

        let state = state_with_trusted_origins(vec![]);
        let request = Request::builder()
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(
                "email=alice%40example.com&password=hunter2&redirect_uri=http%3A%2F%2Fx&next=http%3A%2F%2Fy&company=Acme&plan=pro",
            ))
            .expect("valid request");

        let Form(req) = Form::<RegisterRequest>::from_request(request, &state)
            .await
            .expect("form deserializes");

        assert_eq!(req.email, "alice@example.com");
        assert_eq!(req.password, "hunter2");
        assert_eq!(req.redirect_uri, "http://x");
        assert_eq!(req.next, "http://y");
        assert_eq!(
            req.extra,
            HashMap::from([("company".to_string(), "Acme".to_string()), ("plan".to_string(), "pro".to_string())])
        );
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
            extra: HashMap::new(),
        };

        let result = start_register(State(state), headers, Form(req)).await;

        assert_eq!(result.err(), Some(RegisterError::UntrustedOrigin));
    }
}
