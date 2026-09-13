pub(crate) use controller::start_register;

mod controller {
    use axum::extract::State;
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::Form;
    use serde::{Deserialize, Serialize};

    use crate::server::origin_check::require_trusted_origin;
    use crate::server::AppState;

    #[derive(Deserialize)]
    pub(crate) struct RegisterRequest {
        pub(super) identifier: String,
        pub(super) password: String,
        /// Where to send the browser back to once registration is done, success or
        /// not -- supplied by the login page's own form, not user-typed input.
        pub(super) next: String,
    }

    #[derive(Serialize)]
    struct BackendRegisterRequest<'a> {
        identifier: &'a str,
        password: &'a str,
    }

    /// Forwards registration to backend's `/register`, then bounces the browser
    /// back to `next` (the login page) -- `?error=1` appended when it failed, so
    /// the static registration page can show a message without any JS fetch/CORS
    /// dance.
    pub(crate) async fn start_register(
        State(state): State<AppState>,
        headers: HeaderMap,
        Form(req): Form<RegisterRequest>,
    ) -> Result<Response, StatusCode> {
        require_trusted_origin(&headers, &state.config.trusted_origins)?;

        let resp = state
            .http_client
            .post(format!("{}/register", state.config.backend_url))
            .json(&BackendRegisterRequest {
                identifier: &req.identifier,
                password: &req.password,
            })
            .send()
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;

        let location = if resp.status().is_success() {
            req.next
        } else if resp.status().is_client_error() {
            let sep = if req.next.contains('?') { '&' } else { '?' };
            format!("{}{sep}error=1", req.next)
        } else {
            return Err(StatusCode::BAD_GATEWAY);
        };

        Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
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
    }

    #[tokio::test]
    async fn rejects_an_untrusted_origin_before_contacting_backend() {
        // backend_url above is unreachable -- a FORBIDDEN result (rather than a
        // BAD_GATEWAY from trying to reach it) proves the origin check runs first.
        let state = state_with_trusted_origins(vec!["http://login.test".to_string()]);
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("http://evil.test"));
        let req = RegisterRequest {
            identifier: "alice".to_string(),
            password: "hunter2".to_string(),
            next: "http://login.test/".to_string(),
        };

        let result = start_register(State(state), headers, Form(req)).await;

        assert_eq!(result.err(), Some(StatusCode::FORBIDDEN));
    }
}
