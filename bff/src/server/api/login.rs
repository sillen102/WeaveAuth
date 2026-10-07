pub(crate) use controller::start_login;

mod controller {
    use axum::extract::State;
    use axum::http::{StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use common::extract::ApiQuery;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;

    use crate::server::AppState;
    use crate::server::cookie::build_cookie;
    use crate::server::login_cookie::LOGIN_COOKIE_MAX_AGE_SECS;

    use super::service::{self, LoginServiceError};

    #[derive(Deserialize)]
    pub(crate) struct LoginQuery {
        /// Where the browser goes once logged in; must be on the allowlist. `None` or
        /// empty: the configured default.
        pub(super) redirect_uri: Option<String>,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum LoginError {
        #[error("redirect_uri is not allowed")]
        #[error_response(StatusCode::BAD_REQUEST, details = "redirect_uri is not allowed")]
        InvalidRedirectUri,
    }

    impl From<LoginServiceError> for LoginError {
        fn from(err: LoginServiceError) -> Self {
            match err {
                LoginServiceError::InvalidRedirectUri => {
                    // Not logged with the value: it is whatever the caller sent.
                    tracing::info!("login refused: redirect_uri is not on the allowlist");
                    LoginError::InvalidRedirectUri
                }
            }
        }
    }

    /// Starts a login: checks the allowlist, keeps the PKCE verifier, `state` and `nonce` in a
    /// short-lived cookie and sends the browser to Hydra. The `redirect_uri` comes back to
    /// `/callback` in that cookie, where it is checked again.
    pub(crate) async fn start_login(
        State(state): State<AppState>,
        ApiQuery(query): ApiQuery<LoginQuery>,
    ) -> Result<Response, LoginError> {
        let started = service::start(&state, query.redirect_uri)?;
        let cookie = build_cookie(
            &state.config.login_cookie(),
            &started.cookie_value,
            "/",
            LOGIN_COOKIE_MAX_AGE_SECS,
            state.config.secure_cookies(),
        );
        Ok((
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, started.authorize_url),
                (header::SET_COOKIE, cookie),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
        )
            .into_response())
    }
}

mod service {
    use thiserror::Error;

    use crate::server::AppState;
    use crate::server::login_cookie::PendingLogin;

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum LoginServiceError {
        #[error("redirect_uri is not allowed")]
        InvalidRedirectUri,
    }

    pub(crate) struct StartedLogin {
        /// Where to send the browser.
        pub(crate) authorize_url: String,
        /// The value of the login cookie `/callback` needs.
        pub(crate) cookie_value: String,
    }

    /// Per RFC 6749 10.15 the final destination is only ever one the deployer listed: it is
    /// compared as an exact string, so no URL parsing can read another host into it.
    pub(crate) fn start(
        state: &AppState,
        redirect_uri: Option<String>,
    ) -> Result<StartedLogin, LoginServiceError> {
        let redirect_uri = redirect_uri
            .filter(|r| !r.is_empty())
            .or_else(|| state.config.default_redirect_uri.clone())
            .ok_or(LoginServiceError::InvalidRedirectUri)?;
        if !state.config.allows_redirect_uri(&redirect_uri) {
            return Err(LoginServiceError::InvalidRedirectUri);
        }
        let pending = PendingLogin::new(redirect_uri);
        Ok(StartedLogin {
            authorize_url: state.hydra.authorize_url(
                &pending.state,
                &pending.nonce,
                &pending.code_challenge(),
            ),
            cookie_value: pending.to_cookie_value(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use crate::config::Config;
    use crate::server::AppState;
    use axum::extract::State;
    use common::extract::ApiQuery;

    fn state() -> AppState {
        AppState::new(Config {
            redirect_uri_allowlist: vec!["https://app.test/".into()],
            ..Config::default()
        })
        .unwrap()
    }

    #[tokio::test]
    async fn a_redirect_uri_off_the_allowlist_is_the_invalid_redirect_uri_error() {
        let result = start_login(
            State(state()),
            ApiQuery(serde_json::from_str(r#"{"redirect_uri":"https://evil.test/"}"#).unwrap()),
        )
        .await;

        assert_eq!(result.err(), Some(LoginError::InvalidRedirectUri));
    }

    #[tokio::test]
    async fn an_allowlisted_redirect_uri_is_redirected_to_hydra() {
        let response = start_login(
            State(state()),
            ApiQuery(serde_json::from_str(r#"{"redirect_uri":"https://app.test/"}"#).unwrap()),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn without_a_redirect_uri_the_default_is_used() {
        let state = AppState::new(Config {
            redirect_uri_allowlist: vec!["https://app.test/".into()],
            default_redirect_uri: Some("https://app.test/".into()),
            ..Config::default()
        })
        .unwrap();

        let response = start_login(State(state), ApiQuery(serde_json::from_str("{}").unwrap()))
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
    }

    fn state_with_default() -> AppState {
        AppState::new(Config {
            redirect_uri_allowlist: vec![
                "https://app.test/".into(),
                "https://app.test/other".into(),
            ],
            default_redirect_uri: Some("https://app.test/".into()),
            ..Config::default()
        })
        .unwrap()
    }

    #[test]
    fn an_explicit_redirect_uri_wins_over_the_default() {
        let started =
            super::service::start(&state_with_default(), Some("https://app.test/other".into()))
                .unwrap();

        let pending =
            crate::server::login_cookie::PendingLogin::from_cookie_value(&started.cookie_value)
                .unwrap();
        assert_eq!(pending.redirect_uri, "https://app.test/other");
    }

    #[test]
    fn an_empty_redirect_uri_falls_back_to_the_default() {
        let started = super::service::start(&state_with_default(), Some(String::new())).unwrap();

        let pending =
            crate::server::login_cookie::PendingLogin::from_cookie_value(&started.cookie_value)
                .unwrap();
        assert_eq!(pending.redirect_uri, "https://app.test/");
    }

    #[tokio::test]
    async fn without_a_redirect_uri_and_no_default_it_is_refused() {
        let result = start_login(
            State(state()),
            ApiQuery(serde_json::from_str("{}").unwrap()),
        )
        .await;

        assert_eq!(result.err(), Some(LoginError::InvalidRedirectUri));
    }
}
