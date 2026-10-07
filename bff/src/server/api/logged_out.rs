pub(crate) use controller::logged_out;

mod controller {
    use axum::extract::State;
    use axum::http::{StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use common::extract::ApiQuery;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;

    use crate::server::AppState;

    use super::service::{self, LoggedOutServiceError};

    /// What Hydra appends to the redirect: the `state` the end-session request carried.
    #[derive(Deserialize)]
    pub(crate) struct LoggedOutQuery {
        pub(super) state: Option<String>,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum LoggedOutError {
        #[error("no destination to send the browser to")]
        #[error_response(StatusCode::BAD_REQUEST, details = "no destination")]
        NoDestination,
    }

    impl From<LoggedOutServiceError> for LoggedOutError {
        fn from(err: LoggedOutServiceError) -> Self {
            match err {
                LoggedOutServiceError::NoDestination => {
                    // Not logged with the state: it is whatever the browser sent.
                    tracing::info!("logged-out refused: no allowed destination and no default");
                    LoggedOutError::NoDestination
                }
            }
        }
    }

    /// Where Hydra sends the browser once it has ended its session: on to the app's
    /// destination, which `POST /logout` handed Hydra as `state`. Anyone can send a browser
    /// here with any `state`, so it is only followed when it is on the allowlist.
    pub(crate) async fn logged_out(
        State(state): State<AppState>,
        ApiQuery(query): ApiQuery<LoggedOutQuery>,
    ) -> Result<Response, LoggedOutError> {
        let destination = service::destination(&state, query.state.as_deref())?;
        Ok((
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, destination),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
        )
            .into_response())
    }
}

mod service {
    use thiserror::Error;

    use crate::server::AppState;

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum LoggedOutServiceError {
        #[error("no allowed destination and no default")]
        NoDestination,
    }

    /// The allowlisted `state`, else the default destination, else nothing.
    pub(crate) fn destination(
        state: &AppState,
        requested: Option<&str>,
    ) -> Result<String, LoggedOutServiceError> {
        requested
            .filter(|uri| state.config.allows_redirect_uri(uri))
            .or(state.config.default_redirect_uri.as_deref())
            .map(str::to_string)
            .ok_or(LoggedOutServiceError::NoDestination)
    }
}

#[cfg(test)]
mod tests {
    use super::service::*;
    use crate::config::Config;
    use crate::server::AppState;

    fn state(default: Option<&str>) -> AppState {
        AppState::new(Config {
            redirect_uri_allowlist: vec!["https://app.test/".into()],
            default_redirect_uri: default.map(str::to_string),
            ..Config::default()
        })
        .unwrap()
    }

    #[test]
    fn an_allowlisted_state_is_the_destination() {
        let state = state(Some("https://app.test/default"));
        assert_eq!(
            destination(&state, Some("https://app.test/")).unwrap(),
            "https://app.test/"
        );
    }

    #[test]
    fn a_foreign_or_missing_state_falls_back_to_the_default() {
        let state = state(Some("https://app.test/default"));
        for requested in [Some("https://evil.test/"), None] {
            assert_eq!(
                destination(&state, requested).unwrap(),
                "https://app.test/default"
            );
        }
    }

    #[test]
    fn a_foreign_state_with_no_default_is_refused() {
        assert_eq!(
            destination(&state(None), Some("https://evil.test/")),
            Err(LoggedOutServiceError::NoDestination)
        );
    }
}
