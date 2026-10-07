pub(crate) use controller::logout;

mod controller {
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use common::extract::ApiQuery;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;

    use crate::server::AppState;
    use crate::server::cookie::{clear_cookie, extract_cookie};
    use crate::server::origin_check::require_trusted_origin;

    use super::service;

    #[derive(Deserialize)]
    pub(crate) struct LogoutQuery {
        /// Where Hydra sends the browser after the logout; used only when on the allowlist.
        pub(super) redirect_uri: Option<String>,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum LogoutError {
        #[error("request did not come from a trusted origin")]
        #[error_response(
            StatusCode::FORBIDDEN,
            details = "request did not come from a trusted origin"
        )]
        UntrustedOrigin,
    }

    /// Ends the browser's session -- dropped here, its refresh token revoked at Hydra -- and
    /// sends the browser to Hydra's logout, with the session's id_token as the hint that lets
    /// Hydra skip its confirmation page. A `POST` from a trusted origin only: the session
    /// cookie rides along on any cross-site request, so any site could otherwise log users out.
    /// A `redirect_uri` off the allowlist is dropped, never a reason to leave the user logged in.
    pub(crate) async fn logout(
        State(mut state): State<AppState>,
        headers: HeaderMap,
        ApiQuery(query): ApiQuery<LogoutQuery>,
    ) -> Result<Response, LogoutError> {
        require_trusted_origin(&headers, &state.trusted_origins).map_err(|error| {
            tracing::warn!(%error, "logout rejected");
            LogoutError::UntrustedOrigin
        })?;
        let session_id = extract_cookie(&headers, &state.config.session_cookie());

        let hydra_logout_url = service::logout(
            &mut state,
            session_id.as_deref(),
            query.redirect_uri.as_deref(),
        )
        .await;

        let cleared = clear_cookie(
            &state.config.session_cookie(),
            "/",
            state.config.secure_cookies(),
        );
        Ok((
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, hydra_logout_url),
                (header::SET_COOKIE, cleared),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
        )
            .into_response())
    }
}

mod service {
    use secrecy::ExposeSecret;

    use crate::server::AppState;

    /// Drops the session and revokes its refresh token, and returns where to send the
    /// browser. A browser with no (or an unknown) session still goes to Hydra, which ends
    /// its own login session, only without the hint.
    pub(crate) async fn logout(
        state: &mut AppState,
        session_id: Option<&str>,
        redirect_uri: Option<&str>,
    ) -> String {
        let session = match session_id {
            Some(id) => state.end_session(id).await,
            None => None,
        };
        let redirect_uri = redirect_uri.filter(|uri| {
            let allowed = state.config.allows_redirect_uri(uri);
            if !allowed {
                tracing::info!("logout redirect_uri is not on the allowlist, dropped");
            }
            allowed
        });
        let hint = session
            .as_ref()
            .map(|session| session.id_token.expose_secret());
        // Hydra only returns the browser to bff itself; the app's destination rides along as `state`.
        state.hydra.logout_url(hint, redirect_uri)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::Config;
        use crate::model::session::SessionData;
        use crate::storage::SessionStorage;
        use chrono::{Duration, Utc};
        use secrecy::SecretString;

        fn state() -> AppState {
            AppState::new(Config {
                redirect_uri_allowlist: vec!["https://app.test/".into()],
                hydra_internal_url: "http://127.0.0.1:1".into(),
                ..Config::default()
            })
            .unwrap()
        }

        fn session() -> SessionData {
            let now = Utc::now();
            SessionData {
                access_token: SecretString::from("a"),
                refresh_token: SecretString::from("r"),
                id_token: SecretString::from("the-id-token"),
                expires_at: now + Duration::hours(1),
                created_at: now,
                refresh_expires_at: now + Duration::days(1),
                user_id: uuid::Uuid::new_v4(),
                sid: None,
            }
        }

        #[tokio::test]
        async fn a_known_session_ends_and_its_id_token_is_the_hint() {
            let mut state = state();
            state.sessions.save_session("s".into(), session()).await;

            let url = logout(&mut state, Some("s"), Some("https://app.test/")).await;

            assert!(url.contains("id_token_hint=the-id-token"), "{url}");
            assert!(url.contains("state=https%3A%2F%2Fapp.test%2F"), "{url}");
            assert!(state.sessions.get_session("s").await.is_none());
        }

        #[tokio::test]
        async fn no_session_still_goes_to_hydra_without_a_hint() {
            let mut state = state();
            for id in [None, Some("unknown")] {
                let url = logout(&mut state, id, None).await;
                assert!(url.contains("/oauth2/sessions/logout?"), "{url}");
                assert!(!url.contains("id_token_hint"), "{url}");
                assert!(!url.contains("state="), "{url}");
            }
        }

        #[tokio::test]
        async fn a_destination_off_the_allowlist_is_dropped() {
            let url = logout(&mut state(), None, Some("https://evil.test/")).await;
            assert!(!url.contains("state="), "{url}");
        }
    }
}
