pub(crate) use controller::callback;

mod controller {
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{AppendHeaders, IntoResponse, Response};
    use common::extract::ApiQuery;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;

    use crate::hydra::HydraError;
    use crate::server::AppState;
    use crate::server::cookie::{build_cookie, clear_cookie, extract_cookie};
    use crate::server::login_cookie::PendingLogin;

    use super::service::{self, CallbackServiceError, Returned};

    /// What Hydra appends to the redirect: a `code`, or an `error` when the login failed.
    #[derive(Deserialize)]
    pub(crate) struct CallbackQuery {
        pub(super) code: Option<String>,
        pub(super) state: Option<String>,
        pub(super) error: Option<String>,
    }

    impl From<CallbackQuery> for Returned {
        /// An `error` wins over a `code`.
        fn from(query: CallbackQuery) -> Self {
            let state = query.state;
            match (query.error, query.code) {
                (Some(error), _) => Returned::Refused { error, state },
                (None, Some(code)) => Returned::Code { code, state },
                (None, None) => Returned::Empty { state },
            }
        }
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum CallbackError {
        #[error("no login in progress")]
        #[error_response(StatusCode::BAD_REQUEST, details = "no login in progress")]
        NoLoginInProgress,
        #[error("state does not match the login in progress")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid state")]
        StateMismatch,
        #[error("the login was refused")]
        #[error_response(StatusCode::BAD_REQUEST, details = "the login was refused")]
        LoginRefused,
        #[error("no authorization code")]
        #[error_response(StatusCode::BAD_REQUEST, details = "no authorization code")]
        MissingCode,
        #[error("redirect_uri is not allowed")]
        #[error_response(StatusCode::BAD_REQUEST, details = "redirect_uri is not allowed")]
        InvalidRedirectUri,
        #[error("token exchange failed")]
        #[error_response(StatusCode::BAD_REQUEST, details = "token exchange failed")]
        TokenExchangeFailed,
        #[error("identity provider returned an invalid response")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "identity provider returned an invalid response"
        )]
        InvalidTokenResponse,
        #[error("identity provider unavailable")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "identity provider unavailable")]
        IdentityProviderUnavailable,
    }

    impl From<CallbackServiceError> for CallbackError {
        fn from(err: CallbackServiceError) -> Self {
            match &err {
                CallbackServiceError::StateMismatch => {
                    tracing::warn!("callback refused: state does not match the login in progress");
                }
                CallbackServiceError::NoLoginInProgress | CallbackServiceError::MissingCode => {
                    tracing::info!(%err, "callback refused");
                }
                CallbackServiceError::LoginRefused { error } => {
                    tracing::info!(error, "hydra refused the login");
                }
                CallbackServiceError::RedirectNotAllowed => {
                    tracing::warn!(
                        "callback refused: the login's redirect_uri is not on the allowlist"
                    );
                }
                CallbackServiceError::Exchange(HydraError::Misconfigured { .. }) => {
                    tracing::error!(%err, "callback failed: hydra refused bff's client credentials");
                }
                CallbackServiceError::Exchange(_)
                | CallbackServiceError::IdToken(_)
                | CallbackServiceError::Missing(_) => {
                    tracing::warn!(%err, "callback failed");
                }
            }
            match err {
                CallbackServiceError::NoLoginInProgress => CallbackError::NoLoginInProgress,
                CallbackServiceError::StateMismatch => CallbackError::StateMismatch,
                CallbackServiceError::LoginRefused { .. } => CallbackError::LoginRefused,
                CallbackServiceError::MissingCode => CallbackError::MissingCode,
                CallbackServiceError::RedirectNotAllowed => CallbackError::InvalidRedirectUri,
                CallbackServiceError::Exchange(HydraError::Rejected { .. }) => {
                    CallbackError::TokenExchangeFailed
                }
                CallbackServiceError::Exchange(_) => CallbackError::IdentityProviderUnavailable,
                CallbackServiceError::IdToken(_) | CallbackServiceError::Missing(_) => {
                    CallbackError::InvalidTokenResponse
                }
            }
        }
    }

    /// Where Hydra sends the browser back to. Checks `state` against the login cookie,
    /// redeems the code (PKCE, `client_secret_basic`), verifies the id_token, and starts the
    /// session: the browser gets only its id, in `wa_session`, and goes on to the
    /// `redirect_uri` it started the login with.
    pub(crate) async fn callback(
        State(mut state): State<AppState>,
        headers: HeaderMap,
        ApiQuery(query): ApiQuery<CallbackQuery>,
    ) -> Result<Response, CallbackError> {
        let pending = extract_cookie(&headers, &state.config.login_cookie())
            .and_then(|value| PendingLogin::from_cookie_value(&value));
        let previous_session = extract_cookie(&headers, &state.config.session_cookie());

        let started = service::complete(
            &mut state,
            pending,
            query.into(),
            previous_session.as_deref(),
        )
        .await?;

        let secure = state.config.secure_cookies();
        let session_cookie = build_cookie(
            &state.config.session_cookie(),
            &started.session_id,
            "/",
            started.session_max_age_secs,
            secure,
        );
        Ok((
            StatusCode::SEE_OTHER,
            AppendHeaders([
                (header::LOCATION, started.redirect_uri),
                (header::SET_COOKIE, session_cookie),
                (
                    header::SET_COOKIE,
                    clear_cookie(&state.config.login_cookie(), "/", secure),
                ),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ]),
        )
            .into_response())
    }
}

mod service {
    use secrecy::ExposeSecret;
    use thiserror::Error;
    use uuid::Uuid;

    use crate::hydra::{HydraError, IdTokenError};
    use crate::model::session::{MAX_SESSION_LIFETIME, SessionData};
    use crate::server::AppState;
    use crate::server::login_cookie::PendingLogin;
    use crate::server::secrets::constant_time_eq;
    use crate::storage::SessionStorage;
    use chrono::Utc;

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum CallbackServiceError {
        #[error("no login in progress")]
        NoLoginInProgress,
        #[error("state does not match the login in progress")]
        StateMismatch,
        /// Hydra redirected back with an `error`; `error` is its code, which the browser
        /// controls, so it is only ever logged.
        #[error("hydra refused the login")]
        LoginRefused { error: String },
        #[error("callback has no code")]
        MissingCode,
        #[error("the login's redirect_uri is not on the allowlist")]
        RedirectNotAllowed,
        #[error("code exchange failed: {0}")]
        Exchange(#[from] HydraError),
        #[error("id_token rejected: {0}")]
        IdToken(#[from] IdTokenError),
        #[error("hydra's token response has no {0}")]
        Missing(&'static str),
    }

    /// What the callback request's query says, one variant per case; each carries the `state`.
    pub(crate) enum Returned {
        Code {
            code: String,
            state: Option<String>,
        },
        Refused {
            error: String,
            state: Option<String>,
        },
        Empty {
            state: Option<String>,
        },
    }

    impl Returned {
        fn state(&self) -> Option<&str> {
            match self {
                Self::Code { state, .. } | Self::Refused { state, .. } | Self::Empty { state } => {
                    state.as_deref()
                }
            }
        }
    }

    pub(crate) struct StartedSession {
        pub(crate) session_id: String,
        pub(crate) session_max_age_secs: i64,
        /// Where to send the browser now.
        pub(crate) redirect_uri: String,
    }

    /// Finishes the login `pending` describes with what Hydra sent back, and saves the session.
    /// The session the browser logged in over, `previous_session`, ends with it.
    pub(crate) async fn complete(
        state: &mut AppState,
        pending: Option<PendingLogin>,
        returned: Returned,
        previous_session: Option<&str>,
    ) -> Result<StartedSession, CallbackServiceError> {
        let pending = pending.ok_or(CallbackServiceError::NoLoginInProgress)?;
        // Before anything else: a code arriving with someone else's state is not ours to redeem.
        let state_matches = returned.state().is_some_and(|returned| {
            constant_time_eq(returned.as_bytes(), pending.state.as_bytes())
        });
        if !state_matches {
            return Err(CallbackServiceError::StateMismatch);
        }
        let code = match returned {
            Returned::Refused { error, .. } => {
                return Err(CallbackServiceError::LoginRefused { error });
            }
            Returned::Empty { .. } => return Err(CallbackServiceError::MissingCode),
            Returned::Code { code, .. } => code,
        };
        // The cookie is the browser's to edit, so the destination is checked again.
        if !state.config.allows_redirect_uri(&pending.redirect_uri) {
            return Err(CallbackServiceError::RedirectNotAllowed);
        }

        let tokens = state.hydra.exchange_code(&code, &pending.verifier).await?;
        let id_token = tokens
            .id_token
            .ok_or(CallbackServiceError::Missing("id_token"))?;
        let refresh_token = tokens
            .refresh_token
            .ok_or(CallbackServiceError::Missing("refresh_token"))?;
        let verified = state
            .hydra
            .verify_id_token(
                id_token.expose_secret(),
                tokens.access_token.expose_secret(),
                &pending.nonce,
            )
            .await?;

        if verified.sid.is_none() {
            tracing::warn!(
                "id_token has no sid: back-channel logout by session can't end this session"
            );
        }
        let refresh_ttl = state.hydra.refresh_ttl();
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let evicted = state
            .sessions
            .save_session(
                session_id.clone(),
                SessionData {
                    access_token: tokens.access_token,
                    refresh_token,
                    id_token,
                    expires_at: now + tokens.expires_in,
                    created_at: now,
                    refresh_expires_at: now + refresh_ttl,
                    user_id: verified.user_id,
                    sid: verified.sid,
                },
            )
            .await;
        state.revoke_refresh_tokens(evicted).await;
        if let Some(previous) = previous_session {
            state.end_session(previous).await;
        }
        Ok(StartedSession {
            session_id,
            session_max_age_secs: session_max_age_secs(refresh_ttl),
            redirect_uri: pending.redirect_uri,
        })
    }

    /// The cookie never outlives the refresh token or the absolute session lifetime.
    fn session_max_age_secs(refresh_ttl: chrono::Duration) -> i64 {
        refresh_ttl.min(MAX_SESSION_LIFETIME).num_seconds()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::Config;
        use chrono::Duration;

        fn state() -> AppState {
            AppState::new(Config {
                redirect_uri_allowlist: vec!["https://app.test/".into()],
                hydra_internal_url: "http://127.0.0.1:1".into(),
                ..Config::default()
            })
            .unwrap()
        }

        fn pending(redirect_uri: &str) -> PendingLogin {
            PendingLogin {
                state: "s1".into(),
                verifier: "v".into(),
                nonce: "n".into(),
                redirect_uri: redirect_uri.into(),
            }
        }

        fn code(state: Option<&str>) -> Returned {
            Returned::Code {
                code: "c".into(),
                state: state.map(str::to_string),
            }
        }

        async fn outcome(
            pending: Option<PendingLogin>,
            returned: Returned,
        ) -> CallbackServiceError {
            complete(&mut state(), pending, returned, None)
                .await
                .err()
                .expect("callback must be refused")
        }

        #[tokio::test]
        async fn no_pending_login_is_refused() {
            assert_eq!(
                outcome(None, code(Some("s1"))).await,
                CallbackServiceError::NoLoginInProgress
            );
        }

        #[tokio::test]
        async fn a_missing_or_foreign_state_is_refused_for_every_kind_of_return() {
            let p = || Some(pending("https://app.test/"));
            for returned in [
                code(None),
                code(Some("other")),
                Returned::Refused {
                    error: "access_denied".into(),
                    state: Some("other".into()),
                },
                Returned::Empty { state: None },
            ] {
                assert_eq!(
                    outcome(p(), returned).await,
                    CallbackServiceError::StateMismatch
                );
            }
        }

        #[tokio::test]
        async fn a_refusal_or_an_empty_return_with_our_state_says_why() {
            let p = || Some(pending("https://app.test/"));
            let refused = Returned::Refused {
                error: "access_denied".into(),
                state: Some("s1".into()),
            };
            assert_eq!(
                outcome(p(), refused).await,
                CallbackServiceError::LoginRefused {
                    error: "access_denied".into()
                }
            );
            assert_eq!(
                outcome(
                    p(),
                    Returned::Empty {
                        state: Some("s1".into())
                    }
                )
                .await,
                CallbackServiceError::MissingCode
            );
        }

        #[tokio::test]
        async fn a_redirect_uri_off_the_allowlist_is_refused_before_the_code_is_redeemed() {
            assert_eq!(
                outcome(Some(pending("https://evil.test/")), code(Some("s1"))).await,
                CallbackServiceError::RedirectNotAllowed
            );
        }

        #[test]
        fn the_cookie_lives_as_long_as_the_refresh_token_up_to_the_session_cap() {
            assert_eq!(session_max_age_secs(Duration::hours(1)), 3600);
            assert_eq!(
                session_max_age_secs(MAX_SESSION_LIFETIME + Duration::days(1)),
                MAX_SESSION_LIFETIME.num_seconds()
            );
        }
    }
}
