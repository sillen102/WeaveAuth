pub(crate) use controller::{confirm_password_reset, request_password_reset};

mod controller {
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use common::extract::ApiForm;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;

    use crate::server::AppState;
    use crate::server::origin_check::require_trusted_origin;

    use super::service::{self, ConfirmOutcome, PasswordResetServiceError};

    #[derive(Deserialize)]
    pub(crate) struct RequestForm {
        pub(super) email: String,
    }

    #[derive(Deserialize)]
    pub(crate) struct ConfirmForm {
        pub(super) token: String,
        pub(super) new_password: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum PasswordResetError {
        #[error("request did not come from a trusted origin")]
        #[error_response(
            StatusCode::FORBIDDEN,
            details = "request did not come from a trusted origin"
        )]
        UntrustedOrigin,
        #[error("backend returned an unexpected response")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "backend returned an unexpected response"
        )]
        BackendUnavailable,
    }

    impl From<PasswordResetServiceError> for PasswordResetError {
        fn from(err: PasswordResetServiceError) -> Self {
            tracing::warn!(%err, "password reset failed");
            match err {
                PasswordResetServiceError::BackendUnavailable(_) => Self::BackendUnavailable,
            }
        }
    }

    fn check_origin(state: &AppState, headers: &HeaderMap) -> Result<(), PasswordResetError> {
        require_trusted_origin(headers, &state.config.trusted_origins).map_err(|error| {
            tracing::warn!(%error, "request rejected");
            PasswordResetError::UntrustedOrigin
        })
    }

    /// To a fixed page on login: no caller-supplied target, so nothing to redirect elsewhere.
    fn to_login_page(state: &AppState, page_and_query: &str) -> Response {
        let location = format!("{}/{page_and_query}", state.config.login_public_url);
        (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
    }

    /// Always lands on the same "check your inbox" page: backend answers the
    /// same whether or not the address has an account.
    pub(crate) async fn request_password_reset(
        State(state): State<AppState>,
        headers: HeaderMap,
        ApiForm(req): ApiForm<RequestForm>,
    ) -> Result<Response, PasswordResetError> {
        check_origin(&state, &headers)?;
        service::request(&state, &req.email).await?;
        Ok(to_login_page(&state, "forgot-password.html?status=sent"))
    }

    /// Doesn't sign the user in: they log in with the new password, so a
    /// forged confirm can't drop someone into an account that isn't theirs.
    pub(crate) async fn confirm_password_reset(
        State(mut state): State<AppState>,
        headers: HeaderMap,
        ApiForm(req): ApiForm<ConfirmForm>,
    ) -> Result<Response, PasswordResetError> {
        check_origin(&state, &headers)?;
        Ok(
            match service::confirm(&mut state, &req.token, &req.new_password).await? {
                ConfirmOutcome::Done => to_login_page(&state, "login.html?status=password_reset"),
                // No token in the URL: the reset page kept it in sessionStorage.
                ConfirmOutcome::WeakPassword => {
                    to_login_page(&state, "reset-password.html?status=weak_password")
                }
                ConfirmOutcome::InvalidToken => {
                    to_login_page(&state, "forgot-password.html?status=invalid_token")
                }
            },
        )
    }
}

mod service {
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;
    use uuid::Uuid;

    use common::model::error_response::ErrorResponse;

    use crate::server::AppState;
    use crate::storage::SessionStorage;

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum PasswordResetServiceError {
        #[error("backend returned an unexpected response: {0}")]
        BackendUnavailable(String),
    }

    pub(crate) enum ConfirmOutcome {
        Done,
        /// The token is still good; the password needs another try.
        WeakPassword,
        /// Unknown, expired or spent: a new link is needed.
        InvalidToken,
    }

    #[derive(Serialize)]
    struct RequestBody<'a> {
        email: &'a str,
    }

    #[derive(Serialize)]
    struct ConfirmBody<'a> {
        token: &'a str,
        new_password: &'a str,
    }

    #[derive(Deserialize)]
    struct ConfirmResponse {
        user_id: Uuid,
    }

    pub(crate) async fn request(
        state: &AppState,
        email: &str,
    ) -> Result<(), PasswordResetServiceError> {
        let response = state
            .http_client
            .post(format!(
                "{}/oauth/password-reset/request",
                state.config.backend_url
            ))
            .json(&RequestBody { email })
            .send()
            .await
            .map_err(|error| {
                PasswordResetServiceError::BackendUnavailable(format!(
                    "password reset request failed: {}",
                    common::error::cause_chain(&error.without_url())
                ))
            })?;
        match response.status() {
            status if status.is_success() => Ok(()),
            status => Err(PasswordResetServiceError::BackendUnavailable(format!(
                "password reset request returned {status}"
            ))),
        }
    }

    /// A token that isn't base64url (what backend issues) is refused right
    /// here, without a backend call.
    ///
    /// A done reset ends every bff session of the user: backend already
    /// refuses their refresh tokens, and this stops the access tokens bff
    /// holds too.
    pub(crate) async fn confirm(
        state: &mut AppState,
        token: &str,
        new_password: &str,
    ) -> Result<ConfirmOutcome, PasswordResetServiceError> {
        let well_formed = !token.is_empty()
            && token.len() <= 128
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !well_formed {
            return Ok(ConfirmOutcome::InvalidToken);
        }

        let response = state
            .http_client
            .post(format!(
                "{}/oauth/password-reset/confirm",
                state.config.backend_url
            ))
            .json(&ConfirmBody {
                token,
                new_password,
            })
            .send()
            .await
            .map_err(|error| {
                PasswordResetServiceError::BackendUnavailable(format!(
                    "password reset confirm failed: {}",
                    common::error::cause_chain(&error.without_url())
                ))
            })?;
        match response.status() {
            status if status.is_success() => {
                let reset: ConfirmResponse = response.json().await.map_err(|error| {
                    PasswordResetServiceError::BackendUnavailable(format!(
                        "password reset confirm response unreadable: {}",
                        common::error::cause_chain(&error.without_url())
                    ))
                })?;
                state.sessions.revoke_all_for_user(reset.user_id).await;
                Ok(ConfirmOutcome::Done)
            }
            StatusCode::BAD_REQUEST => {
                let weak = response
                    .json::<ErrorResponse>()
                    .await
                    // Pinned by backend's `password_reset_confirm_reports_a_weak_password_by_reason_over_http`.
                    .is_ok_and(|body| body.reason == "WeakPassword");
                Ok(if weak {
                    ConfirmOutcome::WeakPassword
                } else {
                    ConfirmOutcome::InvalidToken
                })
            }
            status => Err(PasswordResetServiceError::BackendUnavailable(format!(
                "password reset confirm returned {status}"
            ))),
        }
    }
}
