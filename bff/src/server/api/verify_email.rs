pub(crate) use controller::{resend_verification, verify_email};

mod controller {
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{AppendHeaders, IntoResponse, Response};
    use common::extract::ApiForm;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;

    use crate::server::AppState;
    use crate::server::api::complete_login::CompleteLoginServiceError;
    use crate::server::cookie::extract_cookie;
    use crate::server::origin_check::{is_safe_redirect_target, require_trusted_origin};
    use crate::server::verification::{VERIFY_COOKIE, clear_verification_cookie};

    use super::service::{self, CodeOutcome, ResendOutcome, VerifyEmailServiceError};

    #[derive(Deserialize)]
    pub(crate) struct VerifyEmailRequest {
        pub(super) code: String,
        /// Where the user was headed, handed on to the login that completes
        /// once the code is right. Backend allowlist-checks it.
        pub(super) redirect_uri: String,
        /// The login page to bounce back to, supplied by its form.
        pub(super) next: String,
    }

    #[derive(Deserialize)]
    pub(crate) struct ResendRequest {
        pub(super) next: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum VerifyEmailError {
        #[error("request did not come from a trusted origin")]
        #[error_response(
            StatusCode::FORBIDDEN,
            details = "request did not come from a trusted origin"
        )]
        UntrustedOrigin,
        #[error("next is not a same-origin path or a trusted origin")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "next is not a same-origin path or a trusted origin"
        )]
        InvalidNext,
        #[error("redirect_uri is not allowed")]
        #[error_response(StatusCode::BAD_REQUEST, details = "redirect_uri is not allowed")]
        InvalidRedirectUri,
        #[error("token exchange failed")]
        #[error_response(StatusCode::BAD_REQUEST, details = "token exchange failed")]
        TokenExchangeFailed,
        #[error("backend returned an unexpected response")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "backend returned an unexpected response"
        )]
        BackendUnavailable,
    }

    impl From<VerifyEmailServiceError> for VerifyEmailError {
        fn from(err: VerifyEmailServiceError) -> Self {
            tracing::warn!(%err, "email verification failed");
            match err {
                VerifyEmailServiceError::BackendUnavailable(_) => Self::BackendUnavailable,
                VerifyEmailServiceError::LoginFailed(
                    CompleteLoginServiceError::InvalidRedirectUri,
                ) => Self::InvalidRedirectUri,
                VerifyEmailServiceError::LoginFailed(
                    CompleteLoginServiceError::TokenExchangeFailed(_),
                ) => Self::TokenExchangeFailed,
                VerifyEmailServiceError::LoginFailed(
                    CompleteLoginServiceError::BackendUnavailable(_),
                ) => Self::BackendUnavailable,
            }
        }
    }

    /// Back to the login page with `?status=...`.
    fn bounce(next: &str, status: &str) -> Response {
        let sep = if next.contains('?') { '&' } else { '?' };
        (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, format!("{next}{sep}status={status}"))],
        )
            .into_response()
    }

    /// Like `bounce`, and drops the verification cookie: backend no longer
    /// knows the session, so keeping it would only repeat the failure.
    fn bounce_session_expired(state: &AppState, next: &str) -> Response {
        let mut response = bounce(next, "session_expired");
        if let Ok(value) = clear_verification_cookie(&state.config).parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        response
    }

    fn check_request(
        state: &AppState,
        headers: &HeaderMap,
        next: &str,
    ) -> Result<(), VerifyEmailError> {
        require_trusted_origin(headers, &state.config.trusted_origins).map_err(|error| {
            tracing::warn!(%error, "request rejected");
            VerifyEmailError::UntrustedOrigin
        })?;
        if !is_safe_redirect_target(next, &state.config.trusted_origins) {
            return Err(VerifyEmailError::InvalidNext);
        }
        Ok(())
    }

    /// Submits the 6-digit code with the restricted verification session the
    /// login handed out (in its own cookie, sent to this path only). A right
    /// code makes backend release the login session it withheld, which this
    /// completes into a real session on the spot -- so the user ends up where
    /// they were going without logging in a second time.
    pub(crate) async fn verify_email(
        State(mut state): State<AppState>,
        headers: HeaderMap,
        ApiForm(req): ApiForm<VerifyEmailRequest>,
    ) -> Result<Response, VerifyEmailError> {
        check_request(&state, &headers, &req.next)?;
        let Some(verification_session) = extract_cookie(&headers, VERIFY_COOKIE) else {
            return Ok(bounce_session_expired(&state, &req.next));
        };

        match service::confirm(
            &mut state,
            &verification_session,
            &req.code,
            &req.redirect_uri,
        )
        .await?
        {
            CodeOutcome::LoggedIn { cookie } => Ok((
                StatusCode::SEE_OTHER,
                AppendHeaders([
                    (header::SET_COOKIE, cookie),
                    (header::SET_COOKIE, clear_verification_cookie(&state.config)),
                ]),
                [(header::LOCATION, req.redirect_uri)],
            )
                .into_response()),
            CodeOutcome::InvalidCode => Ok(bounce(&req.next, "invalid")),
            CodeOutcome::SessionExpired => Ok(bounce_session_expired(&state, &req.next)),
        }
    }

    pub(crate) async fn resend_verification(
        State(state): State<AppState>,
        headers: HeaderMap,
        ApiForm(req): ApiForm<ResendRequest>,
    ) -> Result<Response, VerifyEmailError> {
        check_request(&state, &headers, &req.next)?;
        let Some(verification_session) = extract_cookie(&headers, VERIFY_COOKIE) else {
            return Ok(bounce_session_expired(&state, &req.next));
        };

        match service::resend(&state, &verification_session).await? {
            ResendOutcome::Accepted => Ok(bounce(&req.next, "sent")),
            ResendOutcome::SessionExpired => Ok(bounce_session_expired(&state, &req.next)),
        }
    }
}

mod service {
    use axum::http::StatusCode;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::server::AppState;
    use crate::server::api::complete_login::{CompleteLoginServiceError, complete_login};

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum VerifyEmailServiceError {
        #[error("backend returned an unexpected response: {0}")]
        BackendUnavailable(String),
        #[error("completing the login failed: {0}")]
        LoginFailed(#[from] CompleteLoginServiceError),
    }

    pub(crate) enum CodeOutcome {
        /// `Set-Cookie` header value for the new session.
        LoggedIn { cookie: String },
        /// Wrong, expired or used-up code.
        InvalidCode,
        /// Backend doesn't know the verification session (any more).
        SessionExpired,
    }

    pub(crate) enum ResendOutcome {
        Accepted,
        SessionExpired,
    }

    #[derive(Serialize)]
    struct ConfirmBody<'a> {
        verification_session: &'a str,
        code: &'a str,
    }

    #[derive(Deserialize)]
    struct ConfirmResponse {
        login_session: String,
    }

    #[derive(Serialize)]
    struct RequestBody<'a> {
        verification_session: &'a str,
    }

    pub(crate) async fn confirm(
        state: &mut AppState,
        verification_session: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<CodeOutcome, VerifyEmailServiceError> {
        let response = state
            .http_client
            .post(format!(
                "{}/oauth/email-verification/confirm",
                state.config.backend_url
            ))
            .json(&ConfirmBody {
                verification_session,
                code,
            })
            .send()
            .await
            .map_err(|error| {
                VerifyEmailServiceError::BackendUnavailable(format!(
                    "email verification confirm failed: {}",
                    common::error::cause_chain(&error.without_url())
                ))
            })?;

        match response.status() {
            StatusCode::BAD_REQUEST => return Ok(CodeOutcome::InvalidCode),
            StatusCode::UNAUTHORIZED => return Ok(CodeOutcome::SessionExpired),
            status if !status.is_success() => {
                return Err(VerifyEmailServiceError::BackendUnavailable(format!(
                    "email verification confirm returned {status}"
                )));
            }
            _ => {}
        }
        let released: ConfirmResponse = response.json().await.map_err(|error| {
            VerifyEmailServiceError::BackendUnavailable(format!(
                "email verification confirm response unreadable: {}",
                common::error::cause_chain(&error.without_url())
            ))
        })?;

        let cookie = complete_login(state, &released.login_session, redirect_uri).await?;
        Ok(CodeOutcome::LoggedIn { cookie })
    }

    pub(crate) async fn resend(
        state: &AppState,
        verification_session: &str,
    ) -> Result<ResendOutcome, VerifyEmailServiceError> {
        let response = state
            .http_client
            .post(format!(
                "{}/oauth/email-verification/request",
                state.config.backend_url
            ))
            .json(&RequestBody {
                verification_session,
            })
            .send()
            .await
            .map_err(|error| {
                VerifyEmailServiceError::BackendUnavailable(format!(
                    "email verification request failed: {}",
                    common::error::cause_chain(&error.without_url())
                ))
            })?;

        match response.status() {
            status if status.is_success() => Ok(ResendOutcome::Accepted),
            StatusCode::UNAUTHORIZED => Ok(ResendOutcome::SessionExpired),
            status => Err(VerifyEmailServiceError::BackendUnavailable(format!(
                "email verification request returned {status}"
            ))),
        }
    }
}
