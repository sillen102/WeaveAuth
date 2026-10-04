pub(crate) use controller::confirm_email_verification;
pub(crate) use controller::confirm_email_verification_doc;
pub(crate) use controller::request_email_verification;
pub(crate) use controller::request_email_verification_doc;
pub(crate) use service::{EmailVerification, send_verification_email};

mod controller {
    use aide::transform::TransformOperation;
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiJson;
    use common_macros::ErrorResponses;
    use indoc::indoc;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::server::AppState;

    use super::service;
    use super::service::{
        ConfirmOutcome, ConfirmServiceError, RequestOutcome, RequestServiceError,
    };

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct EmailVerificationRequestRequest {
        pub(super) verification_session: String,
    }

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct EmailVerificationConfirmRequest {
        pub(super) verification_session: String,
        pub(super) code: String,
    }

    #[derive(Debug, Serialize, JsonSchema, Eq, PartialEq)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub(crate) enum EmailVerificationRequestResponse {
        /// A new code is on its way.
        Sent { expires_in_secs: i64 },
        /// Nothing sent: a code went out too recently.
        CoolingDown { retry_after_secs: i64 },
        /// Nothing sent: locked out after too many wrong guesses.
        Locked { retry_after_secs: i64 },
        /// Nothing sent: locked out too many times, until the password is
        /// reset.
        LockedUntilReset,
    }

    #[derive(Debug, Serialize, JsonSchema)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub(crate) enum EmailVerificationConfirmResponse {
        Verified {
            /// Single-use proof of authentication, exactly what
            /// `/oauth/login` returns for a verified account.
            login_session: String,
        },
        /// Locked out after too many wrong guesses (423): even the right code
        /// is refused until the lock ends.
        Locked { retry_after_secs: i64 },
        /// Locked out too many times (423): refused until the password is
        /// reset.
        LockedUntilReset,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum EmailVerificationRequestError {
        #[error("invalid or expired verification session")]
        #[error_response(
            StatusCode::UNAUTHORIZED,
            details = "invalid or expired verification session"
        )]
        InvalidSession,
        #[error("email delivery is not configured")]
        #[error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            details = "email delivery is not configured"
        )]
        DeliveryNotConfigured,
    }

    impl From<RequestServiceError> for EmailVerificationRequestError {
        fn from(err: RequestServiceError) -> Self {
            match err {
                RequestServiceError::InvalidSession => Self::InvalidSession,
                RequestServiceError::DeliveryNotConfigured => {
                    tracing::error!(
                        "verification code requested but no email handler is configured"
                    );
                    Self::DeliveryNotConfigured
                }
            }
        }
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum EmailVerificationConfirmError {
        #[error("invalid or expired verification session")]
        #[error_response(
            StatusCode::UNAUTHORIZED,
            details = "invalid or expired verification session"
        )]
        InvalidSession,
        #[error("invalid or expired email verification code")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "invalid or expired email verification code"
        )]
        InvalidOrExpiredCode,
        #[error("email verification code used up by wrong attempts")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "email verification code used up by wrong attempts"
        )]
        CodeUsedUp,
    }

    impl From<ConfirmServiceError> for EmailVerificationConfirmError {
        fn from(err: ConfirmServiceError) -> Self {
            match err {
                ConfirmServiceError::InvalidSession => Self::InvalidSession,
                ConfirmServiceError::InvalidOrExpiredCode => Self::InvalidOrExpiredCode,
                ConfirmServiceError::CodeUsedUp => Self::CodeUsedUp,
            }
        }
    }

    pub(crate) fn request_email_verification_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("request_email_verification")
            .summary("Send a new verification code")
            .description(indoc! {r#"
                Authenticated with the `verification_session` `/oauth/login` returned (401
                otherwise). Returns 202 and sends a fresh 9-digit code to the account's address,
                delivered asynchronously through the configured email handler (`status: "sent"`,
                with `expires_in_secs`). Also 202 when nothing was sent, with `retry_after_secs`
                saying how long until a new code can be requested: `status: "cooling_down"` when
                a code was sent within the resend cooldown, `status: "locked"` when the account
                is locked after wrong guesses; `status: "locked_until_reset"` (no
                `retry_after_secs`) after five lockouts, until the password is reset. 401 as
                well for an already verified account, 503 when no email handler is configured."#})
    }

    pub(crate) fn confirm_email_verification_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("confirm_email_verification")
            .summary("Verify an email address with the emailed code")
            .description(indoc! {r#"
                Authenticated with the `verification_session` `/oauth/login` returned (401
                otherwise). When `code` matches, marks the email verified, ends the verification
                session and returns the `login_session` the login withheld (`status:
                "verified"`). 400 if the code is wrong or expired, or with reason `CodeUsedUp`
                if too many wrong attempts used it up (a new one is needed); the verification
                session stays usable. 423 with `status: "locked"` and `retry_after_secs` while
                the account is locked out after too many wrong guesses, or `status:
                "locked_until_reset"` after five lockouts, until the password is reset: even the
                right code is refused."#})
    }

    pub(crate) async fn request_email_verification(
        State(mut state): State<AppState>,
        ApiJson(req): ApiJson<EmailVerificationRequestRequest>,
    ) -> Result<(StatusCode, Json<EmailVerificationRequestResponse>), EmailVerificationRequestError>
    {
        let response =
            match service::request_email_verification(&mut state, &req.verification_session).await?
            {
                RequestOutcome::Sent { expires_in_secs } => {
                    EmailVerificationRequestResponse::Sent { expires_in_secs }
                }
                RequestOutcome::CoolingDown { retry_after_secs } => {
                    EmailVerificationRequestResponse::CoolingDown { retry_after_secs }
                }
                RequestOutcome::Locked { retry_after_secs } => {
                    EmailVerificationRequestResponse::Locked { retry_after_secs }
                }
                RequestOutcome::LockedUntilReset => {
                    EmailVerificationRequestResponse::LockedUntilReset
                }
            };
        Ok((StatusCode::ACCEPTED, Json(response)))
    }

    pub(crate) async fn confirm_email_verification(
        State(mut state): State<AppState>,
        ApiJson(req): ApiJson<EmailVerificationConfirmRequest>,
    ) -> Result<(StatusCode, Json<EmailVerificationConfirmResponse>), EmailVerificationConfirmError>
    {
        let outcome =
            service::confirm_email_verification(&mut state, &req.verification_session, &req.code)
                .await?;
        Ok(match outcome {
            ConfirmOutcome::Verified { login_session } => (
                StatusCode::OK,
                Json(EmailVerificationConfirmResponse::Verified { login_session }),
            ),
            ConfirmOutcome::Locked { retry_after_secs } => (
                StatusCode::LOCKED,
                Json(EmailVerificationConfirmResponse::Locked { retry_after_secs }),
            ),
            ConfirmOutcome::LockedUntilReset => (
                StatusCode::LOCKED,
                Json(EmailVerificationConfirmResponse::LockedUntilReset),
            ),
        })
    }
}

mod service {
    use chrono::Utc;
    use thiserror::Error;
    use tokio::task::JoinHandle;
    use uuid::Uuid;

    use crate::model::user::User;
    use crate::server::AppState;
    use crate::server::api::current_user;
    use crate::storage::in_memory::{
        InMemoryEmailVerificationCodeStorage, InMemoryVerificationSessionStorage,
    };
    use crate::storage::{
        CheckCodeOutcome, EmailVerificationCodeStorage, IssueCodeOutcome, LoginSessionStorage,
        MarkVerifiedOutcome, UserStorage, VerificationSessionStorage,
    };

    use crate::email::{EmailKind, OutboundEmail};

    #[derive(Debug, Error, Eq, PartialEq)]
    #[error("invalid or expired verification session")]
    pub(crate) struct InvalidSession;

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum ConfirmServiceError {
        #[error("invalid or expired verification session")]
        InvalidSession,
        #[error("invalid or expired email verification code")]
        InvalidOrExpiredCode,
        #[error("email verification code used up by wrong attempts")]
        CodeUsedUp,
    }

    pub(crate) enum ConfirmOutcome {
        /// The `login_session` the login withheld.
        Verified {
            login_session: String,
        },
        Locked {
            retry_after_secs: i64,
        },
        LockedUntilReset,
    }

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum RequestServiceError {
        #[error("invalid or expired verification session")]
        InvalidSession,
        #[error("no email handler is configured")]
        DeliveryNotConfigured,
    }

    /// Why no email was sent.
    #[derive(Debug)]
    pub(crate) enum NotSent {
        /// No email handler is configured.
        Disabled,
        CoolingDown {
            retry_after_secs: i64,
        },
        Locked {
            retry_after_secs: i64,
        },
        LockedUntilReset,
    }

    pub(crate) enum RequestOutcome {
        Sent { expires_in_secs: i64 },
        CoolingDown { retry_after_secs: i64 },
        Locked { retry_after_secs: i64 },
        LockedUntilReset,
    }

    /// Everything the verification-email flow needs from `AppState`.
    #[derive(Clone)]
    pub(crate) struct EmailVerification {
        pub(crate) codes: InMemoryEmailVerificationCodeStorage,
        /// What `/oauth/login` hands an unverified account; see
        /// `VerificationSessionStorage`.
        pub(crate) sessions: InMemoryVerificationSessionStorage,
        pub(crate) code_ttl_secs: i64,
        /// Withhold the `login_session` from an unverified account.
        pub(crate) required: bool,
    }

    #[cfg(test)]
    impl EmailVerification {
        pub(crate) fn disabled() -> Self {
            Self {
                codes: InMemoryEmailVerificationCodeStorage::new(60, 0),
                sessions: InMemoryVerificationSessionStorage::new(60),
                code_ttl_secs: 60,
                required: false,
            }
        }
    }

    /// Issues a code for `user_id` and sends it in a background task, so a
    /// slow SMTP server or plugin neither delays registration or login (whose
    /// response time would show which requests send mail) nor the resend
    /// response (which says outright whether it sent). The returned handle
    /// completes when the send has; callers drop it. `Err` says why nothing is
    /// sent: no handler, inside the resend cooldown, or locked out after too
    /// many wrong guesses. A delivery failure is logged there and nowhere
    /// else: the user can ask for a new code.
    pub(crate) async fn send_verification_email(
        state: &mut AppState,
        user_id: Uuid,
        email: &str,
    ) -> Result<JoinHandle<()>, NotSent> {
        let handler = state.email_handler.clone().ok_or(NotSent::Disabled)?;
        let login_url = state.login_public_url.as_str();

        let code = match state.email_verification.codes.issue_code(user_id).await {
            IssueCodeOutcome::Issued(code) => code,
            IssueCodeOutcome::CoolingDown { retry_after_secs } => {
                tracing::info!(
                    %user_id,
                    retry_after_secs,
                    "verification email skipped: resend cooldown"
                );
                return Err(NotSent::CoolingDown { retry_after_secs });
            }
            IssueCodeOutcome::LockedUntilReset => {
                tracing::warn!(%user_id, "verification email skipped: locked until password reset");
                return Err(NotSent::LockedUntilReset);
            }
            IssueCodeOutcome::Locked { retry_after_secs } => {
                tracing::warn!(
                    %user_id,
                    retry_after_secs,
                    "verification email skipped: locked after wrong guesses"
                );
                return Err(NotSent::Locked { retry_after_secs });
            }
        };
        let mail = OutboundEmail {
            user_id,
            email: email.to_string(),
            expires_at: Utc::now()
                + chrono::Duration::seconds(state.email_verification.code_ttl_secs),
            kind: EmailKind::EmailVerification {
                code,
                verify_page_url: format!("{login_url}/verify-email.html"),
            },
        };
        Ok(tokio::spawn(async move {
            if let Err(error) = handler.send(&mail).await {
                tracing::warn!(%error, user_id = %mail.user_id, "could not deliver verification email");
            }
        }))
    }

    async fn session_user(state: &AppState, token: &str) -> Result<User, InvalidSession> {
        let stamp = state
            .email_verification
            .sessions
            .get_session(token)
            .await
            .ok_or(InvalidSession)?;
        current_user(&state.users, stamp)
            .await
            .ok_or(InvalidSession)
    }

    /// Sends a fresh code to the account the verification session belongs to.
    /// An already verified account has no use for one: its session is invalid.
    pub(crate) async fn request_email_verification(
        state: &mut AppState,
        verification_session: &str,
    ) -> Result<RequestOutcome, RequestServiceError> {
        let user = session_user(state, verification_session)
            .await
            .map_err(|InvalidSession| RequestServiceError::InvalidSession)?;
        if user.email_verified {
            return Err(RequestServiceError::InvalidSession);
        }
        match send_verification_email(state, user.id, &user.email).await {
            Ok(_) => Ok(RequestOutcome::Sent {
                expires_in_secs: state.email_verification.code_ttl_secs,
            }),
            Err(NotSent::Disabled) => Err(RequestServiceError::DeliveryNotConfigured),
            Err(NotSent::CoolingDown { retry_after_secs }) => {
                Ok(RequestOutcome::CoolingDown { retry_after_secs })
            }
            Err(NotSent::Locked { retry_after_secs }) => {
                Ok(RequestOutcome::Locked { retry_after_secs })
            }
            Err(NotSent::LockedUntilReset) => Ok(RequestOutcome::LockedUntilReset),
        }
    }

    /// Checks `code` for the session's account and, on success, verifies the
    /// email, ends the verification session and returns the `login_session`
    /// the login withheld.
    pub(crate) async fn confirm_email_verification(
        state: &mut AppState,
        verification_session: &str,
        code: &str,
    ) -> Result<ConfirmOutcome, ConfirmServiceError> {
        let user = session_user(state, verification_session)
            .await
            .map_err(|InvalidSession| ConfirmServiceError::InvalidSession)?;

        // A verification session never turns into a login for an account that
        // is already verified: it may have been handed out before the account
        // changed hands (a password reset), and no code is checked here.
        if user.email_verified {
            state
                .email_verification
                .sessions
                .delete_session(verification_session)
                .await;
            return Err(ConfirmServiceError::InvalidSession);
        }

        match state
            .email_verification
            .codes
            .check_code(user.id, code.trim())
            .await
        {
            CheckCodeOutcome::Verified => {}
            CheckCodeOutcome::Wrong | CheckCodeOutcome::NoCode => {
                return Err(ConfirmServiceError::InvalidOrExpiredCode);
            }
            CheckCodeOutcome::TooManyAttempts => return Err(ConfirmServiceError::CodeUsedUp),
            CheckCodeOutcome::Locked { retry_after_secs } => {
                return Ok(ConfirmOutcome::Locked { retry_after_secs });
            }
            CheckCodeOutcome::LockedUntilReset => return Ok(ConfirmOutcome::LockedUntilReset),
        }
        match state.users.mark_email_verified(user.id).await {
            MarkVerifiedOutcome::Ok => {}
            MarkVerifiedOutcome::UserNotFound => return Err(ConfirmServiceError::InvalidSession),
        }

        state
            .email_verification
            .sessions
            .delete_session(verification_session)
            .await;
        Ok(ConfirmOutcome::Verified {
            login_session: state.login_sessions.create_session(user.stamp()).await,
        })
    }
}

/// A mail handler that reports every send on a channel, for the tests of
/// the endpoints that send (register, login, resend).
#[cfg(test)]
pub(crate) mod test_support {
    use crate::email::{EmailDeliveryError, EmailHandler, EmailKind, OutboundEmail};
    use crate::server::AppState;
    use crate::storage::in_memory::wrong_code;
    use crate::storage::{EmailVerificationCodeStorage, IssueCodeOutcome};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    /// What a handler was asked to send.
    #[derive(Debug)]
    pub(crate) struct Sent {
        pub(crate) email: String,
        pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
        pub(crate) kind: EmailKind,
    }

    /// Reports every send on a channel; fails each one when told to.
    struct Recorder {
        tx: mpsc::UnboundedSender<Sent>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl EmailHandler for Recorder {
        async fn send(&self, mail: &OutboundEmail) -> Result<(), EmailDeliveryError> {
            let _ = self.tx.send(Sent {
                email: mail.email.clone(),
                expires_at: mail.expires_at,
                kind: mail.kind.clone(),
            });
            if self.fail {
                Err(EmailDeliveryError("boom".to_string()))
            } else {
                Ok(())
            }
        }
    }

    /// Points `state` at a recording handler, with no resend cooldown so a
    /// test never depends on one to block a send.
    pub(crate) fn install_recorder(
        state: &mut AppState,
        fail: bool,
    ) -> mpsc::UnboundedReceiver<Sent> {
        let (tx, rx) = mpsc::unbounded_channel();
        state.email_handler = Some(Arc::new(Recorder { tx, fail }));
        state.login_public_url = "https://login.test".to_string();
        state.email_verification.codes =
            crate::storage::in_memory::InMemoryEmailVerificationCodeStorage::new(900, 0);
        state.email_verification.code_ttl_secs = 900;
        rx
    }

    pub(crate) async fn next_sent(rx: &mut mpsc::UnboundedReceiver<Sent>) -> Sent {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a mail was sent")
            .expect("channel open")
    }

    /// Nothing was sent: gives a background send time to show up first.
    pub(crate) async fn assert_nothing_sent(rx: &mut mpsc::UnboundedReceiver<Sent>) {
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(rx.try_recv().is_err(), "a mail was sent");
    }

    pub(crate) async fn code_for(state: &mut AppState, user_id: Uuid) -> String {
        match state.email_verification.codes.issue_code(user_id).await {
            IssueCodeOutcome::Issued(code) => code,
            IssueCodeOutcome::CoolingDown { .. }
            | IssueCodeOutcome::Locked { .. }
            | IssueCodeOutcome::LockedUntilReset => {
                unreachable!("no cooldown or lock")
            }
        }
    }

    /// Wrong guesses across two codes: the user is locked out.
    pub(crate) async fn lock_out(state: &mut AppState, user_id: Uuid) {
        let mut code = code_for(state, user_id).await;
        for _ in 0..2 {
            let wrong = wrong_code(&code);
            for _ in 0..5 {
                let _ = state
                    .email_verification
                    .codes
                    .check_code(user_id, wrong)
                    .await;
            }
            if let IssueCodeOutcome::Issued(next) =
                state.email_verification.codes.issue_code(user_id).await
            {
                code = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use super::service::NotSent;
    use super::test_support::{
        Sent, assert_nothing_sent, code_for, install_recorder, lock_out, next_sent,
    };
    use super::*;
    use crate::model::user::{CredentialStamp, User};
    use crate::server::AppState;
    use crate::storage::in_memory::wrong_code;
    use crate::storage::{
        CheckCodeOutcome, EmailVerificationCodeStorage, LoginSessionStorage, UserStorage,
        VerificationSessionStorage,
    };
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiJson;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    async fn state_with(fail: bool) -> (AppState, mpsc::UnboundedReceiver<Sent>) {
        let mut state = AppState::for_test().await;
        let rx = install_recorder(&mut state, fail);
        (state, rx)
    }

    async fn add_user(state: &mut AppState, email: &str, verified: bool) -> Uuid {
        let user = User {
            email: email.to_string(),
            email_verified: verified,
            ..User::default()
        };
        let id = user.id;
        let _ = state.users.create_user(user).await;
        id
    }

    /// A verification session for `user_id`, as `/oauth/login` would hand out.
    async fn session_for(state: &mut AppState, user_id: Uuid) -> String {
        state
            .email_verification
            .sessions
            .create_session(CredentialStamp::initial(user_id))
            .await
    }

    fn confirm_req(session: &str, code: &str) -> EmailVerificationConfirmRequest {
        EmailVerificationConfirmRequest {
            verification_session: session.to_string(),
            code: code.to_string(),
        }
    }

    fn request_req(session: &str) -> EmailVerificationRequestRequest {
        EmailVerificationRequestRequest {
            verification_session: session.to_string(),
        }
    }

    #[tokio::test]
    async fn send_mails_a_nine_digit_code_and_the_page_to_enter_it_on() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;

        send_verification_email(&mut state, user_id, "alice@example.com")
            .await
            .expect("a send was started")
            .await
            .unwrap();

        let sent = next_sent(&mut rx).await;
        assert_eq!(sent.email, "alice@example.com");
        let crate::email::EmailKind::EmailVerification {
            code,
            verify_page_url,
        } = sent.kind
        else {
            unreachable!("not a verification email: {:?}", sent.kind);
        };
        assert_eq!(code.len(), 9);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(verify_page_url, "https://login.test/verify-email.html");
        let expires_in = sent.expires_at - chrono::Utc::now();
        assert!(
            (895..=900).contains(&expires_in.num_seconds()),
            "{expires_in}"
        );
        assert_eq!(
            state
                .email_verification
                .codes
                .check_code(user_id, &code)
                .await,
            CheckCodeOutcome::Verified
        );
    }

    #[tokio::test]
    async fn send_does_not_wait_for_a_slow_handler() {
        struct Slow;
        #[async_trait::async_trait]
        impl crate::email::EmailHandler for Slow {
            async fn send(
                &self,
                _: &crate::email::OutboundEmail,
            ) -> Result<(), crate::email::EmailDeliveryError> {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(())
            }
        }
        let (mut state, _rx) = state_with(false).await;
        state.email_handler = Some(Arc::new(Slow));

        let handle = tokio::time::timeout(
            Duration::from_secs(5),
            send_verification_email(&mut state, Uuid::new_v4(), "alice@example.com"),
        )
        .await
        .expect("returns without waiting for the send");
        handle.expect("a send was started").abort();
    }

    #[tokio::test]
    async fn send_without_a_handler_issues_no_code() {
        let (mut state, _rx) = state_with(false).await;
        state.email_handler = None;

        let handle = send_verification_email(&mut state, Uuid::new_v4(), "alice@example.com").await;

        assert!(matches!(handle, Err(NotSent::Disabled)), "{handle:?}");
        assert_eq!(state.email_verification.codes.entry_count().await, 0);
    }

    #[tokio::test]
    async fn send_swallows_a_delivery_failure() {
        let (mut state, mut rx) = state_with(true).await;

        send_verification_email(&mut state, Uuid::new_v4(), "alice@example.com")
            .await
            .expect("a send was started")
            .await
            .expect("the task does not panic");

        let _ = next_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn send_respects_the_resend_cooldown() {
        let (mut state, mut rx) = state_with(false).await;
        state.email_verification.codes =
            crate::storage::in_memory::InMemoryEmailVerificationCodeStorage::new(900, 60);
        let user_id = Uuid::new_v4();

        let first = send_verification_email(&mut state, user_id, "a@example.com").await;
        let second = send_verification_email(&mut state, user_id, "a@example.com").await;

        first.expect("the first send starts").await.unwrap();
        assert!(
            matches!(
                second,
                Err(NotSent::CoolingDown { retry_after_secs })
                    if (59..=60).contains(&retry_after_secs)
            ),
            "inside the cooldown: {second:?}"
        );
        let _ = next_sent(&mut rx).await;
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn request_sends_a_code_for_the_sessions_unverified_account() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;

        let response =
            request_email_verification(State(state), ApiJson(request_req(&session))).await;

        let (status, body) = response.expect("accepted");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            body.0,
            EmailVerificationRequestResponse::Sent {
                expires_in_secs: 900
            }
        );
        assert_eq!(next_sent(&mut rx).await.email, "alice@example.com");
    }

    #[tokio::test]
    async fn request_inside_the_cooldown_says_nothing_was_sent_and_for_how_long() {
        let (mut state, mut rx) = state_with(false).await;
        state.email_verification.codes =
            crate::storage::in_memory::InMemoryEmailVerificationCodeStorage::new(900, 60);
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        let _ = code_for(&mut state, user_id).await;

        let response =
            request_email_verification(State(state), ApiJson(request_req(&session))).await;

        let (status, body) = response.expect("accepted");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(
            matches!(
                body.0,
                EmailVerificationRequestResponse::CoolingDown { retry_after_secs }
                    if (59..=60).contains(&retry_after_secs)
            ),
            "{:?}",
            body.0
        );
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn request_refuses_an_unknown_session_without_sending() {
        let (state, mut rx) = state_with(false).await;

        let result = request_email_verification(State(state), ApiJson(request_req("nope"))).await;

        assert_eq!(
            result.err(),
            Some(EmailVerificationRequestError::InvalidSession)
        );
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn request_refuses_a_session_issued_before_a_password_change() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        let _ = state
            .users
            .set_password(
                user_id,
                crate::model::user::PasswordHash::Argon2("new-hash".into()),
            )
            .await;

        let result = request_email_verification(State(state), ApiJson(request_req(&session))).await;

        assert_eq!(
            result.err(),
            Some(EmailVerificationRequestError::InvalidSession)
        );
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn request_refuses_an_already_verified_account_without_sending() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", true).await;
        let session = session_for(&mut state, user_id).await;

        let response =
            request_email_verification(State(state), ApiJson(request_req(&session))).await;

        assert_eq!(
            response.err(),
            Some(EmailVerificationRequestError::InvalidSession)
        );
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn confirm_with_the_right_code_verifies_ends_the_session_and_returns_a_login_session() {
        let (mut state, _rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        let code = code_for(&mut state, user_id).await;

        let response = confirm_email_verification(
            State(state.clone()),
            ApiJson(confirm_req(&session, &format!(" {code} "))),
        )
        .await
        .expect("verified");

        let user = state.users.get_user_by_id(user_id).await.unwrap();
        assert!(user.email_verified);
        // The login session is the real thing: it redeems for this user, once.
        let mut sessions = state.login_sessions.clone();
        let EmailVerificationConfirmResponse::Verified { login_session } = response.1.0 else {
            unreachable!("verified");
        };
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(
            sessions.take_session(&login_session).await,
            Some(CredentialStamp::initial(user_id))
        );
        // The verification session is gone.
        assert_eq!(
            state
                .email_verification
                .sessions
                .get_session(&session)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn confirm_with_a_wrong_code_keeps_the_session_and_the_account_unverified() {
        let (mut state, _rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        let code = code_for(&mut state, user_id).await;
        let wrong = wrong_code(&code);

        let result =
            confirm_email_verification(State(state.clone()), ApiJson(confirm_req(&session, wrong)))
                .await;

        assert_eq!(
            result.err(),
            Some(EmailVerificationConfirmError::InvalidOrExpiredCode)
        );
        assert!(
            !state
                .users
                .get_user_by_id(user_id)
                .await
                .unwrap()
                .email_verified
        );
        assert_eq!(
            state
                .email_verification
                .sessions
                .get_session(&session)
                .await,
            Some(CredentialStamp::initial(user_id))
        );
    }

    #[tokio::test]
    async fn confirm_while_locked_out_says_so_even_for_the_right_code() {
        let (mut state, _rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        lock_out(&mut state, user_id).await;

        let result = confirm_email_verification(
            State(state.clone()),
            ApiJson(confirm_req(&session, "123456789")),
        )
        .await;

        let (status, body) = result.expect("answered");
        assert_eq!(status, StatusCode::LOCKED);
        assert!(
            matches!(
                body.0,
                EmailVerificationConfirmResponse::Locked { retry_after_secs }
                    if (3_599..=3_600).contains(&retry_after_secs)
            ),
            "{:?}",
            body.0
        );
        assert!(
            !state
                .users
                .get_user_by_id(user_id)
                .await
                .unwrap()
                .email_verified
        );
    }

    #[tokio::test]
    async fn confirm_after_too_many_lockouts_says_locked_until_reset_for_confirm_and_request() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        state.email_verification.codes.hard_lock(user_id).await;

        let confirm = confirm_email_verification(
            State(state.clone()),
            ApiJson(confirm_req(&session, "123456789")),
        )
        .await
        .expect("answered");
        let request =
            request_email_verification(State(state), ApiJson(request_req(&session))).await;

        assert_eq!(confirm.0, StatusCode::LOCKED);
        assert!(matches!(
            confirm.1.0,
            EmailVerificationConfirmResponse::LockedUntilReset
        ));
        let (status, body) = request.expect("accepted");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body.0, EmailVerificationRequestResponse::LockedUntilReset);
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn confirm_after_the_fifth_wrong_guess_says_the_code_is_used_up() {
        let (mut state, _rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        let code = code_for(&mut state, user_id).await;
        let wrong = wrong_code(&code);
        for _ in 0..4 {
            let _ = confirm_email_verification(
                State(state.clone()),
                ApiJson(confirm_req(&session, wrong)),
            )
            .await;
        }

        let result =
            confirm_email_verification(State(state.clone()), ApiJson(confirm_req(&session, wrong)))
                .await;

        assert_eq!(
            result.err(),
            Some(EmailVerificationConfirmError::CodeUsedUp)
        );
    }

    #[tokio::test]
    async fn confirm_refuses_an_unknown_session_even_with_the_right_code() {
        let (mut state, _rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let code = code_for(&mut state, user_id).await;

        let result =
            confirm_email_verification(State(state.clone()), ApiJson(confirm_req("nope", &code)))
                .await;

        assert_eq!(
            result.err(),
            Some(EmailVerificationConfirmError::InvalidSession)
        );
        assert!(
            !state
                .users
                .get_user_by_id(user_id)
                .await
                .unwrap()
                .email_verified
        );
    }

    #[tokio::test]
    async fn confirm_locks_out_guessing_after_five_wrong_codes() {
        let (mut state, _rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        let code = code_for(&mut state, user_id).await;
        let wrong = wrong_code(&code);

        for _ in 0..5 {
            let _ = confirm_email_verification(
                State(state.clone()),
                ApiJson(confirm_req(&session, wrong)),
            )
            .await;
        }
        let result =
            confirm_email_verification(State(state.clone()), ApiJson(confirm_req(&session, &code)))
                .await;

        assert_eq!(
            result.err(),
            Some(EmailVerificationConfirmError::InvalidOrExpiredCode)
        );
    }

    // A verification session handed out before the account changed hands (a
    // password reset) must not turn into a login once the account is verified.
    #[tokio::test]
    async fn confirm_for_an_already_verified_account_gives_no_login_session() {
        let (mut state, _rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", true).await;
        let session = session_for(&mut state, user_id).await;

        let result = confirm_email_verification(
            State(state.clone()),
            ApiJson(confirm_req(&session, "123456789")),
        )
        .await;

        assert_eq!(
            result.err(),
            Some(EmailVerificationConfirmError::InvalidSession)
        );
        // The session is spent, and no login session was minted for the user.
        assert_eq!(
            state
                .email_verification
                .sessions
                .get_session(&session)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn request_without_an_email_handler_is_service_unavailable() {
        let (mut state, _rx) = state_with(false).await;
        state.email_handler = None;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;

        let response =
            request_email_verification(State(state), ApiJson(request_req(&session))).await;

        assert_eq!(
            response.err(),
            Some(EmailVerificationRequestError::DeliveryNotConfigured)
        );
    }

    #[tokio::test]
    async fn request_while_locked_out_says_locked_and_for_how_long() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        lock_out(&mut state, user_id).await;

        let response =
            request_email_verification(State(state), ApiJson(request_req(&session))).await;

        let (status, body) = response.expect("accepted");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(
            matches!(
                body.0,
                EmailVerificationRequestResponse::Locked { retry_after_secs }
                    if (3_599..=3_600).contains(&retry_after_secs)
            ),
            "{:?}",
            body.0
        );
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn send_is_skipped_while_locked_out() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        lock_out(&mut state, user_id).await;

        let handle = send_verification_email(&mut state, user_id, "alice@example.com").await;

        assert!(matches!(handle, Err(NotSent::Locked { .. })), "{handle:?}");
        assert_nothing_sent(&mut rx).await;
    }
}
