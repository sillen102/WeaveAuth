pub(crate) use controller::confirm_email_verification;
pub(crate) use controller::confirm_email_verification_doc;
pub(crate) use controller::request_email_verification;
pub(crate) use controller::request_email_verification_doc;
#[cfg(test)]
pub(crate) use delivery::{EmailDeliveryError, VerificationEmail};
pub(crate) use delivery::{
    EmailVerificationHandler, PLUGIN_NAME, PluginHandler, SmtpHandler, TEMPLATES_GLOB,
    WebhookHandler,
};
pub(crate) use service::{EmailVerification, send_verification_email};

mod controller {
    use aide::transform::TransformOperation;
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiJson;
    use common_macros::ErrorResponses;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::server::AppState;

    use super::service;
    use super::service::{ConfirmServiceError, InvalidSession};

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct EmailVerificationRequestRequest {
        pub(super) verification_session: String,
    }

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct EmailVerificationConfirmRequest {
        pub(super) verification_session: String,
        pub(super) code: String,
    }

    #[derive(Serialize, JsonSchema)]
    pub(crate) struct EmailVerificationConfirmResponse {
        /// Single-use proof of authentication, exactly what `/oauth/login`
        /// returns for a verified account.
        pub(super) login_session: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum EmailVerificationRequestError {
        #[error("invalid or expired verification session")]
        #[error_response(
            StatusCode::UNAUTHORIZED,
            details = "invalid or expired verification session"
        )]
        InvalidSession,
    }

    impl From<InvalidSession> for EmailVerificationRequestError {
        fn from(_: InvalidSession) -> Self {
            Self::InvalidSession
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
    }

    impl From<ConfirmServiceError> for EmailVerificationConfirmError {
        fn from(err: ConfirmServiceError) -> Self {
            match err {
                ConfirmServiceError::InvalidSession => Self::InvalidSession,
                ConfirmServiceError::InvalidOrExpiredCode => Self::InvalidOrExpiredCode,
            }
        }
    }

    pub(crate) fn request_email_verification_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("request_email_verification")
            .summary("Send a new verification code")
            .description(
                "Authenticated with the `verification_session` `/oauth/login` returned (401 \
                 otherwise). Returns 202 and sends a fresh 6-digit code to the account's \
                 address, delivered asynchronously through the configured email handler. Also \
                 202, sending nothing, when the email is already verified or a code was sent \
                 within the resend cooldown.",
            )
    }

    pub(crate) fn confirm_email_verification_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("confirm_email_verification")
            .summary("Verify an email address with the emailed code")
            .description(
                "Authenticated with the `verification_session` `/oauth/login` returned (401 \
                 otherwise). When `code` matches, marks the email verified, ends the \
                 verification session and returns the `login_session` the login withheld. 400 \
                 if the code is wrong, expired, or used up by too many wrong attempts; the \
                 verification session stays usable.",
            )
    }

    pub(crate) async fn request_email_verification(
        State(mut state): State<AppState>,
        ApiJson(req): ApiJson<EmailVerificationRequestRequest>,
    ) -> Result<StatusCode, EmailVerificationRequestError> {
        service::request_email_verification(&mut state, &req.verification_session).await?;
        Ok(StatusCode::ACCEPTED)
    }

    pub(crate) async fn confirm_email_verification(
        State(mut state): State<AppState>,
        ApiJson(req): ApiJson<EmailVerificationConfirmRequest>,
    ) -> Result<Json<EmailVerificationConfirmResponse>, EmailVerificationConfirmError> {
        let login_session =
            service::confirm_email_verification(&mut state, &req.verification_session, &req.code)
                .await?;
        Ok(Json(EmailVerificationConfirmResponse { login_session }))
    }
}

mod service {
    use std::sync::Arc;

    use chrono::Utc;
    use thiserror::Error;
    use tokio::task::JoinHandle;
    use uuid::Uuid;

    use crate::model::user::User;
    use crate::server::AppState;
    use crate::storage::in_memory::{
        InMemoryEmailVerificationCodeStorage, InMemoryVerificationSessionStorage,
    };
    use crate::storage::{
        CheckCodeOutcome, EmailVerificationCodeStorage, IssueCodeOutcome, LoginSessionStorage,
        MarkVerifiedOutcome, UserStorage, VerificationSessionStorage,
    };

    use super::delivery::{EmailVerificationHandler, VerificationEmail};

    #[derive(Debug, Error, Eq, PartialEq)]
    #[error("invalid or expired verification session")]
    pub(crate) struct InvalidSession;

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum ConfirmServiceError {
        #[error("invalid or expired verification session")]
        InvalidSession,
        #[error("invalid or expired email verification code")]
        InvalidOrExpiredCode,
    }

    /// Everything the verification-email flow needs from `AppState`.
    #[derive(Clone)]
    pub(crate) struct EmailVerification {
        pub(crate) codes: InMemoryEmailVerificationCodeStorage,
        /// What `/oauth/login` hands an unverified account; see
        /// `VerificationSessionStorage`.
        pub(crate) sessions: InMemoryVerificationSessionStorage,
        /// `None`: no email is sent.
        pub(crate) handler: Option<Arc<dyn EmailVerificationHandler>>,
        /// Login's public origin; the email points at its `/verify-email.html`.
        pub(crate) login_public_url: Option<String>,
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
                handler: None,
                login_public_url: None,
                code_ttl_secs: 60,
                required: false,
            }
        }
    }

    /// Issues a code for `user_id` and sends it in a background task, so a
    /// slow SMTP server or plugin neither delays the response (which would
    /// show which requests send mail) nor registration. The returned handle
    /// completes when the send has; callers drop it. `None` when nothing is
    /// sent: no handler, inside the resend cooldown, or locked out after too
    /// many wrong guesses. A delivery failure is logged there and nowhere
    /// else: the user can ask for a new code.
    pub(crate) async fn send_verification_email(
        state: &mut AppState,
        user_id: Uuid,
        email: &str,
    ) -> Option<JoinHandle<()>> {
        let handler = state.email_verification.handler.clone()?;
        let Some(login_url) = state.email_verification.login_public_url.as_deref() else {
            tracing::error!("email handler configured without login_public_url");
            return None;
        };

        let code = match state.email_verification.codes.issue_code(user_id).await {
            IssueCodeOutcome::Issued(code) => code,
            IssueCodeOutcome::CoolingDown => {
                tracing::info!(%user_id, "verification email skipped: resend cooldown");
                return None;
            }
            IssueCodeOutcome::Locked => {
                tracing::warn!(%user_id, "verification email skipped: locked after wrong guesses");
                return None;
            }
        };
        let mail = VerificationEmail {
            user_id,
            email: email.to_string(),
            code,
            verify_page_url: format!("{}/verify-email.html", login_url.trim_end_matches('/')),
            expires_at: Utc::now()
                + chrono::Duration::seconds(state.email_verification.code_ttl_secs),
        };
        Some(tokio::spawn(async move {
            if let Err(error) = handler.send(&mail).await {
                tracing::warn!(%error, user_id = %mail.user_id, "could not deliver verification email");
            }
        }))
    }

    async fn session_user(state: &AppState, token: &str) -> Result<User, InvalidSession> {
        let user_id = state
            .email_verification
            .sessions
            .get_session(token)
            .await
            .ok_or(InvalidSession)?;
        state
            .users
            .get_user_by_id(user_id)
            .await
            .ok_or(InvalidSession)
    }

    /// Sends a fresh code to the account the verification session belongs to,
    /// unless it is already verified.
    pub(crate) async fn request_email_verification(
        state: &mut AppState,
        verification_session: &str,
    ) -> Result<(), InvalidSession> {
        let user = session_user(state, verification_session).await?;
        if !user.email_verified {
            drop(send_verification_email(state, user.id, &user.email).await);
        }
        Ok(())
    }

    /// Checks `code` for the session's account and, on success, verifies the
    /// email, ends the verification session and returns the `login_session`
    /// the login withheld.
    pub(crate) async fn confirm_email_verification(
        state: &mut AppState,
        verification_session: &str,
        code: &str,
    ) -> Result<String, ConfirmServiceError> {
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
            CheckCodeOutcome::Wrong
            | CheckCodeOutcome::NoCode
            | CheckCodeOutcome::TooManyAttempts
            | CheckCodeOutcome::Locked => return Err(ConfirmServiceError::InvalidOrExpiredCode),
        }
        match state.users.mark_email_verified_by_code(user.id).await {
            MarkVerifiedOutcome::Ok => {}
            MarkVerifiedOutcome::UserNotFound => return Err(ConfirmServiceError::InvalidSession),
        }

        state
            .email_verification
            .sessions
            .delete_session(verification_session)
            .await;
        Ok(state.login_sessions.create_session(user.id).await)
    }
}

/// How a verification email leaves WeaveAuth: over SMTP with templates, to a
/// webhook, or to a plugin process. An error is returned to the caller
/// (`service::send_verification_email`), which logs it.
mod delivery {
    use std::time::Duration;

    use chrono::{DateTime, Utc};
    use lettre::message::{Mailbox, MultiPart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
    use secrecy::{ExposeSecret, SecretString};
    use serde::Serialize;
    use tera::{Context, Tera};
    use uuid::Uuid;
    use weaveauth_plugin_sdk::PluginRequest;

    use crate::config::SmtpTls;
    use crate::plugin::{self, PluginProcess};

    /// Names this plugin surface in the `WA_PLUGIN_<PLUGIN>_ENV_*` variables.
    pub(crate) const PLUGIN_NAME: &str = "EMAIL";

    /// This hook's name on the generic plugin contract (`PluginRequest::hook`).
    const HOOK: &str = "email_verification";

    /// Deployer-replaceable email templates: `verify-email.subject.txt`,
    /// `verify-email.txt` and `verify-email.html`. Shared with the login pages
    /// under the repo's top-level `templates/`.
    pub(crate) const TEMPLATES_GLOB: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../templates/emails/*");

    const REQUIRED_TEMPLATES: [&str; 3] = [
        "verify-email.subject.txt",
        "verify-email.txt",
        "verify-email.html",
    ];

    #[derive(Debug, thiserror::Error, Eq, PartialEq)]
    #[error("{0}")]
    pub(crate) struct EmailDeliveryError(pub(crate) String);

    /// What the handler is given, and the webhook's JSON body. Owned, because
    /// the send runs in a background task.
    #[derive(Serialize)]
    pub(crate) struct VerificationEmail {
        pub(crate) user_id: Uuid,
        pub(crate) email: String,
        /// The 6-digit code the user types in.
        pub(crate) code: String,
        /// Login's page where the code is entered.
        pub(crate) verify_page_url: String,
        /// When the code stops working (RFC 3339 in the webhook payload).
        pub(crate) expires_at: DateTime<Utc>,
    }

    #[async_trait::async_trait]
    pub(crate) trait EmailVerificationHandler: Send + Sync {
        async fn send(&self, mail: &VerificationEmail) -> Result<(), EmailDeliveryError>;
    }

    pub(crate) struct PluginHandler {
        plugin: PluginProcess,
    }

    impl PluginHandler {
        pub(crate) fn new(plugin: PluginProcess) -> Self {
            Self { plugin }
        }
    }

    #[async_trait::async_trait]
    impl EmailVerificationHandler for PluginHandler {
        async fn send(&self, mail: &VerificationEmail) -> Result<(), EmailDeliveryError> {
            let data = serde_json::json!({
                "code": mail.code,
                "verify_page_url": mail.verify_page_url,
                "expires_at": mail.expires_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            });
            let serde_json::Value::Object(data) = data else {
                return Err(EmailDeliveryError("payload is not an object".to_string()));
            };
            let request = PluginRequest {
                hook: HOOK.to_string(),
                user_id: mail.user_id.to_string(),
                email: mail.email.clone(),
                data: Some(plugin::json_to_struct(data)),
            };

            self.plugin
                .invoke(request)
                .await
                .map(|_| ())
                .map_err(|status| {
                    EmailDeliveryError(format!(
                        "plugin rejected the verification email: {:?}: {}",
                        status.code(),
                        status.message()
                    ))
                })
        }
    }

    pub(crate) struct WebhookHandler {
        client: reqwest::Client,
        url: String,
    }

    impl WebhookHandler {
        pub(crate) fn new(url: String, timeout: Duration) -> anyhow::Result<Self> {
            crate::config::require_https_or_loopback("email webhook url", &url)?;

            // No redirects: server-to-server call to a deployer-configured
            // target, same reasoning as `extra_data::WebhookHandler`.
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(timeout)
                .build()?;
            Ok(Self { client, url })
        }
    }

    #[async_trait::async_trait]
    impl EmailVerificationHandler for WebhookHandler {
        async fn send(&self, mail: &VerificationEmail) -> Result<(), EmailDeliveryError> {
            let response = self
                .client
                .post(&self.url)
                .json(mail)
                .send()
                .await
                .map_err(|error| {
                    EmailDeliveryError(format!(
                        "email webhook request failed: {}",
                        common::error::cause_chain(&error.without_url())
                    ))
                })?;

            if response.status().is_success() {
                Ok(())
            } else {
                Err(EmailDeliveryError(format!(
                    "email webhook returned {}",
                    response.status()
                )))
            }
        }
    }

    pub(crate) struct SmtpHandler {
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
        templates: Tera,
    }

    impl SmtpHandler {
        /// Loads the templates matching `templates_glob` and fails if one of
        /// the required ones is missing, so a bad override stops the boot
        /// instead of failing every registration. Also refuses SMTP without
        /// TLS to a non-loopback host.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new(
            host: &str,
            port: u16,
            tls: SmtpTls,
            credentials: Option<(String, SecretString)>,
            from: &str,
            timeout: Duration,
            templates_glob: &str,
        ) -> anyhow::Result<Self> {
            crate::config::require_tls_or_loopback(host, tls)?;
            let builder = match tls {
                SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?,
                SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(host)?,
                SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
            };
            let mut builder = builder.port(port).timeout(Some(timeout));
            if let Some((username, password)) = credentials {
                builder = builder
                    .credentials(Credentials::new(username, password.expose_secret().into()));
            }

            let mut templates = Tera::new();
            templates
                .load_from_glob(templates_glob)
                .map_err(|error| anyhow::anyhow!("could not load email templates: {error}"))?;
            for name in REQUIRED_TEMPLATES {
                if !templates.get_template_names().any(|n| n == name) {
                    anyhow::bail!("email template {name:?} not found in {templates_glob:?}");
                }
            }

            Ok(Self {
                transport: builder.build(),
                from: from
                    .parse()
                    .map_err(|error| anyhow::anyhow!("invalid email from address: {error}"))?,
                templates,
            })
        }

        fn render(&self, template: &str, ctx: &Context) -> Result<String, EmailDeliveryError> {
            self.templates.render(template, ctx).map_err(|error| {
                EmailDeliveryError(format!("could not render {template}: {error}"))
            })
        }
    }

    #[async_trait::async_trait]
    impl EmailVerificationHandler for SmtpHandler {
        async fn send(&self, mail: &VerificationEmail) -> Result<(), EmailDeliveryError> {
            let mut ctx = Context::new();
            ctx.insert("email", &mail.email);
            ctx.insert("code", &mail.code);
            ctx.insert("verify_page_url", &mail.verify_page_url);
            ctx.insert(
                "expires_at",
                &mail.expires_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            );

            let subject = self.render("verify-email.subject.txt", &ctx)?;
            let text = self.render("verify-email.txt", &ctx)?;
            let html = self.render("verify-email.html", &ctx)?;

            let to: Mailbox = mail
                .email
                .parse()
                .map_err(|error| EmailDeliveryError(format!("invalid recipient: {error}")))?;
            let message = Message::builder()
                .from(self.from.clone())
                .to(to)
                .subject(subject.trim())
                .multipart(MultiPart::alternative_plain_html(text, html))
                .map_err(|error| EmailDeliveryError(format!("could not build message: {error}")))?;

            self.transport
                .send(message)
                .await
                .map(|_| ())
                .map_err(|error| {
                    EmailDeliveryError(format!(
                        "smtp send failed: {}",
                        common::error::cause_chain(&error)
                    ))
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use super::*;
    use crate::model::user::User;
    use crate::server::AppState;
    use crate::storage::{
        CheckCodeOutcome, EmailVerificationCodeStorage, IssueCodeOutcome, LoginSessionStorage,
        UserStorage, VerificationSessionStorage,
    };
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiJson;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    /// What a handler was asked to send.
    #[derive(Debug)]
    struct Sent {
        email: String,
        code: String,
        verify_page_url: String,
        expires_at: chrono::DateTime<chrono::Utc>,
    }

    /// Reports every send on a channel; fails each one when told to.
    struct Recorder {
        tx: mpsc::UnboundedSender<Sent>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl EmailVerificationHandler for Recorder {
        async fn send(&self, mail: &VerificationEmail) -> Result<(), EmailDeliveryError> {
            let _ = self.tx.send(Sent {
                email: mail.email.clone(),
                code: mail.code.clone(),
                verify_page_url: mail.verify_page_url.clone(),
                expires_at: mail.expires_at,
            });
            if self.fail {
                Err(EmailDeliveryError("boom".to_string()))
            } else {
                Ok(())
            }
        }
    }

    async fn state_with(fail: bool) -> (AppState, mpsc::UnboundedReceiver<Sent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut state = AppState::for_test().await;
        state.email_verification.handler = Some(Arc::new(Recorder { tx, fail }));
        state.email_verification.login_public_url = Some("https://login.test/".to_string());
        state.email_verification.codes =
            crate::storage::in_memory::InMemoryEmailVerificationCodeStorage::new(900, 0);
        state.email_verification.code_ttl_secs = 900;
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
            .create_session(user_id)
            .await
    }

    async fn code_for(state: &mut AppState, user_id: Uuid) -> String {
        match state.email_verification.codes.issue_code(user_id).await {
            IssueCodeOutcome::Issued(code) => code,
            IssueCodeOutcome::CoolingDown | IssueCodeOutcome::Locked => {
                unreachable!("no cooldown or lock")
            }
        }
    }

    async fn next_sent(rx: &mut mpsc::UnboundedReceiver<Sent>) -> Sent {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a mail was sent")
            .expect("channel open")
    }

    /// Nothing was sent: gives a background send time to show up first.
    async fn assert_nothing_sent(rx: &mut mpsc::UnboundedReceiver<Sent>) {
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(rx.try_recv().is_err(), "a mail was sent");
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
    async fn send_mails_a_six_digit_code_and_the_page_to_enter_it_on() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;

        send_verification_email(&mut state, user_id, "alice@example.com")
            .await
            .expect("a send was started")
            .await
            .unwrap();

        let sent = next_sent(&mut rx).await;
        assert_eq!(sent.email, "alice@example.com");
        assert_eq!(sent.code.len(), 6);
        assert!(sent.code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(sent.verify_page_url, "https://login.test/verify-email.html");
        let expires_in = sent.expires_at - chrono::Utc::now();
        assert!(
            (895..=900).contains(&expires_in.num_seconds()),
            "{expires_in}"
        );
        assert_eq!(
            state
                .email_verification
                .codes
                .check_code(user_id, &sent.code)
                .await,
            CheckCodeOutcome::Verified
        );
    }

    #[tokio::test]
    async fn send_does_not_wait_for_a_slow_handler() {
        struct Slow;
        #[async_trait::async_trait]
        impl EmailVerificationHandler for Slow {
            async fn send(&self, _: &VerificationEmail) -> Result<(), EmailDeliveryError> {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(())
            }
        }
        let (mut state, _rx) = state_with(false).await;
        state.email_verification.handler = Some(Arc::new(Slow));

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
        state.email_verification.handler = None;

        let handle = send_verification_email(&mut state, Uuid::new_v4(), "alice@example.com").await;

        assert!(handle.is_none());
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
        assert!(second.is_none(), "inside the cooldown");
        let _ = next_sent(&mut rx).await;
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn request_sends_a_code_for_the_sessions_unverified_account() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;

        let status = request_email_verification(State(state), ApiJson(request_req(&session))).await;

        assert_eq!(status, Ok(StatusCode::ACCEPTED));
        assert_eq!(next_sent(&mut rx).await.email, "alice@example.com");
    }

    #[tokio::test]
    async fn request_refuses_an_unknown_session_without_sending() {
        let (state, mut rx) = state_with(false).await;

        let result = request_email_verification(State(state), ApiJson(request_req("nope"))).await;

        assert_eq!(result, Err(EmailVerificationRequestError::InvalidSession));
        assert_nothing_sent(&mut rx).await;
    }

    #[tokio::test]
    async fn request_sends_nothing_for_an_already_verified_account() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", true).await;
        let session = session_for(&mut state, user_id).await;

        let status = request_email_verification(State(state), ApiJson(request_req(&session))).await;

        assert_eq!(status, Ok(StatusCode::ACCEPTED));
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
        assert!(user.email_verified_by_code);
        // The login session is the real thing: it redeems for this user, once.
        let mut sessions = state.login_sessions.clone();
        assert_eq!(
            sessions.take_session(&response.0.login_session).await,
            Some(user_id)
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
        let wrong = if code == "000000" { "000001" } else { "000000" };

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
            Some(user_id)
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
        let wrong = if code == "000000" { "000001" } else { "000000" };

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
            ApiJson(confirm_req(&session, "123456")),
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
    async fn confirm_while_locked_out_fails_even_with_the_right_code() {
        let (mut state, _rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let session = session_for(&mut state, user_id).await;
        let mut code = code_for(&mut state, user_id).await;
        for _ in 0..2 {
            let wrong = if code == "000000" { "000001" } else { "000000" };
            for _ in 0..5 {
                let _ = confirm_email_verification(
                    State(state.clone()),
                    ApiJson(confirm_req(&session, wrong)),
                )
                .await;
            }
            if let IssueCodeOutcome::Issued(next) =
                state.email_verification.codes.issue_code(user_id).await
            {
                code = next;
            }
        }

        let result =
            confirm_email_verification(State(state.clone()), ApiJson(confirm_req(&session, &code)))
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
    }

    #[tokio::test]
    async fn send_is_skipped_while_locked_out() {
        let (mut state, mut rx) = state_with(false).await;
        let user_id = add_user(&mut state, "alice@example.com", false).await;
        let mut code = code_for(&mut state, user_id).await;
        for _ in 0..2 {
            let wrong = if code == "000000" { "000001" } else { "000000" };
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

        let handle = send_verification_email(&mut state, user_id, "alice@example.com").await;

        assert!(handle.is_none());
        assert_nothing_sent(&mut rx).await;
    }
}

#[cfg(test)]
mod delivery_tests {
    use super::delivery::*;
    use super::*;
    use crate::config::SmtpTls;
    use chrono::{DateTime, Utc};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use uuid::Uuid;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn mail() -> VerificationEmail {
        VerificationEmail {
            user_id: Uuid::nil(),
            email: "alice@example.com".to_string(),
            code: "042517".to_string(),
            verify_page_url: "https://login.test/verify-email.html".to_string(),
            expires_at: DateTime::parse_from_rfc3339("2026-10-03T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[tokio::test]
    async fn webhook_posts_the_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(body_partial_json(serde_json::json!({
                "email": "alice@example.com",
                "code": "042517",
                "verify_page_url": "https://login.test/verify-email.html",
                "expires_at": "2026-10-03T12:00:00Z",
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let handler = WebhookHandler::new(format!("{}/hook", server.uri()), TIMEOUT).unwrap();

        assert_eq!(handler.send(&mail()).await, Ok(()));
    }

    #[tokio::test]
    async fn webhook_fails_on_a_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let handler = WebhookHandler::new(format!("{}/hook", server.uri()), TIMEOUT).unwrap();

        assert!(handler.send(&mail()).await.is_err());
    }

    #[test]
    fn webhook_refuses_plain_http_to_a_non_local_host() {
        assert!(WebhookHandler::new("http://hooks.example.com/x".to_string(), TIMEOUT).is_err());
    }

    /// Accepts one SMTP session and returns the DATA it received.
    async fn fake_smtp() -> (u16, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut read = BufReader::new(read);
            write.write_all(b"220 fake ESMTP\r\n").await.unwrap();
            let mut data = String::new();
            let mut in_data = false;
            let mut line = String::new();
            loop {
                line.clear();
                if read.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                if in_data {
                    if line == ".\r\n" {
                        in_data = false;
                        write.write_all(b"250 queued\r\n").await.unwrap();
                    } else {
                        data.push_str(&line);
                    }
                    continue;
                }
                let upper = line.to_uppercase();
                let reply: &[u8] = if upper.starts_with("EHLO") {
                    b"250 fake\r\n"
                } else if upper.starts_with("DATA") {
                    in_data = true;
                    b"354 go\r\n"
                } else if upper.starts_with("QUIT") {
                    write.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                write.write_all(reply).await.unwrap();
            }
            data
        });
        (port, task)
    }

    fn smtp(port: u16, glob: &str) -> anyhow::Result<SmtpHandler> {
        SmtpHandler::new(
            "127.0.0.1",
            port,
            SmtpTls::None,
            None,
            "WeaveAuth <no-reply@example.com>",
            TIMEOUT,
            glob,
        )
    }

    #[tokio::test]
    async fn smtp_sends_the_default_templates() {
        let (port, session) = fake_smtp().await;
        let handler = smtp(port, TEMPLATES_GLOB).unwrap();

        handler.send(&mail()).await.unwrap();

        let data = session.await.unwrap();
        assert!(data.contains("Subject: Your verification code"), "{data}");
        assert!(data.contains("To: alice@example.com"), "{data}");
        assert!(data.contains("042517"), "{data}");
        assert!(
            data.contains("https://login.test/verify-email.html"),
            "{data}"
        );
        // Quoted-printable wraps lines, so only the unbroken part is checked.
        assert!(data.contains("2026-10-03 12:00 UTC"), "{data}");
    }

    fn override_dir(files: &[(&str, &str)]) -> String {
        let dir = std::env::temp_dir().join(format!("wa-email-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
        format!("{}/*", dir.display())
    }

    const ALL: [(&str, &str); 3] = [
        ("verify-email.subject.txt", "Custom subject"),
        ("verify-email.txt", "custom text {{ code }}"),
        ("verify-email.html", "<p>custom html</p>"),
    ];

    #[tokio::test]
    async fn smtp_uses_a_deployers_templates() {
        let (port, session) = fake_smtp().await;
        let handler = smtp(port, &override_dir(&ALL)).unwrap();

        handler.send(&mail()).await.unwrap();

        let data = session.await.unwrap();
        assert!(data.contains("Subject: Custom subject"), "{data}");
        assert!(data.contains("custom html"), "{data}");
        assert!(!data.contains("Your verification code"), "{data}");
    }

    #[test]
    fn smtp_refuses_a_template_dir_missing_a_required_template() {
        let error = smtp(1, &override_dir(&ALL[..2])).err().expect("must fail");

        assert!(error.to_string().contains("verify-email.html"), "{error}");
    }

    #[tokio::test]
    async fn smtp_reports_a_refused_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let handler = smtp(port, TEMPLATES_GLOB).unwrap();

        let error = handler.send(&mail()).await.unwrap_err();

        assert!(error.0.contains("smtp send failed"), "{error}");
    }

    #[test]
    fn smtp_refuses_plaintext_to_a_remote_host() {
        let result = SmtpHandler::new(
            "smtp.example.com",
            25,
            SmtpTls::None,
            None,
            "no-reply@example.com",
            TIMEOUT,
            TEMPLATES_GLOB,
        );

        let error = result.err().expect("must fail");
        assert!(error.to_string().contains("smtp.example.com"), "{error}");
    }

    #[test]
    fn smtp_refuses_an_invalid_from_address() {
        let result = SmtpHandler::new(
            "127.0.0.1",
            1,
            SmtpTls::None,
            None,
            "not an address",
            TIMEOUT,
            TEMPLATES_GLOB,
        );

        assert!(result.is_err());
    }
}
