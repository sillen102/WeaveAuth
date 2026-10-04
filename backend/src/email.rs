//! How an email leaves WeaveAuth: over SMTP with templates, to a webhook, or
//! to a plugin process. One handler serves every kind of email; the kind picks
//! the templates, the plugin hook name and the webhook payload's `kind`.

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

/// Deployer-replaceable email templates: `<name>.subject.txt`, `<name>.txt`
/// and `<name>.html` for each `EmailKind::template_name`. Shared with the
/// login pages under the repo's top-level `templates/`.
pub(crate) const TEMPLATES_GLOB: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../templates/emails/*");

const REQUIRED_TEMPLATES: [&str; 6] = [
    "verify-email.subject.txt",
    "verify-email.txt",
    "verify-email.html",
    "password-reset.subject.txt",
    "password-reset.txt",
    "password-reset.html",
];

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("{0}")]
pub(crate) struct EmailDeliveryError(pub(crate) String);

/// What the handler is given, and the webhook's JSON body. Owned, because
/// the send runs in a background task.
#[derive(Serialize)]
pub(crate) struct OutboundEmail {
    pub(crate) user_id: Uuid,
    /// The address on the account, never one taken from a request.
    pub(crate) email: String,
    /// When the code or link stops working (RFC 3339 in the webhook payload).
    pub(crate) expires_at: DateTime<Utc>,
    #[serde(flatten)]
    pub(crate) kind: EmailKind,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum EmailKind {
    EmailVerification {
        /// The 9-digit code the user types in.
        code: String,
        /// Login's page where the code is entered.
        verify_page_url: String,
    },
    PasswordReset {
        /// Login's reset page with the single-use token in the fragment.
        reset_url: String,
    },
}

impl EmailKind {
    /// The hook name on the generic plugin contract (`PluginRequest::hook`).
    fn hook(&self) -> &'static str {
        match self {
            Self::EmailVerification { .. } => "email_verification",
            Self::PasswordReset { .. } => "password_reset",
        }
    }

    fn template_name(&self) -> &'static str {
        match self {
            Self::EmailVerification { .. } => "verify-email",
            Self::PasswordReset { .. } => "password-reset",
        }
    }
}

#[async_trait::async_trait]
pub(crate) trait EmailHandler: Send + Sync {
    async fn send(&self, mail: &OutboundEmail) -> Result<(), EmailDeliveryError>;
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
impl EmailHandler for PluginHandler {
    async fn send(&self, mail: &OutboundEmail) -> Result<(), EmailDeliveryError> {
        let Ok(serde_json::Value::Object(mut data)) = serde_json::to_value(&mail.kind) else {
            return Err(EmailDeliveryError("payload is not an object".to_string()));
        };
        data.remove("kind");
        data.insert(
            "expires_at".to_string(),
            mail.expires_at
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                .into(),
        );
        let request = PluginRequest {
            hook: mail.kind.hook().to_string(),
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
                    "plugin rejected the {} email: {:?}: {}",
                    mail.kind.hook(),
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
impl EmailHandler for WebhookHandler {
    async fn send(&self, mail: &OutboundEmail) -> Result<(), EmailDeliveryError> {
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
            builder =
                builder.credentials(Credentials::new(username, password.expose_secret().into()));
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
        self.templates
            .render(template, ctx)
            .map_err(|error| EmailDeliveryError(format!("could not render {template}: {error}")))
    }
}

#[async_trait::async_trait]
impl EmailHandler for SmtpHandler {
    async fn send(&self, mail: &OutboundEmail) -> Result<(), EmailDeliveryError> {
        let mut ctx = Context::from_serialize(&mail.kind)
            .map_err(|error| EmailDeliveryError(format!("could not build context: {error}")))?;
        ctx.insert("email", &mail.email);
        ctx.insert(
            "expires_at",
            &mail.expires_at.format("%Y-%m-%d %H:%M UTC").to_string(),
        );

        let name = mail.kind.template_name();
        let subject = self.render(&format!("{name}.subject.txt"), &ctx)?;
        let text = self.render(&format!("{name}.txt"), &ctx)?;
        let html = self.render(&format!("{name}.html"), &ctx)?;

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

#[cfg(test)]
mod tests {
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

    fn expires_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-03T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn mail() -> OutboundEmail {
        OutboundEmail {
            user_id: Uuid::nil(),
            email: "alice@example.com".to_string(),
            expires_at: expires_at(),
            kind: EmailKind::EmailVerification {
                code: "042517".to_string(),
                verify_page_url: "https://login.test/verify-email.html".to_string(),
            },
        }
    }

    fn reset_mail() -> OutboundEmail {
        OutboundEmail {
            user_id: Uuid::nil(),
            email: "alice@example.com".to_string(),
            expires_at: expires_at(),
            kind: EmailKind::PasswordReset {
                reset_url: "https://login.test/reset-password.html#token=tok3n".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn webhook_posts_the_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(body_partial_json(serde_json::json!({
                "kind": "email_verification",
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
    async fn webhook_posts_a_password_reset_with_its_kind() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(body_partial_json(serde_json::json!({
                "kind": "password_reset",
                "email": "alice@example.com",
                "reset_url": "https://login.test/reset-password.html#token=tok3n",
                "expires_at": "2026-10-03T12:00:00Z",
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let handler = WebhookHandler::new(format!("{}/hook", server.uri()), TIMEOUT).unwrap();

        assert_eq!(handler.send(&reset_mail()).await, Ok(()));
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

    #[tokio::test]
    async fn smtp_sends_a_password_reset_with_its_own_templates() {
        let (port, session) = fake_smtp().await;
        let handler = smtp(port, TEMPLATES_GLOB).unwrap();

        handler.send(&reset_mail()).await.unwrap();

        let data = session.await.unwrap();
        assert!(data.contains("Subject: Reset your password"), "{data}");
        assert!(data.contains("To: alice@example.com"), "{data}");
        assert!(data.contains("token=3Dtok3n"), "{data}");
    }

    /// A temp dir of template overrides, deleted when dropped.
    struct OverrideDir(std::path::PathBuf);

    impl OverrideDir {
        fn new(files: &[(&str, &str)]) -> Self {
            let dir = std::env::temp_dir().join(format!("wa-email-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            for (name, body) in files {
                std::fs::write(dir.join(name), body).unwrap();
            }
            Self(dir)
        }

        fn glob(&self) -> String {
            format!("{}/*", self.0.display())
        }
    }

    impl Drop for OverrideDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const ALL: [(&str, &str); 6] = [
        ("password-reset.subject.txt", "Custom reset subject"),
        ("password-reset.txt", "custom text {{ reset_url }}"),
        ("password-reset.html", "<p>custom reset html</p>"),
        ("verify-email.subject.txt", "Custom subject"),
        ("verify-email.txt", "custom text {{ code }}"),
        ("verify-email.html", "<p>custom html</p>"),
    ];

    #[tokio::test]
    async fn smtp_uses_a_deployers_templates() {
        let (port, session) = fake_smtp().await;
        let dir = OverrideDir::new(&ALL);
        let handler = smtp(port, &dir.glob()).unwrap();

        handler.send(&mail()).await.unwrap();

        let data = session.await.unwrap();
        assert!(data.contains("Subject: Custom subject"), "{data}");
        assert!(data.contains("custom html"), "{data}");
        assert!(!data.contains("Your verification code"), "{data}");
    }

    #[test]
    fn smtp_refuses_a_template_dir_missing_a_required_template() {
        let error = smtp(1, &OverrideDir::new(&ALL[..5]).glob())
            .err()
            .expect("must fail");

        assert!(error.to_string().contains("verify-email.html"), "{error}");
    }

    #[test]
    fn smtp_refuses_a_template_dir_missing_a_password_reset_template() {
        let error = smtp(1, &OverrideDir::new(&ALL[1..]).glob())
            .err()
            .expect("must fail");

        assert!(
            error.to_string().contains("password-reset.subject.txt"),
            "{error}"
        );
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
