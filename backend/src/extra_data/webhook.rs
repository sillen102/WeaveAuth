use std::collections::HashMap;
use std::time::Duration;

use uuid::Uuid;

use super::{ExtraDataError, ExtraDataHandler, ExtraDataPayload};

/// Forwards extra registration fields to a deployer-configured HTTP
/// endpoint. Any transport error or non-2xx response fails the registration.
pub(crate) struct WebhookHandler {
    client: reqwest::Client,
    url: String,
}

impl WebhookHandler {
    pub(crate) fn new(url: String, timeout: Duration) -> anyhow::Result<Self> {
        require_https_or_loopback(&url)?;

        // No redirects: this is a server-to-server call to a
        // deployer-configured (should be internal-only) target, so
        // following a redirect elsewhere would be a request-forgery vector
        // -- same reasoning as `oidc_http_client` in `server::AppState::new`.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()?;
        Ok(Self { client, url })
    }
}

/// Registration fields include the user's email and whatever the deployer's
/// form collects -- reject a plaintext hop to a non-local host so that
/// doesn't ship over the wire in the clear. `https://` is otherwise always
/// required; `http://` is only accepted for loopback, for local dev/testing
/// against a webhook running on the same machine.
fn require_https_or_loopback(url: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid extra-data webhook url {url:?}: {e}"))?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    let is_loopback = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if is_loopback {
        return Ok(());
    }
    anyhow::bail!("extra-data webhook url {url:?} must use https (http is only allowed for loopback hosts)")
}

#[async_trait::async_trait]
impl ExtraDataHandler for WebhookHandler {
    async fn handle(&self, user_id: Uuid, email: &str, fields: &HashMap<String, String>) -> Result<(), ExtraDataError> {
        let payload = ExtraDataPayload { user_id, email, fields };
        let response = self.client.post(&self.url).json(&payload).send().await.map_err(|error| {
            tracing::warn!(%error, url = %self.url, "extra-data webhook request failed");
            ExtraDataError
        })?;

        if response.status().is_success() {
            Ok(())
        } else {
            tracing::warn!(status = %response.status(), url = %self.url, "extra-data webhook returned a non-success status");
            Err(ExtraDataError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn fields() -> HashMap<String, String> {
        HashMap::from([("company".to_string(), "Acme".to_string())])
    }

    #[tokio::test]
    async fn succeeds_on_a_2xx_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let handler = WebhookHandler::new(format!("{}/hook", server.uri()), TIMEOUT).expect("valid client");

        let result = handler.handle(Uuid::new_v4(), "alice@example.com", &fields()).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fails_on_a_5xx_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let handler = WebhookHandler::new(format!("{}/hook", server.uri()), TIMEOUT).expect("valid client");

        let result = handler.handle(Uuid::new_v4(), "alice@example.com", &fields()).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fails_when_the_endpoint_is_unreachable() {
        let handler = WebhookHandler::new("http://127.0.0.1:1".to_string(), TIMEOUT).expect("valid client");

        let result = handler.handle(Uuid::new_v4(), "alice@example.com", &fields()).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn times_out_against_a_slow_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&server)
            .await;
        let handler =
            WebhookHandler::new(format!("{}/hook", server.uri()), Duration::from_millis(50)).expect("valid client");

        let result = handler.handle(Uuid::new_v4(), "alice@example.com", &fields()).await;

        assert!(result.is_err());
    }

    #[test]
    fn accepts_https_urls() {
        assert!(require_https_or_loopback("https://internal.example.com/hook").is_ok());
    }

    #[test]
    fn accepts_http_for_loopback_hosts() {
        assert!(require_https_or_loopback("http://127.0.0.1:9000/hook").is_ok());
        assert!(require_https_or_loopback("http://localhost:9000/hook").is_ok());
        assert!(require_https_or_loopback("http://[::1]:9000/hook").is_ok());
    }

    #[test]
    fn rejects_plain_http_for_a_non_loopback_host() {
        assert!(require_https_or_loopback("http://internal.example.com/hook").is_err());
    }

    #[test]
    fn rejects_an_unparseable_url() {
        assert!(require_https_or_loopback("not a url").is_err());
    }
}
