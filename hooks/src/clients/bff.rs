use super::{UpstreamError, send};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct BffInternal {
    client: reqwest::Client,
    base: String,
    api_key: SecretString,
}

impl BffInternal {
    pub(crate) fn new(client: reqwest::Client, base: String, api_key: SecretString) -> Self {
        Self {
            client,
            base,
            api_key,
        }
    }

    /// Ends every bff session of `sub`.
    pub(crate) async fn revoke(&self, sub: Uuid) -> Result<(), UpstreamError> {
        let request = self
            .client
            .post(format!("{}/internal/revoke", self.base))
            .bearer_auth(self.api_key.expose_secret())
            .json(&serde_json::json!({ "sub": sub }));
        send("bff internal revoke", request).await?;
        Ok(())
    }
}
