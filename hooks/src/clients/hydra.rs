use super::{UpstreamError, send};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct HydraAdmin {
    client: reqwest::Client,
    base: String,
}

impl HydraAdmin {
    pub(crate) fn new(client: reqwest::Client, base: String) -> Self {
        Self { client, base }
    }

    /// Revokes every consent session of `subject`, and with them the access
    /// and refresh tokens issued under it.
    pub(crate) async fn revoke_consent_sessions(&self, subject: Uuid) -> Result<(), UpstreamError> {
        let request = self
            .client
            .delete(format!("{}/admin/oauth2/auth/sessions/consent", self.base))
            .query(&[("subject", subject.to_string().as_str()), ("all", "true")]);
        send("hydra revoke consent sessions", request).await?;
        Ok(())
    }

    /// Revokes the login (SSO) sessions of `subject`.
    pub(crate) async fn revoke_login_sessions(&self, subject: Uuid) -> Result<(), UpstreamError> {
        let request = self
            .client
            .delete(format!("{}/admin/oauth2/auth/sessions/login", self.base))
            .query(&[("subject", subject.to_string())]);
        send("hydra revoke login sessions", request).await?;
        Ok(())
    }
}
