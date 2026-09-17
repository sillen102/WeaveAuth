use chrono::{DateTime, Utc};
use secrecy::SecretString;
use uuid::Uuid;

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct SessionData {
    pub access_token: SecretString,
    pub refresh_token: SecretString,
    pub expires_at: DateTime<Utc>,
    /// When `refresh_token` itself dies -- once this passes, the proxy can no
    /// longer silently redeem a fresh access token and forces a full re-login.
    pub refresh_expires_at: DateTime<Utc>,
    /// The user backend authenticated before issuing this token -- carried
    /// through from `/oauth/token`'s response.
    pub user_id: Uuid,
}
