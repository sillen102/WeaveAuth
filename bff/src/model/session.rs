use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct SessionData {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    /// The user backend authenticated before issuing this token -- carried
    /// through from `/oauth/token`'s response.
    pub user_id: Uuid,
}
