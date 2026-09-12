use chrono::{DateTime, Utc};

#[derive(Clone)]
pub(crate) struct SessionData {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}
