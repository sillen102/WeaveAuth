use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) struct Session {
    pub cookie: String,
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl Session {
    pub(crate) fn new(user_id: Uuid) -> Self {
        Self {
            cookie: String::new(),
            access_token: String::new(),
            refresh_token: String::new(),
            user_id,
            created_at: Utc::now(),
            expires_at: Utc::now(),
        }
    }
}
