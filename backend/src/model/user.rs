use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct User {
    pub id: Uuid,
    pub identifier: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub(crate) fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            identifier: String::new(),
            password: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {}
