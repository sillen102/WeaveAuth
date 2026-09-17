use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::model::session::SessionData;
use crate::storage::{ExpiryMaintenance, SessionStorage};
use chrono::Utc;

#[derive(Clone)]
pub(crate) struct InMemorySessionStorage {
    sessions: Arc<Mutex<HashMap<String, SessionData>>>,
}

impl InMemorySessionStorage {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl SessionStorage for InMemorySessionStorage {
    async fn save_session(&mut self, session_id: String, data: SessionData) {
        self.sessions.lock().await.insert(session_id, data);
    }

    async fn get_session(&self, session_id: &str) -> Option<SessionData> {
        self.sessions.lock().await.get(session_id).cloned()
    }
}

impl ExpiryMaintenance for InMemorySessionStorage {
    async fn sweep_expired(&mut self) {
        let now = Utc::now();
        // `refresh_expires_at` is the outer bound -- the proxy can still
        // silently refresh the access token up until then.
        self.sessions
            .lock()
            .await
            .retain(|_, data| data.refresh_expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use secrecy::ExposeSecret;

    fn sample_session(token: &str) -> SessionData {
        SessionData {
            access_token: token.into(),
            refresh_token: format!("{token}-refresh").into(),
            expires_at: Utc::now(),
            refresh_expires_at: Utc::now(),
            user_id: uuid::Uuid::new_v4(),
        }
    }

    #[tokio::test]
    async fn get_session_returns_none_for_unknown_id() {
        let storage = InMemorySessionStorage::new();
        assert!(storage.get_session("missing").await.is_none());
    }

    #[tokio::test]
    async fn save_then_get_round_trips() {
        let mut storage = InMemorySessionStorage::new();
        storage
            .save_session("session-1".to_string(), sample_session("token-1"))
            .await;

        let data = storage.get_session("session-1").await.unwrap();
        assert_eq!(data.access_token.expose_secret(), "token-1");
        assert_eq!(data.refresh_token.expose_secret(), "token-1-refresh");
    }

    #[tokio::test]
    async fn get_session_does_not_consume_it() {
        let mut storage = InMemorySessionStorage::new();
        storage
            .save_session("session-1".to_string(), sample_session("token-1"))
            .await;

        assert!(storage.get_session("session-1").await.is_some());
        assert!(storage.get_session("session-1").await.is_some());
    }

    #[tokio::test]
    async fn saving_the_same_id_again_overwrites_the_previous_entry() {
        let mut storage = InMemorySessionStorage::new();
        storage
            .save_session("session-1".to_string(), sample_session("token-1"))
            .await;
        storage
            .save_session("session-1".to_string(), sample_session("token-2"))
            .await;

        let data = storage.get_session("session-1").await.unwrap();
        assert_eq!(data.access_token.expose_secret(), "token-2");
    }
}
