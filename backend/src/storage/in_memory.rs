use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;
use uuid::Uuid;
use crate::model::pkce::CodeChallengeMethod;
use crate::model::session::Session;
use crate::model::user::User;
use crate::storage::{PkceStorage, SessionStorage, UserStorage};

pub(crate) struct InMemorySessionStorage {
    sessions: HashMap<String, Session>,
}

impl InMemorySessionStorage {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

impl SessionStorage for InMemorySessionStorage {
    async fn save_session(&mut self, session: Session) {
        self.sessions.insert(session.cookie.clone(), session);
    }

    async fn get_session(&self, cookie: &str) -> Option<&Session> {
        self.sessions.get(cookie)
    }
}

pub(crate) struct InMemoryUserStorage {
    users: HashMap<Uuid, User>,
}

impl InMemoryUserStorage {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }
}

impl UserStorage for InMemoryUserStorage {
    async fn save_user(&mut self, user: User) {
        self.users.insert(user.id, user);
    }

    async fn get_user(&self, id: Uuid) -> Option<&User> {
        self.users.get(&id)
    }
}

#[derive(Clone)]
pub(crate) struct InMemoryPkceStorage {
    code_challenges: Arc<Mutex<HashMap<String, (String, CodeChallengeMethod, DateTime<Utc>, String)>>>,
    ttl_secs: i64,
}

impl InMemoryPkceStorage {
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            code_challenges: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
        }
    }
}

impl PkceStorage for InMemoryPkceStorage {
    async fn save_code_challenge(
        &mut self,
        auth_code: String,
        code_challenge: String,
        code_challenge_method: CodeChallengeMethod,
        redirect_uri: String,
    ) {
        self.code_challenges
            .lock()
            .await
            .insert(auth_code, (code_challenge, code_challenge_method, Utc::now(), redirect_uri));
    }

    async fn take_code_challenge(&mut self, auth_code: &str) -> Option<(String, CodeChallengeMethod, String)> {
        let (challenge, method, issued_at, redirect_uri) = self.code_challenges.lock().await.remove(auth_code)?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        Some((challenge, method, redirect_uri))
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;
    use crate::model::pkce::CodeChallengeMethod;
    use crate::model::session::Session;
    use crate::model::user::User;
    use crate::storage::in_memory::{InMemoryPkceStorage, InMemorySessionStorage, InMemoryUserStorage};
    use crate::storage::{PkceStorage, SessionStorage, UserStorage};

    #[tokio::test]
    async fn test_save_session() {
        let mut storage = InMemorySessionStorage::new();
        let user_id = Uuid::new_v4();
        let session = Session::new(user_id);
        let cookie = session.cookie.clone();
        storage.save_session(session).await;
        let retrieved_session = storage.get_session(&cookie).await;
        assert!(retrieved_session.is_some());
        assert_eq!(retrieved_session.unwrap().user_id, user_id);
    }

    #[tokio::test]
    async fn test_get_session() {
        let storage = InMemorySessionStorage::new();
        let session = storage.get_session("test_cookie").await;
        assert!(session.is_none());
    }

    #[tokio::test]
    async fn test_get_session_returns_session() {
        let mut storage = InMemorySessionStorage::new();
        let user_id = Uuid::new_v4();
        let session = Session::new(user_id);
        let cookie = session.cookie.clone();
        storage.sessions.insert(cookie.clone(), session);
        let retrieved_session = storage.get_session(&cookie).await;
        assert!(retrieved_session.is_some());
        assert_eq!(retrieved_session.unwrap().user_id, user_id);
    }

    #[tokio::test]
    async fn test_save_user() {
        let mut storage = InMemoryUserStorage::new();
        let user = User::default();
        let user_id = user.id;
        storage.save_user(user).await;
        let retrieved_user = storage.get_user(user_id).await;
        assert!(retrieved_user.is_some());
        assert_eq!(retrieved_user.unwrap().id, user_id);
    }

    #[tokio::test]
    async fn test_get_user() {
        let storage = InMemoryUserStorage::new();
        let user = storage.get_user(Uuid::new_v4()).await;
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_take_code_challenge() {
        let mut storage = InMemoryPkceStorage::new(300);
        let challenge = storage.take_code_challenge("test_code").await;
        assert!(challenge.is_none());
    }

    #[tokio::test]
    async fn test_save_code_challenge() {
        let mut storage = InMemoryPkceStorage::new(300);
        storage
            .save_code_challenge(
                "test_code".to_string(),
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
            )
            .await;
        let challenge = storage.take_code_challenge("test_code").await;
        assert_eq!(
            challenge,
            Some((
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn test_take_code_challenge_is_single_use() {
        let mut storage = InMemoryPkceStorage::new(300);
        storage
            .save_code_challenge(
                "test_code".to_string(),
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
            )
            .await;
        storage.take_code_challenge("test_code").await;
        let challenge = storage.take_code_challenge("test_code").await;
        assert!(challenge.is_none());
    }

    #[tokio::test]
    async fn test_take_code_challenge_rejects_expired_entries() {
        // A negative TTL means "expired the instant it's issued" -- avoids
        // sleeping in the test to exercise the expiry branch.
        let mut storage = InMemoryPkceStorage::new(-1);
        storage
            .save_code_challenge(
                "test_code".to_string(),
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
            )
            .await;
        let challenge = storage.take_code_challenge("test_code").await;
        assert!(challenge.is_none());
    }
}
