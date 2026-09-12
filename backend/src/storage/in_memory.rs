use crate::model::pkce::CodeChallengeMethod;
use crate::model::user::User;
use crate::storage::{LoginSessionStorage, PkceStorage, UserStorage};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct InMemoryUserStorage {
    users: Arc<Mutex<HashMap<Uuid, User>>>,
}

impl InMemoryUserStorage {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl UserStorage for InMemoryUserStorage {
    async fn create_user(&mut self, user: User) -> bool {
        let mut users = self.users.lock().await;
        if users.values().any(|u| u.identifier == user.identifier) {
            return false;
        }
        users.insert(user.id, user);
        true
    }

    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        self.users
            .lock()
            .await
            .values()
            .find(|u| u.identifier == identifier)
            .cloned()
    }
}

#[derive(Clone)]
pub(crate) struct InMemoryPkceStorage {
    code_challenges:
        Arc<Mutex<HashMap<String, (String, CodeChallengeMethod, DateTime<Utc>, String, Uuid)>>>,
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
        user_id: Uuid,
    ) {
        self.code_challenges.lock().await.insert(
            auth_code,
            (
                code_challenge,
                code_challenge_method,
                Utc::now(),
                redirect_uri,
                user_id,
            ),
        );
    }

    async fn take_code_challenge(
        &mut self,
        auth_code: &str,
    ) -> Option<(String, CodeChallengeMethod, String, Uuid)> {
        let (challenge, method, issued_at, redirect_uri, user_id) =
            self.code_challenges.lock().await.remove(auth_code)?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        Some((challenge, method, redirect_uri, user_id))
    }
}

#[derive(Clone)]
pub(crate) struct InMemoryLoginSessionStorage {
    sessions: Arc<Mutex<HashMap<String, (Uuid, DateTime<Utc>)>>>,
    ttl_secs: i64,
}

impl InMemoryLoginSessionStorage {
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
        }
    }
}

impl LoginSessionStorage for InMemoryLoginSessionStorage {
    async fn create_session(&mut self, user_id: Uuid) -> String {
        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        self.sessions
            .lock()
            .await
            .insert(token.clone(), (user_id, Utc::now()));
        token
    }

    async fn take_session(&mut self, token: &str) -> Option<Uuid> {
        let (user_id, issued_at) = self.sessions.lock().await.remove(token)?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        Some(user_id)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;
    use crate::model::pkce::CodeChallengeMethod;
    use crate::model::user::User;
    use crate::storage::in_memory::{
        InMemoryLoginSessionStorage, InMemoryPkceStorage, InMemoryUserStorage,
    };
    use crate::storage::{LoginSessionStorage, PkceStorage, UserStorage};

    #[tokio::test]
    async fn test_create_user() {
        let mut storage = InMemoryUserStorage::new();
        let mut user = User::default();
        user.identifier = "carol".to_string();
        let user_id = user.id;
        assert!(storage.create_user(user).await);
        let retrieved_user = storage.get_user_by_identifier("carol").await;
        assert_eq!(retrieved_user.map(|u| u.id), Some(user_id));
    }

    #[tokio::test]
    async fn test_create_user_rejects_a_taken_identifier() {
        let mut storage = InMemoryUserStorage::new();
        let mut first = User::default();
        first.identifier = "carol".to_string();
        let first_id = first.id;
        assert!(storage.create_user(first).await);

        let mut second = User::default();
        second.identifier = "carol".to_string();
        assert!(!storage.create_user(second).await);

        // The original registration is untouched -- no shadowing, no overwrite.
        let retrieved = storage.get_user_by_identifier("carol").await;
        assert_eq!(retrieved.map(|u| u.id), Some(first_id));
    }

    #[tokio::test]
    async fn test_get_user_by_identifier() {
        let mut storage = InMemoryUserStorage::new();
        let mut user = User::default();
        user.identifier = "alice".to_string();
        storage.create_user(user).await;

        let found = storage.get_user_by_identifier("alice").await;
        assert_eq!(found.map(|u| u.identifier), Some("alice".to_string()));
        assert!(storage.get_user_by_identifier("bob").await.is_none());
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
        let user_id = Uuid::new_v4();
        storage
            .save_code_challenge(
                "test_code".to_string(),
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            )
            .await;
        let challenge = storage.take_code_challenge("test_code").await;
        assert_eq!(
            challenge,
            Some((
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
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
                Uuid::new_v4(),
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
                Uuid::new_v4(),
            )
            .await;
        let challenge = storage.take_code_challenge("test_code").await;
        assert!(challenge.is_none());
    }

    #[tokio::test]
    async fn login_session_round_trips_to_the_user_that_created_it() {
        let mut storage = InMemoryLoginSessionStorage::new(60);
        let user_id = Uuid::new_v4();
        let token = storage.create_session(user_id).await;

        assert_eq!(storage.take_session(&token).await, Some(user_id));
    }

    #[tokio::test]
    async fn login_session_is_single_use() {
        let mut storage = InMemoryLoginSessionStorage::new(60);
        let token = storage.create_session(Uuid::new_v4()).await;

        storage.take_session(&token).await;
        assert_eq!(storage.take_session(&token).await, None);
    }

    #[tokio::test]
    async fn login_session_rejects_unknown_token() {
        let mut storage = InMemoryLoginSessionStorage::new(60);
        assert_eq!(storage.take_session("no-such-token").await, None);
    }

    #[tokio::test]
    async fn login_session_rejects_expired_entries() {
        let mut storage = InMemoryLoginSessionStorage::new(-1);
        let token = storage.create_session(Uuid::new_v4()).await;

        assert_eq!(storage.take_session(&token).await, None);
    }
}
