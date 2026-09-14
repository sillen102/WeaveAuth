use crate::crypto::JwtKeys;
use crate::model::pkce::CodeChallengeMethod;
use crate::model::user::User;
use crate::storage::{
    JwkStorage, LoginSessionStorage, OidcLinkOutcome, OidcLoginState, OidcStateStorage,
    PendingOidcLink, PendingOidcLinkStorage, PkceStorage, RefreshTokenOutcome,
    RefreshTokenStorage, UserStorage, VerifiedEmail,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct InMemoryJwkStorage {
    active_key: Arc<JwtKeys>,
}

impl InMemoryJwkStorage {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            active_key: Arc::new(JwtKeys::generate()?),
        })
    }
}

impl JwkStorage for InMemoryJwkStorage {
    async fn active_key(&self) -> Arc<JwtKeys> {
        self.active_key.clone()
    }

    async fn jwk_set(&self) -> serde_json::Value {
        self.active_key.jwk_set()
    }
}

#[derive(Default)]
struct UserStorageInner {
    users: HashMap<Uuid, User>,
    /// `(provider, subject)` -> user id -- every OIDC identity ever linked to
    /// a user, possibly several per user (one per provider they've signed in
    /// with). Lives behind the same lock as `users` so linking and
    /// find-or-create can't race into two accounts for one identity.
    oidc_identities: HashMap<(String, String), Uuid>,
}

#[derive(Clone)]
pub(crate) struct InMemoryUserStorage {
    inner: Arc<Mutex<UserStorageInner>>,
}

impl InMemoryUserStorage {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(UserStorageInner::default())),
        }
    }
}

impl UserStorage for InMemoryUserStorage {
    async fn create_user(&mut self, user: User) -> bool {
        let mut inner = self.inner.lock().await;
        if inner.users.values().any(|u| u.email == user.email) {
            return false;
        }
        inner.users.insert(user.id, user);
        true
    }

    async fn get_user_by_email(&self, email: &str) -> Option<User> {
        self.inner.lock().await.users.values().find(|u| u.email == email).cloned()
    }

    async fn get_user_by_id(&self, id: Uuid) -> Option<User> {
        self.inner.lock().await.users.get(&id).cloned()
    }

    async fn resolve_oidc_login(&mut self, provider: &str, subject: &str, email: &VerifiedEmail) -> OidcLinkOutcome {
        let email = email.as_str();
        let mut inner = self.inner.lock().await;

        let identity_key = (provider.to_string(), subject.to_string());
        if let Some(user_id) = inner.oidc_identities.get(&identity_key).copied() {
            // `users` is expected to always have an entry for every linked
            // identity's user id -- indexing_slicing is denied crate-wide, so
            // this reads via `get` and treats the (should-be-impossible)
            // missing case as "fall through and re-resolve by email" rather
            // than panicking.
            if let Some(user) = inner.users.get(&user_id) {
                return OidcLinkOutcome::Resolved(user.clone());
            }
        }

        let existing = inner.users.values().find(|u| u.email == email).cloned();
        let user = match existing {
            Some(existing) if !existing.email_verified => {
                return OidcLinkOutcome::RequiresPasswordConfirmation { existing_user_id: existing.id };
            }
            Some(existing) => existing,
            None => {
                let now = Utc::now();
                let user = User {
                    id: Uuid::new_v4(),
                    email: email.to_string(),
                    password: None,
                    email_verified: true,
                    created_at: now,
                    updated_at: now,
                };
                inner.users.insert(user.id, user.clone());
                user
            }
        };

        inner.oidc_identities.insert(identity_key, user.id);
        OidcLinkOutcome::Resolved(user)
    }

    async fn link_verified_oidc_identity(&mut self, user_id: Uuid, provider: &str, subject: &str) -> Option<User> {
        let mut inner = self.inner.lock().await;

        let user = inner.users.get_mut(&user_id)?;
        user.email_verified = true;
        let user = user.clone();

        inner.oidc_identities.insert((provider.to_string(), subject.to_string()), user_id);
        Some(user)
    }
}

/// token -> (provider, subject, existing_user_id, issued_at)
type PendingOidcLinkEntries = HashMap<String, (String, String, Uuid, DateTime<Utc>)>;

#[derive(Clone)]
pub(crate) struct InMemoryPendingOidcLinkStorage {
    entries: Arc<Mutex<PendingOidcLinkEntries>>,
    ttl_secs: i64,
}

impl InMemoryPendingOidcLinkStorage {
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
        }
    }
}

impl PendingOidcLinkStorage for InMemoryPendingOidcLinkStorage {
    async fn save_pending_link(&mut self, provider: String, subject: String, existing_user_id: Uuid) -> String {
        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        self.entries
            .lock()
            .await
            .insert(token.clone(), (provider, subject, existing_user_id, Utc::now()));
        token
    }

    async fn take_pending_link(&mut self, token: &str) -> Option<PendingOidcLink> {
        let (provider, subject, existing_user_id, issued_at) = self.entries.lock().await.remove(token)?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        Some(PendingOidcLink { provider, subject, existing_user_id })
    }
}

/// csrf_state -> (provider, pkce_verifier, nonce, issued_at)
type OidcStateEntries = HashMap<String, (String, String, String, DateTime<Utc>)>;

#[derive(Clone)]
pub(crate) struct InMemoryOidcStateStorage {
    entries: Arc<Mutex<OidcStateEntries>>,
    ttl_secs: i64,
}

impl InMemoryOidcStateStorage {
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
        }
    }
}

impl OidcStateStorage for InMemoryOidcStateStorage {
    async fn save_state(&mut self, csrf_state: String, provider: String, pkce_verifier: String, nonce: String) {
        self.entries
            .lock()
            .await
            .insert(csrf_state, (provider, pkce_verifier, nonce, Utc::now()));
    }

    async fn take_state(&mut self, csrf_state: &str) -> Option<OidcLoginState> {
        let (provider, pkce_verifier, nonce, issued_at) = self.entries.lock().await.remove(csrf_state)?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        Some(OidcLoginState { provider, pkce_verifier, nonce })
    }
}

/// auth_code -> (code_challenge, method, issued_at, redirect_uri, user_id)
type PkceEntries = HashMap<String, (String, CodeChallengeMethod, DateTime<Utc>, String, Uuid)>;

#[derive(Clone)]
pub(crate) struct InMemoryPkceStorage {
    code_challenges: Arc<Mutex<PkceEntries>>,
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

/// session_id -> (user_id, issued_at)
type LoginSessionEntries = HashMap<String, (Uuid, DateTime<Utc>)>;

#[derive(Clone)]
pub(crate) struct InMemoryLoginSessionStorage {
    sessions: Arc<Mutex<LoginSessionEntries>>,
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

struct RefreshTokenRecord {
    user_id: Uuid,
    family_id: Uuid,
    issued_at: DateTime<Utc>,
    used: bool,
}

#[derive(Clone)]
pub(crate) struct InMemoryRefreshTokenStorage {
    tokens: Arc<Mutex<HashMap<String, RefreshTokenRecord>>>,
    ttl_secs: i64,
}

impl InMemoryRefreshTokenStorage {
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
        }
    }
}

impl RefreshTokenStorage for InMemoryRefreshTokenStorage {
    async fn save_refresh_token(&mut self, token: String, user_id: Uuid, family_id: Uuid) {
        self.tokens.lock().await.insert(
            token,
            RefreshTokenRecord {
                user_id,
                family_id,
                issued_at: Utc::now(),
                used: false,
            },
        );
    }

    async fn take_refresh_token(&mut self, token: &str) -> RefreshTokenOutcome {
        let mut tokens = self.tokens.lock().await;
        let Some(record) = tokens.get_mut(token) else {
            return RefreshTokenOutcome::NotFound;
        };

        if (Utc::now() - record.issued_at).num_seconds() > self.ttl_secs {
            tokens.remove(token);
            return RefreshTokenOutcome::NotFound;
        }

        if record.used {
            let family_id = record.family_id;
            tokens.retain(|_, r| r.family_id != family_id);
            return RefreshTokenOutcome::Reused;
        }

        record.used = true;
        RefreshTokenOutcome::Valid {
            user_id: record.user_id,
            family_id: record.family_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;
    use crate::model::pkce::CodeChallengeMethod;
    use crate::model::user::User;
    use crate::storage::in_memory::{
        InMemoryLoginSessionStorage, InMemoryOidcStateStorage, InMemoryPkceStorage,
        InMemoryRefreshTokenStorage, InMemoryUserStorage,
    };
    use crate::storage::{
        LoginSessionStorage, OidcLinkOutcome, OidcLoginState, OidcStateStorage, PkceStorage,
        RefreshTokenOutcome, RefreshTokenStorage, UserStorage, VerifiedEmail,
    };

    fn verified(email: &str) -> VerifiedEmail {
        VerifiedEmail::new(email.to_string(), true).expect("true always verifies")
    }

    #[tokio::test]
    async fn test_create_user() {
        let mut storage = InMemoryUserStorage::new();
        let mut user = User::default();
        user.email = "carol".to_string();
        let user_id = user.id;
        assert!(storage.create_user(user).await);
        let retrieved_user = storage.get_user_by_email("carol").await;
        assert_eq!(retrieved_user.map(|u| u.id), Some(user_id));
    }

    #[tokio::test]
    async fn test_create_user_rejects_a_taken_email() {
        let mut storage = InMemoryUserStorage::new();
        let mut first = User::default();
        first.email = "carol".to_string();
        let first_id = first.id;
        assert!(storage.create_user(first).await);

        let mut second = User::default();
        second.email = "carol".to_string();
        assert!(!storage.create_user(second).await);

        // The original registration is untouched -- no shadowing, no overwrite.
        let retrieved = storage.get_user_by_email("carol").await;
        assert_eq!(retrieved.map(|u| u.id), Some(first_id));
    }

    #[tokio::test]
    async fn test_get_user_by_email() {
        let mut storage = InMemoryUserStorage::new();
        let mut user = User::default();
        user.email = "alice".to_string();
        storage.create_user(user).await;

        let found = storage.get_user_by_email("alice").await;
        assert_eq!(found.map(|u| u.email), Some("alice".to_string()));
        assert!(storage.get_user_by_email("bob").await.is_none());
    }

    #[tokio::test]
    async fn resolve_oidc_login_creates_on_first_login() {
        let mut storage = InMemoryUserStorage::new();
        let outcome = storage.resolve_oidc_login("google", "sub-123", &verified("alice@example.com")).await;

        let OidcLinkOutcome::Resolved(user) = outcome else {
            unreachable!("expected Resolved, got {outcome:?}");
        };
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.password, None);
        assert!(user.email_verified);
    }

    #[tokio::test]
    async fn resolve_oidc_login_returns_the_same_user_on_repeat_login() {
        let mut storage = InMemoryUserStorage::new();
        let OidcLinkOutcome::Resolved(first) =
            storage.resolve_oidc_login("google", "sub-123", &verified("alice@example.com")).await
        else {
            unreachable!("expected Resolved");
        };
        let OidcLinkOutcome::Resolved(second) =
            storage.resolve_oidc_login("google", "sub-123", &verified("alice@example.com")).await
        else {
            unreachable!("expected Resolved");
        };

        assert_eq!(first.id, second.id);
    }

    #[tokio::test]
    async fn resolve_oidc_login_links_directly_into_an_already_verified_account() {
        let mut storage = InMemoryUserStorage::new();
        let local_user = User {
            email: "alice@example.com".to_string(),
            password: Some("hash".to_string()),
            email_verified: true,
            ..User::default()
        };
        storage.create_user(local_user.clone()).await;

        let outcome = storage.resolve_oidc_login("google", "sub-123", &verified("alice@example.com")).await;

        let OidcLinkOutcome::Resolved(oidc_user) = outcome else {
            unreachable!("expected Resolved, got {outcome:?}");
        };
        assert_eq!(oidc_user.id, local_user.id);
        // The password is untouched -- the user can still log in with it too.
        assert_eq!(oidc_user.password.as_deref(), Some("hash"));
    }

    #[tokio::test]
    async fn resolve_oidc_login_links_a_second_provider_to_the_same_account() {
        let mut storage = InMemoryUserStorage::new();
        let OidcLinkOutcome::Resolved(google_user) =
            storage.resolve_oidc_login("google", "google-sub", &verified("alice@example.com")).await
        else {
            unreachable!("expected Resolved");
        };

        let OidcLinkOutcome::Resolved(linkedin_user) =
            storage.resolve_oidc_login("linkedin", "linkedin-sub", &verified("alice@example.com")).await
        else {
            unreachable!("expected Resolved");
        };

        assert_eq!(google_user.id, linkedin_user.id);

        // Both identities now resolve to the same account.
        let OidcLinkOutcome::Resolved(via_google) =
            storage.resolve_oidc_login("google", "google-sub", &verified("alice@example.com")).await
        else {
            unreachable!("expected Resolved");
        };
        assert_eq!(via_google.id, google_user.id);
    }

    #[tokio::test]
    async fn resolve_oidc_login_refuses_to_link_into_an_unverified_account() {
        // The whole point: an OIDC login never silently merges into an
        // unverified local account -- that account could belong to a
        // squatter with no real claim on the email, and merging into it
        // would hand them a login path into the real owner's identity.
        let mut storage = InMemoryUserStorage::new();
        let squatter = User {
            email: "alice@example.com".to_string(),
            password: Some("squatter-hash".to_string()),
            email_verified: false,
            ..User::default()
        };
        storage.create_user(squatter.clone()).await;

        let outcome = storage.resolve_oidc_login("google", "sub-123", &verified("alice@example.com")).await;

        assert_eq!(
            outcome,
            OidcLinkOutcome::RequiresPasswordConfirmation { existing_user_id: squatter.id }
        );
        // Nothing was mutated -- still unverified, no identity linked yet.
        let still_unverified = storage.get_user_by_email("alice@example.com").await.unwrap();
        assert!(!still_unverified.email_verified);
    }

    #[tokio::test]
    async fn link_verified_oidc_identity_marks_the_account_verified_and_links_it() {
        let mut storage = InMemoryUserStorage::new();
        let squatter = User {
            email: "alice@example.com".to_string(),
            password: Some("squatter-hash".to_string()),
            email_verified: false,
            ..User::default()
        };
        storage.create_user(squatter.clone()).await;

        let linked = storage
            .link_verified_oidc_identity(squatter.id, "google", "sub-123")
            .await
            .expect("user still exists");

        assert_eq!(linked.id, squatter.id);
        assert!(linked.email_verified);

        // The newly linked identity now resolves straight to this account.
        let OidcLinkOutcome::Resolved(via_google) =
            storage.resolve_oidc_login("google", "sub-123", &verified("alice@example.com")).await
        else {
            unreachable!("expected Resolved");
        };
        assert_eq!(via_google.id, squatter.id);
    }

    #[tokio::test]
    async fn link_verified_oidc_identity_returns_none_for_an_unknown_user() {
        let mut storage = InMemoryUserStorage::new();

        let result = storage.link_verified_oidc_identity(Uuid::new_v4(), "google", "sub-123").await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn oidc_state_round_trips() {
        let mut storage = InMemoryOidcStateStorage::new(60);
        storage
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;

        assert_eq!(
            storage.take_state("csrf-token").await,
            Some(OidcLoginState {
                provider: "google".to_string(),
                pkce_verifier: "verifier".to_string(),
                nonce: "nonce".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn oidc_state_is_single_use() {
        let mut storage = InMemoryOidcStateStorage::new(60);
        storage
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;
        storage.take_state("csrf-token").await;

        assert_eq!(storage.take_state("csrf-token").await, None);
    }

    #[tokio::test]
    async fn oidc_state_rejects_expired_entries() {
        let mut storage = InMemoryOidcStateStorage::new(-1);
        storage
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;

        assert_eq!(storage.take_state("csrf-token").await, None);
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

    #[tokio::test]
    async fn refresh_token_round_trips_to_the_user_and_family_it_was_saved_with() {
        let mut storage = InMemoryRefreshTokenStorage::new(60);
        let user_id = Uuid::new_v4();
        let family_id = Uuid::new_v4();
        storage
            .save_refresh_token("token1".to_string(), user_id, family_id)
            .await;

        assert_eq!(
            storage.take_refresh_token("token1").await,
            RefreshTokenOutcome::Valid { user_id, family_id }
        );
    }

    #[tokio::test]
    async fn refresh_token_reuse_is_detected_and_revokes_the_whole_family() {
        let mut storage = InMemoryRefreshTokenStorage::new(60);
        let user_id = Uuid::new_v4();
        let family_id = Uuid::new_v4();
        storage
            .save_refresh_token("token1".to_string(), user_id, family_id)
            .await;

        // Legitimate rotation: token1 -> token2, same family.
        assert_eq!(
            storage.take_refresh_token("token1").await,
            RefreshTokenOutcome::Valid { user_id, family_id }
        );
        storage
            .save_refresh_token("token2".to_string(), user_id, family_id)
            .await;

        // token1 gets replayed (stale client or a thief) -- reuse detected.
        assert_eq!(
            storage.take_refresh_token("token1").await,
            RefreshTokenOutcome::Reused
        );

        // The whole family is now dead, including the still-unused sibling.
        assert_eq!(
            storage.take_refresh_token("token2").await,
            RefreshTokenOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn refresh_token_rejects_unknown_token() {
        let mut storage = InMemoryRefreshTokenStorage::new(60);
        assert_eq!(
            storage.take_refresh_token("no-such-token").await,
            RefreshTokenOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn refresh_token_rejects_expired_entries() {
        let mut storage = InMemoryRefreshTokenStorage::new(-1);
        storage
            .save_refresh_token("token1".to_string(), Uuid::new_v4(), Uuid::new_v4())
            .await;

        assert_eq!(
            storage.take_refresh_token("token1").await,
            RefreshTokenOutcome::NotFound
        );
    }
}
