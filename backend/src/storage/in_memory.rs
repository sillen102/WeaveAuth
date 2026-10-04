use crate::crypto::{Jwk, JwtKeys};
use crate::model::pkce::CodeChallengeMethod;
use crate::model::user::{CredentialStamp, PasswordHash, User};
use crate::storage::{
    CheckCodeOutcome, CreateUserOutcome, EmailVerificationCodeStorage, ExpiryMaintenance,
    IssueCodeOutcome, IssueResetOutcome, JwkRotationError, JwkStorage, LoginSessionStorage,
    MarkVerifiedOutcome, OidcLinkOutcome, OidcLoginState, OidcStateStorage,
    PasswordResetTokenStorage, PendingOidcLink, PendingOidcLinkStorage, PkceStorage,
    RefreshTokenOutcome, RefreshTokenStorage, RevokeOutcome, SetPasswordOutcome,
    UpgradeHashOutcome, UserStorage, VerificationSessionStorage, VerifiedEmail,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

struct JwkKeys {
    active: Arc<JwtKeys>,
    active_since: DateTime<Utc>,
    /// Published but not yet signing, with when it was staged.
    next: Option<(Arc<JwtKeys>, DateTime<Utc>)>,
    /// Public halves of replaced keys, with when they were replaced; the
    /// private key is dropped at rotation.
    retired: Vec<(Jwk, DateTime<Utc>)>,
}

#[derive(Clone)]
pub(crate) struct InMemoryJwkStorage {
    keys: Arc<RwLock<JwkKeys>>,
}

impl InMemoryJwkStorage {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            keys: Arc::new(RwLock::new(JwkKeys {
                active: Arc::new(JwtKeys::generate()?),
                active_since: Utc::now(),
                next: None,
                retired: Vec::new(),
            })),
        })
    }
}

impl JwkStorage for InMemoryJwkStorage {
    async fn active_key(&self) -> Arc<JwtKeys> {
        self.keys.read().await.active.clone()
    }

    async fn jwk_set(&self) -> serde_json::Value {
        let keys = self.keys.read().await;
        let published: Vec<&Jwk> = std::iter::once(keys.active.jwk())
            .chain(keys.next.iter().map(|(key, _)| key.jwk()))
            .chain(keys.retired.iter().map(|(jwk, _)| jwk))
            .collect();
        serde_json::json!({ "keys": published })
    }

    async fn active_since(&self) -> DateTime<Utc> {
        self.keys.read().await.active_since
    }

    async fn next_since(&self) -> Option<DateTime<Utc>> {
        self.keys.read().await.next.as_ref().map(|(_, at)| *at)
    }

    async fn stage_next(&self, now: DateTime<Utc>) -> Result<(), JwkRotationError> {
        if self.keys.read().await.next.is_some() {
            return Ok(());
        }
        // RSA keygen is slow; do it before taking the write lock so token issuance isn't stalled.
        let new_key = tokio::task::spawn_blocking(JwtKeys::generate)
            .await
            .map_err(|e| JwkRotationError::Generate(e.to_string()))?
            .map_err(|e| JwkRotationError::Generate(format!("{e:#}")))?;

        self.keys
            .write()
            .await
            .next
            .get_or_insert((Arc::new(new_key), now));
        Ok(())
    }

    async fn promote_next(&self, now: DateTime<Utc>) -> Result<(), JwkRotationError> {
        let mut keys = self.keys.write().await;
        let (next, _) = keys.next.take().ok_or(JwkRotationError::NoNextKey)?;
        let previous = std::mem::replace(&mut keys.active, next);
        keys.retired.push((previous.jwk().clone(), now));
        keys.active_since = now;
        Ok(())
    }

    async fn prune_retired(&self, now: DateTime<Utc>, grace: chrono::Duration) {
        self.keys
            .write()
            .await
            .retired
            .retain(|(_, retired_at)| now < *retired_at + grace);
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
    async fn create_user(&mut self, user: User) -> CreateUserOutcome {
        let mut inner = self.inner.lock().await;
        if inner.users.values().any(|u| u.email == user.email) {
            return CreateUserOutcome::EmailTaken;
        }
        inner.users.insert(user.id, user);
        CreateUserOutcome::Created
    }

    async fn get_user_by_email(&self, email: &str) -> Option<User> {
        self.inner
            .lock()
            .await
            .users
            .values()
            .find(|u| u.email == email)
            .cloned()
    }

    async fn get_user_by_id(&self, id: Uuid) -> Option<User> {
        self.inner.lock().await.users.get(&id).cloned()
    }

    async fn resolve_oidc_login(
        &mut self,
        provider: &str,
        subject: &str,
        email: &VerifiedEmail,
        new_user_id: Uuid,
    ) -> OidcLinkOutcome {
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

        if let Some(existing) = inner.users.values().find(|u| u.email == email) {
            let existing_user_id = existing.id;
            let has_password = existing.password.is_some();
            let mut linked_providers: Vec<String> = inner
                .oidc_identities
                .iter()
                .filter(|(_, user_id)| **user_id == existing_user_id)
                .map(|((provider, _), _)| provider.clone())
                .collect();
            linked_providers.sort();
            linked_providers.dedup();
            return OidcLinkOutcome::RequiresLinkConfirmation {
                existing_user_id,
                has_password,
                linked_providers,
            };
        }

        let now = Utc::now();
        let user = User {
            id: new_user_id,
            email: email.to_string(),
            password: None,
            email_verified: true,
            credential_version: 0,
            created_at: now,
            updated_at: now,
        };
        inner.users.insert(user.id, user.clone());
        inner.oidc_identities.insert(identity_key, user.id);
        OidcLinkOutcome::Resolved(user)
    }

    async fn link_verified_oidc_identity(
        &mut self,
        stamp: CredentialStamp,
        provider: &str,
        subject: &str,
    ) -> Option<User> {
        let mut inner = self.inner.lock().await;

        let user = inner
            .users
            .get_mut(&stamp.user_id)
            .filter(|user| user.credential_version == stamp.version)?;
        user.email_verified = true;
        let user = user.clone();

        inner
            .oidc_identities
            .insert((provider.to_string(), subject.to_string()), stamp.user_id);
        Some(user)
    }

    async fn set_password(
        &mut self,
        user_id: Uuid,
        password_hash: PasswordHash,
    ) -> SetPasswordOutcome {
        let mut inner = self.inner.lock().await;
        let Some(user) = inner.users.get_mut(&user_id) else {
            return SetPasswordOutcome::UserNotFound;
        };
        user.password = Some(password_hash);
        user.credential_version += 1;
        user.updated_at = Utc::now();
        SetPasswordOutcome::Ok
    }

    async fn upgrade_password_hash(
        &mut self,
        stamp: CredentialStamp,
        password_hash: PasswordHash,
    ) -> UpgradeHashOutcome {
        let mut inner = self.inner.lock().await;
        let Some(user) = inner
            .users
            .get_mut(&stamp.user_id)
            .filter(|user| user.credential_version == stamp.version)
        else {
            return UpgradeHashOutcome::Stale;
        };
        user.password = Some(password_hash);
        user.updated_at = Utc::now();
        UpgradeHashOutcome::Ok
    }

    async fn mark_email_verified(&mut self, user_id: Uuid) -> MarkVerifiedOutcome {
        let mut inner = self.inner.lock().await;
        let Some(user) = inner.users.get_mut(&user_id) else {
            return MarkVerifiedOutcome::UserNotFound;
        };
        if !user.email_verified {
            user.email_verified = true;
            user.updated_at = Utc::now();
        }
        MarkVerifiedOutcome::Ok
    }

    async fn oidc_identity_owner(&self, provider: &str, subject: &str) -> Option<Uuid> {
        self.inner
            .lock()
            .await
            .oidc_identities
            .get(&(provider.to_string(), subject.to_string()))
            .copied()
    }
}

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
    async fn save_pending_link(
        &mut self,
        provider: String,
        subject: String,
        existing_user_id: Uuid,
    ) -> String {
        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        self.entries.lock().await.insert(
            token.clone(),
            (provider, subject, existing_user_id, Utc::now()),
        );
        token
    }

    async fn take_pending_link(&mut self, token: &str) -> Option<PendingOidcLink> {
        let (provider, subject, existing_user_id, issued_at) =
            self.entries.lock().await.remove(token)?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        Some(PendingOidcLink {
            provider,
            subject,
            existing_user_id,
        })
    }
}

impl ExpiryMaintenance for InMemoryPendingOidcLinkStorage {
    async fn sweep_expired(&mut self) {
        let ttl_secs = self.ttl_secs;
        let now = Utc::now();
        self.entries
            .lock()
            .await
            .retain(|_, (_, _, _, issued_at)| (now - *issued_at).num_seconds() <= ttl_secs);
    }
}

/// Keyed by sha256(token), not the token itself -- this trait's contract is
/// what a future durable (e.g. Postgres) implementation follows too, and a
/// table of directly-usable plaintext reset tokens would turn a single read
/// of that table into account takeover for every pending reset. Hashing
/// costs nothing here and is awkward to retrofit later.
type PasswordResetTokenEntries = HashMap<String, (Uuid, DateTime<Utc>)>;

#[derive(Clone)]
pub(crate) struct InMemoryPasswordResetTokenStorage {
    entries: Arc<Mutex<PasswordResetTokenEntries>>,
    ttl_secs: i64,
    cooldown_secs: i64,
}

impl InMemoryPasswordResetTokenStorage {
    pub fn new(ttl_secs: i64, cooldown_secs: i64) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
            cooldown_secs,
        }
    }

    /// How many outstanding (not necessarily unexpired) tokens exist across
    /// every user -- there's no way to observe token issuance through the
    /// `PasswordResetTokenStorage` trait itself (the token value is only
    /// ever handed to whoever asked for it), so tests that need to confirm
    /// `/oauth/password-reset/request` actually issued something use this
    /// instead of the token they were never given.
    #[cfg(test)]
    pub(crate) async fn token_count(&self) -> usize {
        self.entries.lock().await.len()
    }
}

#[cfg(test)]
impl InMemoryPendingOidcLinkStorage {
    pub(crate) async fn entry_count(&self) -> usize {
        self.entries.lock().await.len()
    }
}

#[cfg(test)]
impl InMemoryOidcStateStorage {
    pub(crate) async fn entry_count(&self) -> usize {
        self.entries.lock().await.len()
    }
}

#[cfg(test)]
impl InMemoryPkceStorage {
    pub(crate) async fn entry_count(&self) -> usize {
        self.code_challenges.lock().await.len()
    }
}

#[cfg(test)]
impl InMemoryLoginSessionStorage {
    pub(crate) async fn entry_count(&self) -> usize {
        self.sessions.lock().await.len()
    }
}

#[cfg(test)]
impl InMemoryRefreshTokenStorage {
    pub(crate) async fn entry_count(&self) -> usize {
        self.tokens.lock().await.len()
    }
}

fn hash_reset_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

impl PasswordResetTokenStorage for InMemoryPasswordResetTokenStorage {
    fn ttl_secs(&self) -> i64 {
        self.ttl_secs
    }

    async fn issue_reset_token(&mut self, user_id: Uuid) -> IssueResetOutcome {
        let mut entries = self.entries.lock().await;
        let now = Utc::now();
        // ponytail: scans every user's tokens under the one lock; a per-user
        // index (or a durable store's `WHERE user_id`) once the table grows.
        if entries.values().any(|(owner, issued_at)| {
            *owner == user_id && (now - *issued_at).num_seconds() < self.cooldown_secs
        }) {
            return IssueResetOutcome::CoolingDown;
        }

        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        entries.insert(hash_reset_token(&token), (user_id, now));
        IssueResetOutcome::Issued(token)
    }

    async fn take_reset_token(&mut self, token: &str) -> Option<Uuid> {
        let mut entries = self.entries.lock().await;
        let (user_id, issued_at) = entries.remove(&hash_reset_token(token))?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        entries.retain(|_, (owner, _)| *owner != user_id);
        Some(user_id)
    }
}

type VerificationSessionEntries = HashMap<String, (CredentialStamp, DateTime<Utc>)>;

#[derive(Clone)]
pub(crate) struct InMemoryVerificationSessionStorage {
    sessions: Arc<Mutex<VerificationSessionEntries>>,
    ttl_secs: i64,
}

impl InMemoryVerificationSessionStorage {
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
        }
    }
}

impl VerificationSessionStorage for InMemoryVerificationSessionStorage {
    fn ttl_secs(&self) -> i64 {
        self.ttl_secs
    }

    async fn create_session(&mut self, stamp: CredentialStamp) -> String {
        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        self.sessions
            .lock()
            .await
            .insert(token.clone(), (stamp, Utc::now()));
        token
    }

    async fn get_session(&self, token: &str) -> Option<CredentialStamp> {
        let (stamp, issued_at) = *self.sessions.lock().await.get(token)?;
        ((Utc::now() - issued_at).num_seconds() <= self.ttl_secs).then_some(stamp)
    }

    async fn delete_session(&mut self, token: &str) {
        self.sessions.lock().await.remove(token);
    }

    async fn revoke_all_for_user(&mut self, user_id: Uuid) -> RevokeOutcome {
        self.sessions
            .lock()
            .await
            .retain(|_, (owner, _)| owner.user_id != user_id);
        RevokeOutcome::Ok
    }
}

impl ExpiryMaintenance for InMemoryVerificationSessionStorage {
    async fn sweep_expired(&mut self) {
        let ttl_secs = self.ttl_secs;
        let now = Utc::now();
        self.sessions
            .lock()
            .await
            .retain(|_, (_, issued_at)| (now - *issued_at).num_seconds() <= ttl_secs);
    }
}

/// Digits in a code; 10^CODE_DIGITS must fit the u32 it is drawn from.
pub(crate) const CODE_DIGITS: usize = 9;
const _: () = assert!(CODE_DIGITS < 10);

/// Wrong guesses a single code survives; the next one deletes it.
const MAX_CODE_ATTEMPTS: u32 = 5;
/// Wrong guesses (across codes, since the last success) before the user is
/// locked out. The count is kept as long as the user's record is: dropping it
/// after an hour without a new code (see the sweep) resets it too.
const MAX_FAILED_ATTEMPTS: u32 = 10;
/// How long the first lock lasts. Each repeat doubles it while the earlier
/// locks are remembered (1h, 2h, 4h, 8h, 16h).
const LOCKOUT_SECS: i64 = 3_600;
/// Locks within the remembered window after which the user stays locked
/// until a password reset.
const MAX_LOCKOUTS: u32 = 5;
/// How long after a lock ends it still counts towards the next one's length.
const LOCKOUT_MEMORY_SECS: i64 = 86_400;

/// The current code, stored as sha256(user id || code) rather than the code
/// itself, like the other single-use secrets here.
struct CodeEntry {
    hash: String,
    attempts: u32,
}

/// Everything known about one user's codes. It outlives the code itself: the
/// resend cooldown and the failure count must survive a code being used up,
/// or the "5 guesses, resend, 5 more guesses" loop would never be limited.
#[derive(Default)]
struct UserCodes {
    code: Option<CodeEntry>,
    last_issued_at: Option<DateTime<Utc>>,
    /// Wrong guesses since the last success or lock; reaching
    /// `MAX_FAILED_ATTEMPTS` starts a lockout.
    failed_attempts: u32,
    /// When the latest lock ends (or ended: kept for `LOCKOUT_MEMORY_SECS`).
    locked_until: Option<DateTime<Utc>>,
    /// Locks within the remembered window; each doubles the next one.
    lockouts: u32,
    /// Set by the lock after `MAX_LOCKOUTS` of them; only removing the record
    /// (a password reset) ends it.
    locked_until_reset: bool,
}

/// A lock in force.
#[derive(Debug, Eq, PartialEq)]
enum Lock {
    Until(DateTime<Utc>),
    UntilReset,
}

impl UserCodes {
    /// Whether this record still has to be kept: a lock in force, a code or
    /// cooldown that hasn't run out, or failures that still count towards a
    /// lock. Anything else is the sweep's to drop.
    fn still_needed(&self, now: DateTime<Utc>, ttl: i64, cooldown: i64, lockout: i64) -> bool {
        let age = self
            .last_issued_at
            .map(|issued| (now - issued).num_seconds());
        self.locked_until_reset
            || self
                .locked_until
                .is_some_and(|until| until + chrono::Duration::seconds(LOCKOUT_MEMORY_SECS) > now)
            || age.is_some_and(|age| {
                age <= ttl || age < cooldown || (self.failed_attempts > 0 && age <= lockout)
            })
    }

    /// The lock in force, if any.
    fn locked(&self, now: DateTime<Utc>) -> Option<Lock> {
        if self.locked_until_reset {
            return Some(Lock::UntilReset);
        }
        self.locked_until
            .filter(|until| *until > now)
            .map(Lock::Until)
    }

    /// Starts a lock, twice as long as the previous one if that is still
    /// remembered, or one that only a password reset ends after
    /// `MAX_LOCKOUTS` of them.
    fn lock(&mut self, now: DateTime<Utc>, lockout_secs: i64) -> Lock {
        self.failed_attempts = 0;
        let remembered = self
            .locked_until
            .is_some_and(|until| until + chrono::Duration::seconds(LOCKOUT_MEMORY_SECS) > now);
        if !remembered {
            self.lockouts = 0;
        }
        if self.lockouts >= MAX_LOCKOUTS {
            self.locked_until_reset = true;
            return Lock::UntilReset;
        }
        let secs = lockout_secs << self.lockouts;
        self.lockouts += 1;
        let until = now + chrono::Duration::seconds(secs);
        self.locked_until = Some(until);
        Lock::Until(until)
    }
}

#[derive(Clone)]
pub(crate) struct InMemoryEmailVerificationCodeStorage {
    users: Arc<Mutex<HashMap<Uuid, UserCodes>>>,
    ttl_secs: i64,
    cooldown_secs: i64,
    lockout_secs: i64,
}

impl InMemoryEmailVerificationCodeStorage {
    pub fn new(ttl_secs: i64, cooldown_secs: i64) -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
            cooldown_secs,
            lockout_secs: LOCKOUT_SECS,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_lockout_secs(mut self, lockout_secs: i64) -> Self {
        self.lockout_secs = lockout_secs;
        self
    }

    #[cfg(test)]
    pub(crate) async fn hard_lock(&self, user_id: Uuid) {
        self.users
            .lock()
            .await
            .entry(user_id)
            .or_default()
            .locked_until_reset = true;
    }

    #[cfg(test)]
    pub(crate) async fn entry_count(&self) -> usize {
        self.users.lock().await.len()
    }
}

/// Whole seconds from `now` until `until`, rounded up so a user who waits
/// that long is never turned away again.
fn secs_until(until: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    ((until - now).num_milliseconds() + 999) / 1000
}

/// A code that is not `code`.
#[cfg(test)]
pub(crate) fn wrong_code(code: &str) -> &'static str {
    debug_assert_eq!(
        code.len(),
        CODE_DIGITS,
        "the literals below have nine digits"
    );
    if code == "000000000" {
        "000000001"
    } else {
        "000000000"
    }
}

fn hash_code(user_id: Uuid, code: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(user_id.as_bytes());
    digest.update(code.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

impl EmailVerificationCodeStorage for InMemoryEmailVerificationCodeStorage {
    async fn issue_code(&mut self, user_id: Uuid) -> IssueCodeOutcome {
        let mut users = self.users.lock().await;
        let user = users.entry(user_id).or_default();
        let now = Utc::now();
        match user.locked(now) {
            Some(Lock::Until(until)) => {
                return IssueCodeOutcome::Locked {
                    retry_after_secs: secs_until(until, now),
                };
            }
            Some(Lock::UntilReset) => return IssueCodeOutcome::LockedUntilReset,
            None => {}
        }
        let cooldown_ends = user
            .last_issued_at
            .map(|issued| issued + chrono::Duration::seconds(self.cooldown_secs))
            .filter(|ends| *ends > now);
        if let Some(ends) = cooldown_ends {
            return IssueCodeOutcome::CoolingDown {
                retry_after_secs: secs_until(ends, now),
            };
        }

        let code = format!(
            "{:0width$}",
            rand::rng().random_range(0..10u32.pow(CODE_DIGITS as u32)),
            width = CODE_DIGITS
        );
        user.code = Some(CodeEntry {
            hash: hash_code(user_id, &code),
            attempts: 0,
        });
        user.last_issued_at = Some(now);
        IssueCodeOutcome::Issued(code)
    }

    async fn check_code(&mut self, user_id: Uuid, code: &str) -> CheckCodeOutcome {
        let mut users = self.users.lock().await;
        let Some(user) = users.get_mut(&user_id) else {
            return CheckCodeOutcome::NoCode;
        };
        let now = Utc::now();
        match user.locked(now) {
            Some(Lock::Until(until)) => {
                return CheckCodeOutcome::Locked {
                    retry_after_secs: secs_until(until, now),
                };
            }
            Some(Lock::UntilReset) => return CheckCodeOutcome::LockedUntilReset,
            None => {}
        }
        if user
            .last_issued_at
            .is_none_or(|issued| (now - issued).num_seconds() > self.ttl_secs)
        {
            user.code = None;
        }
        let Some(entry) = user.code.as_mut() else {
            return CheckCodeOutcome::NoCode;
        };

        if entry.hash == hash_code(user_id, code) {
            user.code = None;
            user.failed_attempts = 0;
            user.lockouts = 0;
            return CheckCodeOutcome::Verified;
        }
        entry.attempts += 1;
        user.failed_attempts += 1;
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS {
            user.code = None;
            return match user.lock(now, self.lockout_secs) {
                Lock::Until(until) => CheckCodeOutcome::Locked {
                    retry_after_secs: secs_until(until, now),
                },
                Lock::UntilReset => CheckCodeOutcome::LockedUntilReset,
            };
        }
        if entry.attempts >= MAX_CODE_ATTEMPTS {
            user.code = None;
            return CheckCodeOutcome::TooManyAttempts;
        }
        CheckCodeOutcome::Wrong
    }

    async fn has_live_code(&self, user_id: Uuid) -> bool {
        self.users.lock().await.get(&user_id).is_some_and(|user| {
            user.code.is_some()
                && user
                    .last_issued_at
                    .is_some_and(|issued| (Utc::now() - issued).num_seconds() <= self.ttl_secs)
        })
    }

    async fn clear_user(&mut self, user_id: Uuid) -> RevokeOutcome {
        self.users.lock().await.remove(&user_id);
        RevokeOutcome::Ok
    }
}

impl ExpiryMaintenance for InMemoryEmailVerificationCodeStorage {
    async fn sweep_expired(&mut self) {
        let now = Utc::now();
        self.users.lock().await.retain(|_, user| {
            user.still_needed(now, self.ttl_secs, self.cooldown_secs, self.lockout_secs)
        });
    }
}

impl ExpiryMaintenance for InMemoryPasswordResetTokenStorage {
    async fn sweep_expired(&mut self) {
        let ttl_secs = self.ttl_secs;
        let now = Utc::now();
        self.entries
            .lock()
            .await
            .retain(|_, (_, issued_at)| (now - *issued_at).num_seconds() <= ttl_secs);
    }
}

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
    async fn save_state(
        &mut self,
        csrf_state: String,
        provider: String,
        pkce_verifier: String,
        nonce: String,
    ) {
        self.entries
            .lock()
            .await
            .insert(csrf_state, (provider, pkce_verifier, nonce, Utc::now()));
    }

    async fn take_state(&mut self, csrf_state: &str) -> Option<OidcLoginState> {
        let (provider, pkce_verifier, nonce, issued_at) =
            self.entries.lock().await.remove(csrf_state)?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        Some(OidcLoginState {
            provider,
            pkce_verifier: pkce_verifier.into(),
            nonce: nonce.into(),
        })
    }
}

impl ExpiryMaintenance for InMemoryOidcStateStorage {
    async fn sweep_expired(&mut self) {
        let ttl_secs = self.ttl_secs;
        let now = Utc::now();
        self.entries
            .lock()
            .await
            .retain(|_, (_, _, _, issued_at)| (now - *issued_at).num_seconds() <= ttl_secs);
    }
}

type PkceEntries = HashMap<
    String,
    (
        String,
        CodeChallengeMethod,
        DateTime<Utc>,
        String,
        CredentialStamp,
    ),
>;

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
        stamp: CredentialStamp,
    ) {
        self.code_challenges.lock().await.insert(
            auth_code,
            (
                code_challenge,
                code_challenge_method,
                Utc::now(),
                redirect_uri,
                stamp,
            ),
        );
    }

    async fn take_code_challenge(
        &mut self,
        auth_code: &str,
    ) -> Option<(String, CodeChallengeMethod, String, CredentialStamp)> {
        let (challenge, method, issued_at, redirect_uri, stamp) =
            self.code_challenges.lock().await.remove(auth_code)?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        Some((challenge, method, redirect_uri, stamp))
    }
}

impl ExpiryMaintenance for InMemoryPkceStorage {
    async fn sweep_expired(&mut self) {
        let ttl_secs = self.ttl_secs;
        let now = Utc::now();
        self.code_challenges
            .lock()
            .await
            .retain(|_, (_, _, issued_at, _, _)| (now - *issued_at).num_seconds() <= ttl_secs);
    }
}

type LoginSessionEntries = HashMap<String, (CredentialStamp, DateTime<Utc>)>;

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
    async fn create_session(&mut self, stamp: CredentialStamp) -> String {
        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        self.sessions
            .lock()
            .await
            .insert(token.clone(), (stamp, Utc::now()));
        token
    }

    async fn take_session(&mut self, token: &str) -> Option<CredentialStamp> {
        let (stamp, issued_at) = self.sessions.lock().await.remove(token)?;
        if (Utc::now() - issued_at).num_seconds() > self.ttl_secs {
            return None;
        }
        Some(stamp)
    }

    async fn revoke_all_for_user(&mut self, user_id: Uuid) -> RevokeOutcome {
        self.sessions
            .lock()
            .await
            .retain(|_, (stamp, _)| stamp.user_id != user_id);
        RevokeOutcome::Ok
    }
}

impl ExpiryMaintenance for InMemoryLoginSessionStorage {
    async fn sweep_expired(&mut self) {
        let ttl_secs = self.ttl_secs;
        let now = Utc::now();
        self.sessions
            .lock()
            .await
            .retain(|_, (_, issued_at)| (now - *issued_at).num_seconds() <= ttl_secs);
    }
}

struct RefreshTokenRecord {
    stamp: CredentialStamp,
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
    async fn save_refresh_token(&mut self, token: String, stamp: CredentialStamp, family_id: Uuid) {
        self.tokens.lock().await.insert(
            token,
            RefreshTokenRecord {
                stamp,
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
            stamp: record.stamp,
            family_id: record.family_id,
        }
    }

    async fn revoke_all_for_user(&mut self, user_id: Uuid) -> RevokeOutcome {
        self.tokens
            .lock()
            .await
            .retain(|_, record| record.stamp.user_id != user_id);
        RevokeOutcome::Ok
    }
}

impl ExpiryMaintenance for InMemoryRefreshTokenStorage {
    async fn sweep_expired(&mut self) {
        let ttl_secs = self.ttl_secs;
        let now = Utc::now();
        self.tokens
            .lock()
            .await
            .retain(|_, record| (now - record.issued_at).num_seconds() <= ttl_secs);
    }
}

#[cfg(test)]
mod tests {
    use crate::model::pkce::CodeChallengeMethod;
    use crate::model::user::{CredentialStamp, PasswordHash, User};
    use crate::storage::JwkStorage;
    use crate::storage::in_memory::{CODE_DIGITS, MAX_LOCKOUTS, wrong_code};
    use crate::storage::in_memory::{
        InMemoryEmailVerificationCodeStorage, InMemoryLoginSessionStorage,
        InMemoryOidcStateStorage, InMemoryPasswordResetTokenStorage,
        InMemoryPendingOidcLinkStorage, InMemoryPkceStorage, InMemoryRefreshTokenStorage,
        InMemoryUserStorage, InMemoryVerificationSessionStorage, Lock, UserCodes,
    };
    use crate::storage::{
        CheckCodeOutcome, CreateUserOutcome, EmailVerificationCodeStorage, ExpiryMaintenance,
        IssueCodeOutcome, IssueResetOutcome, LoginSessionStorage, MarkVerifiedOutcome,
        OidcLinkOutcome, OidcStateStorage, PasswordResetTokenStorage, PendingOidcLinkStorage,
        PkceStorage, RefreshTokenOutcome, RefreshTokenStorage, RevokeOutcome, SetPasswordOutcome,
        UpgradeHashOutcome, UserStorage, VerificationSessionStorage, VerifiedEmail,
    };
    use chrono::Utc;
    use secrecy::ExposeSecret;
    use uuid::Uuid;

    fn jwk_kids(set: &serde_json::Value) -> Vec<String> {
        set["keys"]
            .as_array()
            .expect("keys array")
            .iter()
            .map(|k| k["kid"].as_str().expect("kid").to_string())
            .collect()
    }

    async fn rotate(
        storage: &crate::storage::in_memory::InMemoryJwkStorage,
        now: chrono::DateTime<Utc>,
    ) {
        storage.stage_next(now).await.unwrap();
        storage.promote_next(now).await.unwrap();
    }

    #[tokio::test]
    async fn stage_next_publishes_a_key_without_signing_with_it() {
        let storage = crate::storage::in_memory::InMemoryJwkStorage::new().unwrap();
        let active_kid = storage.active_key().await.kid.clone();
        let since = storage.active_since().await;
        let now = Utc::now();
        assert_eq!(storage.next_since().await, None);

        storage.stage_next(now).await.unwrap();

        assert_eq!(storage.active_key().await.kid, active_kid);
        assert_eq!(storage.active_since().await, since);
        assert_eq!(storage.next_since().await, Some(now));
        let kids = jwk_kids(&storage.jwk_set().await);
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0], active_kid);
    }

    #[tokio::test]
    async fn staging_again_keeps_the_already_staged_key() {
        let storage = crate::storage::in_memory::InMemoryJwkStorage::new().unwrap();
        let first = Utc::now();
        storage.stage_next(first).await.unwrap();
        let kids = jwk_kids(&storage.jwk_set().await);

        storage
            .stage_next(first + chrono::Duration::seconds(5))
            .await
            .unwrap();

        assert_eq!(jwk_kids(&storage.jwk_set().await), kids);
        assert_eq!(storage.next_since().await, Some(first));
    }

    #[tokio::test]
    async fn promote_next_activates_the_staged_key_and_keeps_the_old_one_published() {
        let storage = crate::storage::in_memory::InMemoryJwkStorage::new().unwrap();
        let old_kid = storage.active_key().await.kid.clone();
        let now = Utc::now();
        storage.stage_next(now).await.unwrap();
        let staged_kid = jwk_kids(&storage.jwk_set().await)[1].clone();

        storage.promote_next(now).await.unwrap();

        assert_eq!(storage.active_key().await.kid, staged_kid);
        assert_eq!(storage.active_since().await, now);
        assert_eq!(storage.next_since().await, None);
        assert_eq!(
            jwk_kids(&storage.jwk_set().await),
            vec![staged_kid, old_kid]
        );
    }

    #[tokio::test]
    async fn promote_next_without_a_staged_key_fails_and_changes_nothing() {
        let storage = crate::storage::in_memory::InMemoryJwkStorage::new().unwrap();
        let kid = storage.active_key().await.kid.clone();

        let result = storage.promote_next(Utc::now()).await;

        assert!(matches!(
            result,
            Err(crate::storage::JwkRotationError::NoNextKey)
        ));
        assert_eq!(storage.active_key().await.kid, kid);
    }

    #[tokio::test]
    async fn token_signed_before_rotation_verifies_against_the_published_set() {
        use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, encode};

        let storage = crate::storage::in_memory::InMemoryJwkStorage::new().unwrap();
        let old = storage.active_key().await;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(old.kid.clone());
        let claims = serde_json::json!({ "exp": Utc::now().timestamp() + 3600 });
        let token = encode(&header, &claims, &old.encoding_key).unwrap();

        rotate(&storage, Utc::now()).await;

        let set = storage.jwk_set().await;
        let jwk = set["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["kid"] == old.kid.as_str())
            .expect("old key still published");
        let decoding_key = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();
        decode::<serde_json::Value>(&token, &decoding_key, &Validation::new(Algorithm::RS256))
            .expect("old-key token verifies during grace");
    }

    #[tokio::test]
    async fn prune_retired_drops_the_old_key_only_once_the_grace_period_is_over() {
        let storage = crate::storage::in_memory::InMemoryJwkStorage::new().unwrap();
        let old_kid = storage.active_key().await.kid.clone();
        let rotated_at = Utc::now();
        let grace = chrono::Duration::seconds(100);
        rotate(&storage, rotated_at).await;

        storage
            .prune_retired(rotated_at + chrono::Duration::seconds(99), grace)
            .await;
        assert!(jwk_kids(&storage.jwk_set().await).contains(&old_kid));

        storage
            .prune_retired(rotated_at + chrono::Duration::seconds(100), grace)
            .await;
        let new_kid = storage.active_key().await.kid.clone();
        assert_eq!(jwk_kids(&storage.jwk_set().await), vec![new_kid]);
    }

    #[tokio::test]
    async fn prune_retired_never_drops_the_active_key() {
        let storage = crate::storage::in_memory::InMemoryJwkStorage::new().unwrap();
        let kid = storage.active_key().await.kid.clone();

        storage
            .prune_retired(
                Utc::now() + chrono::Duration::days(365),
                chrono::Duration::zero(),
            )
            .await;

        assert_eq!(jwk_kids(&storage.jwk_set().await), vec![kid]);
    }

    fn verified(email: &str) -> VerifiedEmail {
        VerifiedEmail::new(email.to_string(), true).expect("true always verifies")
    }

    #[tokio::test]
    async fn test_create_user() {
        let mut storage = InMemoryUserStorage::new();
        let mut user = User::default();
        user.email = "carol".to_string();
        let user_id = user.id;
        assert_eq!(storage.create_user(user).await, CreateUserOutcome::Created);
        let retrieved_user = storage.get_user_by_email("carol").await;
        assert_eq!(retrieved_user.map(|u| u.id), Some(user_id));
    }

    #[tokio::test]
    async fn test_create_user_rejects_a_taken_email() {
        let mut storage = InMemoryUserStorage::new();
        let mut first = User::default();
        first.email = "carol".to_string();
        let first_id = first.id;
        assert_eq!(storage.create_user(first).await, CreateUserOutcome::Created);

        let mut second = User::default();
        second.email = "carol".to_string();
        assert_eq!(
            storage.create_user(second).await,
            CreateUserOutcome::EmailTaken
        );

        // The original registration is untouched -- no shadowing, no overwrite.
        let retrieved = storage.get_user_by_email("carol").await;
        assert_eq!(retrieved.map(|u| u.id), Some(first_id));
    }

    #[tokio::test]
    async fn test_get_user_by_email() {
        let mut storage = InMemoryUserStorage::new();
        let mut user = User::default();
        user.email = "alice".to_string();
        let _ = storage.create_user(user).await;

        let found = storage.get_user_by_email("alice").await;
        assert_eq!(found.map(|u| u.email), Some("alice".to_string()));
        assert!(storage.get_user_by_email("bob").await.is_none());
    }

    #[tokio::test]
    async fn resolve_oidc_login_creates_on_first_login() {
        let mut storage = InMemoryUserStorage::new();
        let outcome = storage
            .resolve_oidc_login(
                "google",
                "sub-123",
                &verified("alice@example.com"),
                Uuid::new_v4(),
            )
            .await;

        let OidcLinkOutcome::Resolved(user) = outcome else {
            unreachable!("expected Resolved, got {outcome:?}");
        };
        assert_eq!(user.email, "alice@example.com");
        assert!(user.password.is_none());
        assert!(user.email_verified);
    }

    #[tokio::test]
    async fn resolve_oidc_login_returns_the_same_user_on_repeat_login() {
        let mut storage = InMemoryUserStorage::new();
        let OidcLinkOutcome::Resolved(first) = storage
            .resolve_oidc_login(
                "google",
                "sub-123",
                &verified("alice@example.com"),
                Uuid::new_v4(),
            )
            .await
        else {
            unreachable!("expected Resolved");
        };
        let OidcLinkOutcome::Resolved(second) = storage
            .resolve_oidc_login(
                "google",
                "sub-123",
                &verified("alice@example.com"),
                Uuid::new_v4(),
            )
            .await
        else {
            unreachable!("expected Resolved");
        };

        assert_eq!(first.id, second.id);
    }

    #[tokio::test]
    async fn resolve_oidc_login_asks_a_verified_password_account_to_confirm_the_link() {
        let mut storage = InMemoryUserStorage::new();
        let local_user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2("hash".into())),
            email_verified: true,
            ..User::default()
        };
        let _ = storage.create_user(local_user.clone()).await;

        let outcome = storage
            .resolve_oidc_login(
                "google",
                "sub-123",
                &verified("alice@example.com"),
                Uuid::new_v4(),
            )
            .await;

        let OidcLinkOutcome::RequiresLinkConfirmation {
            existing_user_id,
            has_password,
            linked_providers,
        } = outcome
        else {
            unreachable!("expected RequiresLinkConfirmation, got {outcome:?}");
        };
        assert_eq!(existing_user_id, local_user.id);
        assert!(has_password);
        assert!(linked_providers.is_empty());
        assert_eq!(storage.oidc_identity_owner("google", "sub-123").await, None);
    }

    #[tokio::test]
    async fn resolve_oidc_login_asks_a_second_provider_to_confirm_and_lists_the_linked_ones() {
        let mut storage = InMemoryUserStorage::new();
        let OidcLinkOutcome::Resolved(google_user) = storage
            .resolve_oidc_login(
                "google",
                "google-sub",
                &verified("alice@example.com"),
                Uuid::new_v4(),
            )
            .await
        else {
            unreachable!("expected Resolved");
        };

        let outcome = storage
            .resolve_oidc_login(
                "linkedin",
                "linkedin-sub",
                &verified("alice@example.com"),
                Uuid::new_v4(),
            )
            .await;

        let OidcLinkOutcome::RequiresLinkConfirmation {
            existing_user_id,
            has_password,
            linked_providers,
        } = outcome
        else {
            unreachable!("expected RequiresLinkConfirmation, got {outcome:?}");
        };
        assert_eq!(existing_user_id, google_user.id);
        assert!(!has_password);
        assert_eq!(linked_providers, vec!["google".to_string()]);
    }

    #[tokio::test]
    async fn oidc_identity_owner_finds_only_linked_identities() {
        let mut storage = InMemoryUserStorage::new();
        let OidcLinkOutcome::Resolved(user) = storage
            .resolve_oidc_login(
                "google",
                "google-sub",
                &verified("alice@example.com"),
                Uuid::new_v4(),
            )
            .await
        else {
            unreachable!("expected Resolved");
        };

        assert_eq!(
            storage.oidc_identity_owner("google", "google-sub").await,
            Some(user.id)
        );
        assert_eq!(
            storage.oidc_identity_owner("google", "other-sub").await,
            None
        );
        assert_eq!(
            storage.oidc_identity_owner("linkedin", "google-sub").await,
            None
        );
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
            password: Some(PasswordHash::Argon2("squatter-hash".into())),
            email_verified: false,
            ..User::default()
        };
        let _ = storage.create_user(squatter.clone()).await;

        let outcome = storage
            .resolve_oidc_login(
                "google",
                "sub-123",
                &verified("alice@example.com"),
                Uuid::new_v4(),
            )
            .await;

        let OidcLinkOutcome::RequiresLinkConfirmation {
            existing_user_id,
            has_password,
            linked_providers,
        } = outcome
        else {
            unreachable!("expected RequiresLinkConfirmation, got {outcome:?}");
        };
        assert_eq!(existing_user_id, squatter.id);
        assert!(has_password);
        assert!(linked_providers.is_empty());
        // Nothing was mutated -- still unverified, no identity linked yet.
        let still_unverified = storage
            .get_user_by_email("alice@example.com")
            .await
            .unwrap();
        assert!(!still_unverified.email_verified);
    }

    #[tokio::test]
    async fn link_verified_oidc_identity_marks_the_account_verified_and_links_it() {
        let mut storage = InMemoryUserStorage::new();
        let squatter = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2("squatter-hash".into())),
            email_verified: false,
            ..User::default()
        };
        let _ = storage.create_user(squatter.clone()).await;

        let linked = storage
            .link_verified_oidc_identity(squatter.stamp(), "google", "sub-123")
            .await
            .expect("user still exists");

        assert_eq!(linked.id, squatter.id);
        assert!(linked.email_verified);

        // The newly linked identity now resolves straight to this account.
        let OidcLinkOutcome::Resolved(via_google) = storage
            .resolve_oidc_login(
                "google",
                "sub-123",
                &verified("alice@example.com"),
                Uuid::new_v4(),
            )
            .await
        else {
            unreachable!("expected Resolved");
        };
        assert_eq!(via_google.id, squatter.id);
    }

    #[tokio::test]
    async fn link_verified_oidc_identity_returns_none_for_an_unknown_user() {
        let mut storage = InMemoryUserStorage::new();

        let result = storage
            .link_verified_oidc_identity(
                CredentialStamp::initial(Uuid::new_v4()),
                "google",
                "sub-123",
            )
            .await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn mark_email_verified_sets_the_flag() {
        let mut storage = InMemoryUserStorage::new();
        let user = User::default();
        let user_id = user.id;
        let _ = storage.create_user(user).await;

        assert_eq!(
            storage.mark_email_verified(user_id).await,
            MarkVerifiedOutcome::Ok
        );

        let user = storage.get_user_by_id(user_id).await.unwrap();
        assert!(user.email_verified);
    }

    #[tokio::test]
    async fn mark_email_verified_reports_an_unknown_user() {
        let mut storage = InMemoryUserStorage::new();

        assert_eq!(
            storage.mark_email_verified(Uuid::new_v4()).await,
            MarkVerifiedOutcome::UserNotFound
        );
    }

    fn codes() -> InMemoryEmailVerificationCodeStorage {
        InMemoryEmailVerificationCodeStorage::new(60, 0)
    }

    async fn issued(storage: &mut InMemoryEmailVerificationCodeStorage, user_id: Uuid) -> String {
        match storage.issue_code(user_id).await {
            IssueCodeOutcome::Issued(code) => code,
            IssueCodeOutcome::CoolingDown { .. }
            | IssueCodeOutcome::Locked { .. }
            | IssueCodeOutcome::LockedUntilReset => {
                unreachable!("no cooldown or lock in these tests")
            }
        }
    }

    #[tokio::test]
    async fn a_code_is_nine_digits_and_works_once() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        let code = issued(&mut storage, user_id).await;

        assert_eq!(code.len(), CODE_DIGITS);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::Verified
        );
        assert_eq!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::NoCode
        );
    }

    #[tokio::test]
    async fn a_code_only_works_for_the_user_it_was_issued_to() {
        let mut storage = codes();
        let code = issued(&mut storage, Uuid::new_v4()).await;

        assert_eq!(
            storage.check_code(Uuid::new_v4(), &code).await,
            CheckCodeOutcome::NoCode
        );
    }

    #[tokio::test]
    async fn a_wrong_code_is_rejected_and_the_right_one_still_works() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        let code = issued(&mut storage, user_id).await;
        let wrong = wrong_code(&code);

        assert_eq!(
            storage.check_code(user_id, wrong).await,
            CheckCodeOutcome::Wrong
        );
        assert_eq!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::Verified
        );
    }

    #[tokio::test]
    async fn the_fifth_wrong_guess_destroys_the_code() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        let code = issued(&mut storage, user_id).await;
        let wrong = wrong_code(&code);

        for _ in 0..4 {
            assert_eq!(
                storage.check_code(user_id, wrong).await,
                CheckCodeOutcome::Wrong
            );
        }
        assert_eq!(
            storage.check_code(user_id, wrong).await,
            CheckCodeOutcome::TooManyAttempts
        );
        assert_eq!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::NoCode
        );
    }

    #[tokio::test]
    async fn an_expired_code_is_rejected() {
        let mut storage = InMemoryEmailVerificationCodeStorage::new(-1, 0);
        let user_id = Uuid::new_v4();
        let code = issued(&mut storage, user_id).await;

        assert_eq!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::NoCode
        );
    }

    #[tokio::test]
    async fn a_code_is_live_from_issue_until_used_up_or_expired() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        assert!(!storage.has_live_code(user_id).await);

        let code = issued(&mut storage, user_id).await;
        assert!(storage.has_live_code(user_id).await);

        assert_eq!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::Verified
        );
        assert!(!storage.has_live_code(user_id).await);

        let mut expired = InMemoryEmailVerificationCodeStorage::new(-1, 0);
        let _ = issued(&mut expired, user_id).await;
        assert!(!expired.has_live_code(user_id).await);
    }

    #[tokio::test]
    async fn issuing_within_the_cooldown_reports_the_seconds_left() {
        let mut storage = InMemoryEmailVerificationCodeStorage::new(60, 60);
        let user_id = Uuid::new_v4();
        let _ = issued(&mut storage, user_id).await;

        let IssueCodeOutcome::CoolingDown { retry_after_secs } = storage.issue_code(user_id).await
        else {
            unreachable!("cooling down");
        };
        assert!((59..=60).contains(&retry_after_secs), "{retry_after_secs}");
    }

    #[tokio::test]
    async fn issuing_again_within_the_cooldown_changes_nothing() {
        let mut storage = InMemoryEmailVerificationCodeStorage::new(60, 60);
        let user_id = Uuid::new_v4();
        let code = issued(&mut storage, user_id).await;

        assert!(matches!(
            storage.issue_code(user_id).await,
            IssueCodeOutcome::CoolingDown { .. }
        ));
        assert_eq!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::Verified
        );
    }

    #[tokio::test]
    async fn issuing_after_the_cooldown_supersedes_the_old_code() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        let first = issued(&mut storage, user_id).await;
        let mut second = issued(&mut storage, user_id).await;
        while second == first {
            second = issued(&mut storage, user_id).await;
        }

        assert_ne!(
            storage.check_code(user_id, &first).await,
            CheckCodeOutcome::Verified
        );
        assert_eq!(
            storage.check_code(user_id, &second).await,
            CheckCodeOutcome::Verified
        );
    }

    #[tokio::test]
    async fn a_verification_session_resolves_to_its_user_until_deleted() {
        let mut storage = InMemoryVerificationSessionStorage::new(60);
        let user_id = Uuid::new_v4();
        let token = storage
            .create_session(CredentialStamp::initial(user_id))
            .await;

        assert_eq!(
            storage.get_session(&token).await,
            Some(CredentialStamp::initial(user_id))
        );
        assert_eq!(
            storage.get_session(&token).await,
            Some(CredentialStamp::initial(user_id))
        );
        storage.delete_session(&token).await;
        assert_eq!(storage.get_session(&token).await, None);
        assert_eq!(storage.get_session("unknown").await, None);
    }

    #[tokio::test]
    async fn an_expired_verification_session_does_not_resolve_and_is_swept() {
        let mut storage = InMemoryVerificationSessionStorage::new(-1);
        let token = storage
            .create_session(CredentialStamp::initial(Uuid::new_v4()))
            .await;

        assert_eq!(storage.get_session(&token).await, None);
        storage.sweep_expired().await;
        assert!(storage.sessions.lock().await.is_empty());
    }

    // Guessing 5 times, then asking for a resend, must not hand out a fresh
    // code at once: the cooldown outlives the spent code.
    #[tokio::test]
    async fn the_cooldown_still_applies_after_a_code_is_used_up_by_wrong_guesses() {
        let mut storage = InMemoryEmailVerificationCodeStorage::new(60, 60);
        let user_id = Uuid::new_v4();
        let code = issued(&mut storage, user_id).await;
        let wrong = wrong_code(&code);
        for _ in 0..5 {
            let _ = storage.check_code(user_id, wrong).await;
        }

        assert!(matches!(
            storage.issue_code(user_id).await,
            IssueCodeOutcome::CoolingDown { .. }
        ));
    }

    #[tokio::test]
    async fn the_cooldown_still_applies_after_a_successful_check() {
        let mut storage = InMemoryEmailVerificationCodeStorage::new(60, 60);
        let user_id = Uuid::new_v4();
        let code = issued(&mut storage, user_id).await;
        assert_eq!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::Verified
        );

        assert!(matches!(
            storage.issue_code(user_id).await,
            IssueCodeOutcome::CoolingDown { .. }
        ));
    }

    // 10 wrong guesses across codes lock the user out: no further guesses
    // count (not even the right code) and no new code is issued.
    #[tokio::test]
    async fn ten_wrong_guesses_across_codes_lock_the_user_out() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        let mut code = issued(&mut storage, user_id).await;
        for round in 0..2 {
            let wrong = wrong_code(&code);
            for _ in 0..5 {
                let _ = storage.check_code(user_id, wrong).await;
            }
            if round == 0 {
                code = issued(&mut storage, user_id).await;
            }
        }

        assert!(matches!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::Locked { .. }
        ));
        // Locked for the hour: the wait is reported to the second.
        let IssueCodeOutcome::Locked { retry_after_secs } = storage.issue_code(user_id).await
        else {
            unreachable!("locked");
        };
        assert!(
            (3_599..=3_600).contains(&retry_after_secs),
            "{retry_after_secs}"
        );
    }

    #[tokio::test]
    async fn a_success_resets_the_failure_count() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        for _ in 0..3 {
            let code = issued(&mut storage, user_id).await;
            let wrong = wrong_code(&code);
            for _ in 0..4 {
                let _ = storage.check_code(user_id, wrong).await;
            }
            assert_eq!(
                storage.check_code(user_id, &code).await,
                CheckCodeOutcome::Verified
            );
        }

        // 12 wrong guesses in total, but never 10 in a row: not locked.
        assert!(matches!(
            storage.issue_code(user_id).await,
            IssueCodeOutcome::Issued(_)
        ));
    }

    #[tokio::test]
    async fn the_lock_ends_and_the_user_can_ask_for_a_code_again() {
        let mut storage = codes().with_lockout_secs(0);
        let user_id = Uuid::new_v4();
        let mut code = issued(&mut storage, user_id).await;
        for _ in 0..2 {
            let wrong = wrong_code(&code);
            for _ in 0..5 {
                let _ = storage.check_code(user_id, wrong).await;
            }
            if let IssueCodeOutcome::Issued(next) = storage.issue_code(user_id).await {
                code = next;
            }
        }

        assert!(matches!(
            storage.issue_code(user_id).await,
            IssueCodeOutcome::Issued(_)
        ));
    }

    #[tokio::test]
    async fn the_tenth_wrong_guess_reports_the_lock_it_started() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        let mut code = issued(&mut storage, user_id).await;
        let mut last = CheckCodeOutcome::Wrong;
        for round in 0..2 {
            let wrong = wrong_code(&code);
            for _ in 0..5 {
                last = storage.check_code(user_id, wrong).await;
            }
            if round == 0 {
                assert_eq!(last, CheckCodeOutcome::TooManyAttempts);
                code = issued(&mut storage, user_id).await;
            }
        }

        assert!(
            matches!(
                last,
                CheckCodeOutcome::Locked { retry_after_secs }
                    if (3_599..=3_600).contains(&retry_after_secs)
            ),
            "{last:?}"
        );
    }

    #[test]
    fn each_lock_within_a_day_of_the_last_is_twice_as_long() {
        let now = Utc::now();
        let hour = chrono::Duration::hours(1);
        let mut user = UserCodes::default();

        assert_eq!(user.lock(now, 3_600), Lock::Until(now + hour));
        let second = now + hour * 2;
        assert_eq!(user.lock(second, 3_600), Lock::Until(second + hour * 2));
        let third = second + hour * 5;
        assert_eq!(user.lock(third, 3_600), Lock::Until(third + hour * 4));
        // Forgotten after a quiet day: back to the first length.
        let much_later = third + hour * 4 + hour * 25;
        assert_eq!(user.lock(much_later, 3_600), Lock::Until(much_later + hour));
    }

    #[test]
    fn the_lock_after_the_fifth_lasts_until_a_password_reset() {
        let mut now = Utc::now();
        let mut user = UserCodes::default();
        for n in 0..MAX_LOCKOUTS {
            assert!(matches!(user.lock(now, 3_600), Lock::Until(_)), "lock {n}");
            now += chrono::Duration::hours(1 << n);
        }

        assert_eq!(user.lock(now, 3_600), Lock::UntilReset);
        // A year later it is still in force, and the sweep keeps it.
        let later = now + chrono::Duration::days(365);
        assert_eq!(user.locked(later), Some(Lock::UntilReset));
        assert!(user.still_needed(later, 900, 60, 3_600));
    }

    // Guessing keeps counting after a lock ends: every lock ends at once
    // here, and the sixth still has to be the hard one.
    #[tokio::test]
    async fn repeated_wrong_guesses_keep_escalating_after_a_lock_ends() {
        let mut storage = codes().with_lockout_secs(0);
        let user_id = Uuid::new_v4();
        let mut last = CheckCodeOutcome::Wrong;

        for _ in 0..=MAX_LOCKOUTS {
            for _ in 0..2 {
                let code = issued(&mut storage, user_id).await;
                for _ in 0..5 {
                    last = storage.check_code(user_id, wrong_code(&code)).await;
                }
            }
        }

        assert_eq!(last, CheckCodeOutcome::LockedUntilReset);
    }

    #[tokio::test]
    async fn a_hard_lock_refuses_codes_and_issuing_until_the_user_is_cleared() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        storage.hard_lock(user_id).await;

        assert_eq!(
            storage.issue_code(user_id).await,
            IssueCodeOutcome::LockedUntilReset
        );
        assert_eq!(
            storage.check_code(user_id, "123456789").await,
            CheckCodeOutcome::LockedUntilReset
        );

        assert_eq!(storage.clear_user(user_id).await, RevokeOutcome::Ok);
        assert!(matches!(
            storage.issue_code(user_id).await,
            IssueCodeOutcome::Issued(_)
        ));
    }

    #[tokio::test]
    async fn clearing_a_user_removes_the_lock_the_cooldown_and_the_code() {
        let mut storage = codes();
        let user_id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut code = issued(&mut storage, user_id).await;
        let other_code = issued(&mut storage, other).await;
        for _ in 0..2 {
            let wrong = wrong_code(&code);
            for _ in 0..5 {
                let _ = storage.check_code(user_id, wrong).await;
            }
            if let IssueCodeOutcome::Issued(next) = storage.issue_code(user_id).await {
                code = next;
            }
        }
        assert!(matches!(
            storage.issue_code(user_id).await,
            IssueCodeOutcome::Locked { .. }
        ));

        assert_eq!(storage.clear_user(user_id).await, RevokeOutcome::Ok);

        assert_eq!(
            storage.check_code(user_id, &code).await,
            CheckCodeOutcome::NoCode
        );
        assert!(matches!(
            storage.issue_code(user_id).await,
            IssueCodeOutcome::Issued(_)
        ));
        // Another user's code is untouched.
        assert_eq!(
            storage.check_code(other, &other_code).await,
            CheckCodeOutcome::Verified
        );
    }

    // The sweep must not forget a lock (or the failures counting towards one)
    // just because the code that caused it expired.
    #[test]
    fn the_sweep_keeps_locks_and_recent_failures_but_drops_the_rest() {
        let now = Utc::now();
        let long_ago = Some(now - chrono::Duration::hours(10));
        let (ttl, cooldown, lockout) = (900, 60, 3_600);
        let user = |failed_attempts, locked_until| UserCodes {
            code: None,
            last_issued_at: long_ago,
            failed_attempts,
            locked_until,
            lockouts: 0,
            locked_until_reset: false,
        };

        assert!(
            user(10, Some(now + chrono::Duration::hours(1)))
                .still_needed(now, ttl, cooldown, lockout)
        );
        // An ended lock is remembered for a day, so the next one can be longer.
        assert!(
            user(10, Some(now - chrono::Duration::seconds(1)))
                .still_needed(now, ttl, cooldown, lockout)
        );
        assert!(
            !user(10, Some(now - chrono::Duration::hours(25)))
                .still_needed(now, ttl, cooldown, lockout)
        );
        assert!(!user(0, None).still_needed(now, ttl, cooldown, lockout));

        let recent = UserCodes {
            code: None,
            last_issued_at: Some(now - chrono::Duration::minutes(30)),
            failed_attempts: 3,
            locked_until: None,
            lockouts: 0,
            locked_until_reset: false,
        };
        assert!(recent.still_needed(now, ttl, cooldown, lockout));
        let recent_without_failures = UserCodes {
            failed_attempts: 0,
            ..recent
        };
        assert!(!recent_without_failures.still_needed(now, ttl, cooldown, lockout));
    }

    #[tokio::test]
    async fn revoking_a_users_verification_sessions_leaves_other_users_alone() {
        let mut storage = InMemoryVerificationSessionStorage::new(60);
        let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());
        let alice_one = storage
            .create_session(CredentialStamp::initial(alice))
            .await;
        let alice_two = storage
            .create_session(CredentialStamp::initial(alice))
            .await;
        let bob_one = storage.create_session(CredentialStamp::initial(bob)).await;

        assert_eq!(storage.revoke_all_for_user(alice).await, RevokeOutcome::Ok);

        assert_eq!(storage.get_session(&alice_one).await, None);
        assert_eq!(storage.get_session(&alice_two).await, None);
        assert_eq!(
            storage.get_session(&bob_one).await,
            Some(CredentialStamp::initial(bob))
        );
    }

    #[tokio::test]
    async fn sweep_removes_only_expired_codes() {
        let mut expired = InMemoryEmailVerificationCodeStorage::new(-1, 0);
        let _ = expired.issue_code(Uuid::new_v4()).await;
        expired.sweep_expired().await;
        assert_eq!(expired.entry_count().await, 0);

        let mut live = codes();
        let _ = live.issue_code(Uuid::new_v4()).await;
        live.sweep_expired().await;
        assert_eq!(live.entry_count().await, 1);
    }

    #[tokio::test]
    async fn set_password_overwrites_the_hash_and_bumps_updated_at() {
        let mut storage = InMemoryUserStorage::new();
        let mut user = User::default();
        user.email = "carol".to_string();
        user.password = Some(PasswordHash::Argon2("old-hash".into()));
        let user_id = user.id;
        let original_updated_at = user.updated_at;
        let _ = storage.create_user(user).await;

        assert_eq!(
            storage
                .set_password(user_id, PasswordHash::Argon2("new-hash".into()))
                .await,
            SetPasswordOutcome::Ok
        );

        let updated = storage.get_user_by_id(user_id).await.unwrap();
        assert_eq!(updated.password.unwrap().expose(), ("argon2", "new-hash"));
        assert!(updated.updated_at >= original_updated_at);
    }

    #[tokio::test]
    async fn set_password_bumps_the_credential_version() {
        let mut storage = InMemoryUserStorage::new();
        let user = User::default();
        let stamp = user.stamp();
        let _ = storage.create_user(user).await;

        let _ = storage
            .set_password(stamp.user_id, PasswordHash::Argon2("new-hash".into()))
            .await;

        let updated = storage.get_user_by_id(stamp.user_id).await.unwrap();
        assert_ne!(updated.stamp(), stamp);
    }

    #[tokio::test]
    async fn upgrade_password_hash_keeps_the_credential_version() {
        let mut storage = InMemoryUserStorage::new();
        let user = User::default();
        let stamp = user.stamp();
        let _ = storage.create_user(user).await;

        let outcome = storage
            .upgrade_password_hash(stamp, PasswordHash::Argon2("rehashed".into()))
            .await;

        assert_eq!(outcome, UpgradeHashOutcome::Ok);
        let updated = storage.get_user_by_id(stamp.user_id).await.unwrap();
        assert_eq!(updated.stamp(), stamp);
        assert_eq!(updated.password.unwrap().expose(), ("argon2", "rehashed"));
    }

    #[tokio::test]
    async fn upgrade_password_hash_does_not_overwrite_a_password_reset_since_the_stamp() {
        let mut storage = InMemoryUserStorage::new();
        let user = User::default();
        let stamp = user.stamp();
        let _ = storage.create_user(user).await;
        let _ = storage
            .set_password(stamp.user_id, PasswordHash::Argon2("reset".into()))
            .await;

        let outcome = storage
            .upgrade_password_hash(stamp, PasswordHash::Argon2("rehashed-old".into()))
            .await;

        assert_eq!(outcome, UpgradeHashOutcome::Stale);
        let updated = storage.get_user_by_id(stamp.user_id).await.unwrap();
        assert_eq!(updated.password.unwrap().expose(), ("argon2", "reset"));
    }

    #[tokio::test]
    async fn link_verified_oidc_identity_links_nothing_after_a_password_reset_since_the_stamp() {
        let mut storage = InMemoryUserStorage::new();
        let user = User::default();
        let stamp = user.stamp();
        let _ = storage.create_user(user).await;
        let _ = storage
            .set_password(stamp.user_id, PasswordHash::Argon2("reset".into()))
            .await;

        let linked = storage
            .link_verified_oidc_identity(stamp, "google", "attacker-sub")
            .await;

        assert!(linked.is_none());
        assert_eq!(
            storage.oidc_identity_owner("google", "attacker-sub").await,
            None
        );
    }

    #[tokio::test]
    async fn set_password_returns_user_not_found_for_an_unknown_user() {
        let mut storage = InMemoryUserStorage::new();
        assert_eq!(
            storage
                .set_password(Uuid::new_v4(), PasswordHash::Argon2("new-hash".into()))
                .await,
            SetPasswordOutcome::UserNotFound
        );
    }

    #[tokio::test]
    async fn pending_oidc_link_round_trips() {
        let mut storage = InMemoryPendingOidcLinkStorage::new(60);
        let existing_user_id = Uuid::new_v4();
        let token = storage
            .save_pending_link(
                "google".to_string(),
                "sub-123".to_string(),
                existing_user_id,
            )
            .await;

        let link = storage
            .take_pending_link(&token)
            .await
            .expect("link was saved");
        assert_eq!(link.provider, "google");
        assert_eq!(link.subject, "sub-123");
        assert_eq!(link.existing_user_id, existing_user_id);
    }

    #[tokio::test]
    async fn pending_oidc_link_is_single_use() {
        let mut storage = InMemoryPendingOidcLinkStorage::new(60);
        let token = storage
            .save_pending_link("google".to_string(), "sub-123".to_string(), Uuid::new_v4())
            .await;
        storage.take_pending_link(&token).await;

        assert!(storage.take_pending_link(&token).await.is_none());
    }

    #[tokio::test]
    async fn pending_oidc_link_rejects_expired_entries() {
        let mut storage = InMemoryPendingOidcLinkStorage::new(-1);
        let token = storage
            .save_pending_link("google".to_string(), "sub-123".to_string(), Uuid::new_v4())
            .await;

        assert!(storage.take_pending_link(&token).await.is_none());
    }

    #[tokio::test]
    async fn pending_oidc_link_is_not_yet_expired_exactly_at_the_ttl_boundary() {
        let mut storage = InMemoryPendingOidcLinkStorage::new(0);
        let token = storage
            .save_pending_link("google".to_string(), "sub-123".to_string(), Uuid::new_v4())
            .await;

        assert!(storage.take_pending_link(&token).await.is_some());
    }

    #[tokio::test]
    async fn pending_oidc_link_sweep_expired_removes_expired_entries() {
        let mut storage = InMemoryPendingOidcLinkStorage::new(-1);
        storage
            .save_pending_link("google".to_string(), "sub-123".to_string(), Uuid::new_v4())
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 0);
    }

    #[tokio::test]
    async fn pending_oidc_link_sweep_expired_keeps_entries_at_the_ttl_boundary() {
        let mut storage = InMemoryPendingOidcLinkStorage::new(0);
        storage
            .save_pending_link("google".to_string(), "sub-123".to_string(), Uuid::new_v4())
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 1);
    }

    async fn issue(storage: &mut InMemoryPasswordResetTokenStorage, user_id: Uuid) -> String {
        match storage.issue_reset_token(user_id).await {
            IssueResetOutcome::Issued(token) => token,
            IssueResetOutcome::CoolingDown => unreachable!("expected a token, got CoolingDown"),
        }
    }

    #[tokio::test]
    async fn password_reset_token_round_trips_to_the_user_it_was_issued_for() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(60, 0);
        let user_id = Uuid::new_v4();
        let token = issue(&mut storage, user_id).await;

        assert_eq!(storage.take_reset_token(&token).await, Some(user_id));
    }

    #[tokio::test]
    async fn password_reset_token_is_single_use() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(60, 0);
        let token = issue(&mut storage, Uuid::new_v4()).await;

        storage.take_reset_token(&token).await;
        assert_eq!(storage.take_reset_token(&token).await, None);
    }

    #[tokio::test]
    async fn password_reset_token_rejects_unknown_token() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(60, 0);
        assert_eq!(storage.take_reset_token("no-such-token").await, None);
    }

    #[tokio::test]
    async fn password_reset_token_rejects_expired_entries() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(-1, 0);
        let token = issue(&mut storage, Uuid::new_v4()).await;

        assert_eq!(storage.take_reset_token(&token).await, None);
    }

    #[tokio::test]
    async fn password_reset_token_is_not_yet_expired_exactly_at_the_ttl_boundary() {
        // ttl_secs=0, taken immediately: age is 0, which must NOT count as
        // expired (the check is "age > ttl", not "age >= ttl").
        let mut storage = InMemoryPasswordResetTokenStorage::new(0, 0);
        let user_id = Uuid::new_v4();
        let token = issue(&mut storage, user_id).await;

        assert_eq!(storage.take_reset_token(&token).await, Some(user_id));
    }

    #[tokio::test]
    async fn password_reset_sweep_expired_removes_expired_entries() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(-1, 0);
        issue(&mut storage, Uuid::new_v4()).await;

        storage.sweep_expired().await;

        assert_eq!(storage.token_count().await, 0);
    }

    #[tokio::test]
    async fn password_reset_sweep_expired_keeps_entries_at_the_ttl_boundary() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(0, 0);
        issue(&mut storage, Uuid::new_v4()).await;

        storage.sweep_expired().await;

        assert_eq!(storage.token_count().await, 1);
    }

    // An attacker re-requesting a reset must not kill the link the owner is about to open.
    #[tokio::test]
    async fn a_new_reset_token_leaves_the_users_earlier_one_working() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(60, 0);
        let user_id = Uuid::new_v4();
        let first = issue(&mut storage, user_id).await;
        let _second = issue(&mut storage, user_id).await;

        assert_eq!(storage.take_reset_token(&first).await, Some(user_id));
    }

    #[tokio::test]
    async fn redeeming_a_reset_token_spends_every_other_token_of_that_user_only() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(60, 0);
        let user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();
        let first = issue(&mut storage, user_id).await;
        let second = issue(&mut storage, user_id).await;
        let other_users_token = issue(&mut storage, other_user_id).await;

        assert_eq!(storage.take_reset_token(&first).await, Some(user_id));

        assert_eq!(storage.take_reset_token(&second).await, None);
        assert_eq!(
            storage.take_reset_token(&other_users_token).await,
            Some(other_user_id)
        );
    }

    #[tokio::test]
    async fn a_reset_requested_within_the_cooldown_issues_nothing_and_keeps_the_live_token() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(1_800, 60);
        let user_id = Uuid::new_v4();
        let token = issue(&mut storage, user_id).await;

        assert_eq!(
            storage.issue_reset_token(user_id).await,
            IssueResetOutcome::CoolingDown
        );
        assert_eq!(storage.take_reset_token(&token).await, Some(user_id));
    }

    #[tokio::test]
    async fn the_reset_cooldown_is_per_user() {
        let mut storage = InMemoryPasswordResetTokenStorage::new(1_800, 60);
        let _ = issue(&mut storage, Uuid::new_v4()).await;

        assert!(matches!(
            storage.issue_reset_token(Uuid::new_v4()).await,
            IssueResetOutcome::Issued(_)
        ));
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

        let state = storage
            .take_state("csrf-token")
            .await
            .expect("state was saved");
        assert_eq!(state.provider, "google");
        assert_eq!(state.pkce_verifier.expose_secret(), "verifier");
        assert_eq!(state.nonce.expose_secret(), "nonce");
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

        assert!(storage.take_state("csrf-token").await.is_none());
    }

    #[tokio::test]
    async fn oidc_state_is_not_yet_expired_exactly_at_the_ttl_boundary() {
        let mut storage = InMemoryOidcStateStorage::new(0);
        storage
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;

        assert!(storage.take_state("csrf-token").await.is_some());
    }

    #[tokio::test]
    async fn oidc_state_sweep_expired_removes_expired_entries() {
        let mut storage = InMemoryOidcStateStorage::new(-1);
        storage
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 0);
    }

    #[tokio::test]
    async fn oidc_state_sweep_expired_keeps_entries_at_the_ttl_boundary() {
        let mut storage = InMemoryOidcStateStorage::new(0);
        storage
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 1);
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

        assert!(storage.take_state("csrf-token").await.is_none());
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
                CredentialStamp::initial(user_id),
            )
            .await;
        let challenge = storage.take_code_challenge("test_code").await;
        assert_eq!(
            challenge,
            Some((
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                CredentialStamp::initial(user_id),
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
                CredentialStamp::initial(Uuid::new_v4()),
            )
            .await;
        storage.take_code_challenge("test_code").await;
        let challenge = storage.take_code_challenge("test_code").await;
        assert!(challenge.is_none());
    }

    #[tokio::test]
    async fn test_take_code_challenge_is_not_yet_expired_exactly_at_the_ttl_boundary() {
        let mut storage = InMemoryPkceStorage::new(0);
        storage
            .save_code_challenge(
                "test_code".to_string(),
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                CredentialStamp::initial(Uuid::new_v4()),
            )
            .await;

        assert!(storage.take_code_challenge("test_code").await.is_some());
    }

    #[tokio::test]
    async fn pkce_sweep_expired_removes_expired_entries() {
        let mut storage = InMemoryPkceStorage::new(-1);
        storage
            .save_code_challenge(
                "test_code".to_string(),
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                CredentialStamp::initial(Uuid::new_v4()),
            )
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 0);
    }

    #[tokio::test]
    async fn pkce_sweep_expired_keeps_entries_at_the_ttl_boundary() {
        let mut storage = InMemoryPkceStorage::new(0);
        storage
            .save_code_challenge(
                "test_code".to_string(),
                "test_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                CredentialStamp::initial(Uuid::new_v4()),
            )
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 1);
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
                CredentialStamp::initial(Uuid::new_v4()),
            )
            .await;
        let challenge = storage.take_code_challenge("test_code").await;
        assert!(challenge.is_none());
    }

    #[tokio::test]
    async fn login_session_round_trips_to_the_user_that_created_it() {
        let mut storage = InMemoryLoginSessionStorage::new(60);
        let user_id = Uuid::new_v4();
        let token = storage
            .create_session(CredentialStamp::initial(user_id))
            .await;

        assert_eq!(
            storage.take_session(&token).await,
            Some(CredentialStamp::initial(user_id))
        );
    }

    #[tokio::test]
    async fn login_session_is_single_use() {
        let mut storage = InMemoryLoginSessionStorage::new(60);
        let token = storage
            .create_session(CredentialStamp::initial(Uuid::new_v4()))
            .await;

        storage.take_session(&token).await;
        assert_eq!(storage.take_session(&token).await, None);
    }

    #[tokio::test]
    async fn login_session_rejects_unknown_token() {
        let mut storage = InMemoryLoginSessionStorage::new(60);
        assert_eq!(storage.take_session("no-such-token").await, None);
    }

    #[tokio::test]
    async fn login_session_is_not_yet_expired_exactly_at_the_ttl_boundary() {
        let mut storage = InMemoryLoginSessionStorage::new(0);
        let user_id = Uuid::new_v4();
        let token = storage
            .create_session(CredentialStamp::initial(user_id))
            .await;

        assert_eq!(
            storage.take_session(&token).await,
            Some(CredentialStamp::initial(user_id))
        );
    }

    #[tokio::test]
    async fn login_session_sweep_expired_removes_expired_entries() {
        let mut storage = InMemoryLoginSessionStorage::new(-1);
        storage
            .create_session(CredentialStamp::initial(Uuid::new_v4()))
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 0);
    }

    #[tokio::test]
    async fn login_session_sweep_expired_keeps_entries_at_the_ttl_boundary() {
        let mut storage = InMemoryLoginSessionStorage::new(0);
        storage
            .create_session(CredentialStamp::initial(Uuid::new_v4()))
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 1);
    }

    #[tokio::test]
    async fn login_session_rejects_expired_entries() {
        let mut storage = InMemoryLoginSessionStorage::new(-1);
        let token = storage
            .create_session(CredentialStamp::initial(Uuid::new_v4()))
            .await;

        assert_eq!(storage.take_session(&token).await, None);
    }

    #[tokio::test]
    async fn login_session_revoke_all_for_user_kills_only_that_users_sessions() {
        let mut storage = InMemoryLoginSessionStorage::new(60);
        let user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();
        let token = storage
            .create_session(CredentialStamp::initial(user_id))
            .await;
        let other_token = storage
            .create_session(CredentialStamp::initial(other_user_id))
            .await;

        let _ = storage.revoke_all_for_user(user_id).await;

        assert_eq!(storage.take_session(&token).await, None);
        assert_eq!(
            storage.take_session(&other_token).await,
            Some(CredentialStamp::initial(other_user_id))
        );
    }

    #[tokio::test]
    async fn refresh_token_round_trips_to_the_user_and_family_it_was_saved_with() {
        let mut storage = InMemoryRefreshTokenStorage::new(60);
        let user_id = Uuid::new_v4();
        let family_id = Uuid::new_v4();
        storage
            .save_refresh_token(
                "token1".to_string(),
                CredentialStamp::initial(user_id),
                family_id,
            )
            .await;

        assert_eq!(
            storage.take_refresh_token("token1").await,
            RefreshTokenOutcome::Valid {
                stamp: CredentialStamp::initial(user_id),
                family_id
            }
        );
    }

    #[tokio::test]
    async fn refresh_token_reuse_is_detected_and_revokes_the_whole_family() {
        let mut storage = InMemoryRefreshTokenStorage::new(60);
        let user_id = Uuid::new_v4();
        let family_id = Uuid::new_v4();
        storage
            .save_refresh_token(
                "token1".to_string(),
                CredentialStamp::initial(user_id),
                family_id,
            )
            .await;

        // Legitimate rotation: token1 -> token2, same family.
        assert_eq!(
            storage.take_refresh_token("token1").await,
            RefreshTokenOutcome::Valid {
                stamp: CredentialStamp::initial(user_id),
                family_id
            }
        );
        storage
            .save_refresh_token(
                "token2".to_string(),
                CredentialStamp::initial(user_id),
                family_id,
            )
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
    async fn refresh_token_is_not_yet_expired_exactly_at_the_ttl_boundary() {
        let mut storage = InMemoryRefreshTokenStorage::new(0);
        let user_id = Uuid::new_v4();
        let family_id = Uuid::new_v4();
        storage
            .save_refresh_token(
                "token1".to_string(),
                CredentialStamp::initial(user_id),
                family_id,
            )
            .await;

        assert_eq!(
            storage.take_refresh_token("token1").await,
            RefreshTokenOutcome::Valid {
                stamp: CredentialStamp::initial(user_id),
                family_id
            }
        );
    }

    #[tokio::test]
    async fn refresh_token_sweep_expired_removes_expired_entries() {
        let mut storage = InMemoryRefreshTokenStorage::new(-1);
        storage
            .save_refresh_token(
                "token1".to_string(),
                CredentialStamp::initial(Uuid::new_v4()),
                Uuid::new_v4(),
            )
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 0);
    }

    #[tokio::test]
    async fn refresh_token_sweep_expired_keeps_entries_at_the_ttl_boundary() {
        let mut storage = InMemoryRefreshTokenStorage::new(0);
        storage
            .save_refresh_token(
                "token1".to_string(),
                CredentialStamp::initial(Uuid::new_v4()),
                Uuid::new_v4(),
            )
            .await;

        storage.sweep_expired().await;

        assert_eq!(storage.entry_count().await, 1);
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
            .save_refresh_token(
                "token1".to_string(),
                CredentialStamp::initial(Uuid::new_v4()),
                Uuid::new_v4(),
            )
            .await;

        assert_eq!(
            storage.take_refresh_token("token1").await,
            RefreshTokenOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn refresh_token_revoke_all_for_user_kills_every_family_for_that_user_only() {
        let mut storage = InMemoryRefreshTokenStorage::new(60);
        let user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();
        storage
            .save_refresh_token(
                "token1".to_string(),
                CredentialStamp::initial(user_id),
                Uuid::new_v4(),
            )
            .await;
        storage
            .save_refresh_token(
                "token2".to_string(),
                CredentialStamp::initial(user_id),
                Uuid::new_v4(),
            )
            .await;
        storage
            .save_refresh_token(
                "other-token".to_string(),
                CredentialStamp::initial(other_user_id),
                Uuid::new_v4(),
            )
            .await;

        let _ = storage.revoke_all_for_user(user_id).await;

        assert_eq!(
            storage.take_refresh_token("token1").await,
            RefreshTokenOutcome::NotFound
        );
        assert_eq!(
            storage.take_refresh_token("token2").await,
            RefreshTokenOutcome::NotFound
        );
        assert!(matches!(
            storage.take_refresh_token("other-token").await,
            RefreshTokenOutcome::Valid { .. }
        ));
    }
}
