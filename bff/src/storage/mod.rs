use crate::model::session::{SessionData, SessionSelector};
use chrono::{DateTime, Utc};
use thiserror::Error;

pub(crate) mod in_memory;

/// The session an update was for no longer exists.
#[derive(Debug, Error, Eq, PartialEq)]
#[error("session no longer exists")]
pub(crate) struct SessionGone;

pub(crate) trait SessionStorage {
    /// Stores a new session. A user keeps at most [`in_memory::MAX_SESSIONS_PER_USER`] sessions:
    /// the oldest beyond that are dropped and handed back, their refresh tokens still live at Hydra.
    async fn save_session(&mut self, session_id: String, data: SessionData) -> Vec<SessionData>;
    async fn get_session(&self, session_id: &str) -> Option<SessionData>;
    /// Replaces an existing session only: a refresh that finishes after a logout
    /// must not bring the session back.
    async fn update_session(
        &mut self,
        session_id: &str,
        data: SessionData,
    ) -> Result<(), SessionGone>;
    /// Drops the session and hands it back.
    async fn take_session(&mut self, session_id: &str) -> Option<SessionData>;
    /// Drops every session `selector` matches. The browser only ever holds the
    /// session id, so this ends its access token's use at once, too.
    /// Hands back what it dropped, whose refresh tokens are still live at Hydra.
    async fn revoke(&mut self, selector: &SessionSelector) -> Vec<SessionData>;
}

/// A logout token's `jti` was already used.
#[derive(Debug, Error, Eq, PartialEq)]
#[error("jti already used")]
pub(crate) struct JtiReplayed;

/// The `jti`s of the logout tokens accepted so far, so one can't be replayed.
pub(crate) trait JtiStorage {
    /// Remembers `jti` until `until`, or says it was already remembered.
    async fn record(&mut self, jti: &str, until: DateTime<Utc>) -> Result<(), JtiReplayed>;
}

/// Periodic upkeep for storage backends that accumulate entries with no
/// other removal path. A store with a native TTL can implement this as a no-op.
pub(crate) trait ExpiryMaintenance {
    async fn sweep_expired(&mut self);
}
