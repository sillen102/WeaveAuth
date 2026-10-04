use crate::model::session::SessionData;

pub(crate) mod in_memory;

pub(crate) trait SessionStorage {
    async fn save_session(&mut self, session_id: String, data: SessionData);
    async fn get_session(&self, session_id: &str) -> Option<SessionData>;
    /// Drops every session of `user_id`. The browser only ever holds the
    /// session id, so this ends its access token's use at once, too.
    async fn revoke_all_for_user(&mut self, user_id: uuid::Uuid);
}

/// Periodic upkeep for storage backends that accumulate entries with no
/// other removal path -- see the identical trait in the backend crate for
/// why. A store with a native TTL can implement this as a no-op.
pub(crate) trait ExpiryMaintenance {
    async fn sweep_expired(&mut self);
}
