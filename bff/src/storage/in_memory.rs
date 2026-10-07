use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::model::session::{SessionData, SessionSelector};
use crate::storage::{ExpiryMaintenance, JtiReplayed, JtiStorage, SessionGone, SessionStorage};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// How many sessions one user may hold at once; a login beyond it ends the oldest.
pub(crate) const MAX_SESSIONS_PER_USER: usize = 20;

#[derive(Default)]
struct Sessions {
    by_id: HashMap<String, SessionData>,
    /// Session ids per user, so a per-user lookup doesn't scan every session. Kept in step with
    /// `by_id` by `insert` and `remove` only.
    by_user: HashMap<Uuid, Vec<String>>,
}

impl Sessions {
    fn insert(&mut self, session_id: String, data: SessionData) {
        let user_id = data.user_id;
        if let Some(replaced) = self.by_id.insert(session_id.clone(), data) {
            self.unindex(&session_id, replaced.user_id);
        }
        self.by_user.entry(user_id).or_default().push(session_id);
    }

    fn remove(&mut self, session_id: &str) -> Option<SessionData> {
        let data = self.by_id.remove(session_id)?;
        self.unindex(session_id, data.user_id);
        Some(data)
    }

    fn unindex(&mut self, session_id: &str, user_id: Uuid) {
        if let Some(ids) = self.by_user.get_mut(&user_id) {
            ids.retain(|own| own != session_id);
            if ids.is_empty() {
                self.by_user.remove(&user_id);
            }
        }
    }

    fn remove_all(&mut self, ids: Vec<String>) -> Vec<SessionData> {
        ids.iter().filter_map(|id| self.remove(id)).collect()
    }
}

#[derive(Clone)]
pub(crate) struct InMemorySessionStorage {
    sessions: Arc<Mutex<Sessions>>,
}

impl InMemorySessionStorage {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(Sessions::default())),
        }
    }
}

impl SessionStorage for InMemorySessionStorage {
    async fn save_session(&mut self, session_id: String, data: SessionData) -> Vec<SessionData> {
        let user_id = data.user_id;
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session_id, data);
        let mut own: Vec<(String, DateTime<Utc>)> = sessions
            .by_user
            .get(&user_id)
            .into_iter()
            .flatten()
            .filter_map(|id| Some((id.clone(), sessions.by_id.get(id)?.created_at)))
            .collect();
        let excess = own.len().saturating_sub(MAX_SESSIONS_PER_USER);
        own.sort_by_key(|(_, created_at)| *created_at);
        let oldest = own.into_iter().take(excess).map(|(id, _)| id).collect();
        sessions.remove_all(oldest)
    }

    async fn get_session(&self, session_id: &str) -> Option<SessionData> {
        self.sessions.lock().await.by_id.get(session_id).cloned()
    }

    async fn update_session(
        &mut self,
        session_id: &str,
        data: SessionData,
    ) -> Result<(), SessionGone> {
        let mut sessions = self.sessions.lock().await;
        if !sessions.by_id.contains_key(session_id) {
            return Err(SessionGone);
        }
        sessions.remove(session_id);
        sessions.insert(session_id.to_string(), data);
        Ok(())
    }

    async fn take_session(&mut self, session_id: &str) -> Option<SessionData> {
        self.sessions.lock().await.remove(session_id)
    }

    async fn revoke(&mut self, selector: &SessionSelector) -> Vec<SessionData> {
        let mut sessions = self.sessions.lock().await;
        let ids: Vec<String> = match selector {
            SessionSelector::User(user_id) | SessionSelector::UserSession { user_id, .. } => {
                sessions
                    .by_user
                    .get(user_id)
                    .into_iter()
                    .flatten()
                    .filter(|id| sessions.by_id.get(*id).is_some_and(|s| selector.matches(s)))
                    .cloned()
                    .collect()
            }
            SessionSelector::Session { .. } => sessions
                .by_id
                .iter()
                .filter(|(_, data)| selector.matches(data))
                .map(|(id, _)| id.clone())
                .collect(),
        };
        sessions.remove_all(ids)
    }
}

impl ExpiryMaintenance for InMemorySessionStorage {
    async fn sweep_expired(&mut self) {
        let now = Utc::now();
        let mut sessions = self.sessions.lock().await;
        // `ends_at` is the outer bound -- the proxy can still silently refresh the access
        // token up until then.
        let expired = sessions
            .by_id
            .iter()
            .filter(|(_, data)| data.ends_at() <= now)
            .map(|(id, _)| id.clone())
            .collect();
        sessions.remove_all(expired);
    }
}

#[derive(Clone)]
pub(crate) struct InMemoryJtiStorage {
    used: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

impl InMemoryJtiStorage {
    pub fn new() -> Self {
        Self {
            used: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl JtiStorage for InMemoryJtiStorage {
    async fn record(&mut self, jti: &str, until: DateTime<Utc>) -> Result<(), JtiReplayed> {
        let now = Utc::now();
        let mut used = self.used.lock().await;
        // A sweep may not have run since this one expired.
        if used.get(jti).is_some_and(|remembered| *remembered > now) {
            return Err(JtiReplayed);
        }
        used.insert(jti.to_string(), until);
        Ok(())
    }
}

impl ExpiryMaintenance for InMemoryJtiStorage {
    async fn sweep_expired(&mut self) {
        let now = Utc::now();
        self.used.lock().await.retain(|_, until| *until > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use secrecy::ExposeSecret;

    fn sample_session(token: &str) -> SessionData {
        SessionData {
            access_token: token.into(),
            refresh_token: format!("{token}-refresh").into(),
            id_token: format!("{token}-id").into(),
            expires_at: Utc::now(),
            created_at: Utc::now(),
            refresh_expires_at: Utc::now(),
            user_id: uuid::Uuid::new_v4(),
            sid: None,
        }
    }

    fn session_of(user_id: uuid::Uuid, sid: Option<&str>) -> SessionData {
        SessionData {
            user_id,
            sid: sid.map(str::to_string),
            ..sample_session("t")
        }
    }

    #[tokio::test]
    async fn revoking_a_user_drops_only_that_users_sessions() {
        let mut storage = InMemorySessionStorage::new();
        let alice = sample_session("alice");
        let alice_id = alice.user_id;
        storage.save_session("a1".to_string(), alice.clone()).await;
        storage.save_session("a2".to_string(), alice).await;
        storage
            .save_session("b1".to_string(), sample_session("bob"))
            .await;

        storage.revoke(&SessionSelector::User(alice_id)).await;

        assert!(storage.get_session("a1").await.is_none());
        assert!(storage.get_session("a2").await.is_none());
        assert!(storage.get_session("b1").await.is_some());
    }

    #[tokio::test]
    async fn a_user_beyond_the_session_cap_loses_the_oldest_and_gets_it_handed_back() {
        let mut storage = InMemorySessionStorage::new();
        let user = uuid::Uuid::new_v4();
        let other = session_of(uuid::Uuid::new_v4(), None);
        storage.save_session("other".to_string(), other).await;
        for n in 0..MAX_SESSIONS_PER_USER {
            let mut session = session_of(user, None);
            session.created_at = Utc::now() - chrono::Duration::seconds(1000 - n as i64);
            let evicted = storage.save_session(format!("s{n}"), session).await;
            assert!(evicted.is_empty());
        }

        let evicted = storage
            .save_session("newest".to_string(), session_of(user, None))
            .await;

        assert_eq!(evicted.len(), 1);
        assert!(storage.get_session("s0").await.is_none());
        assert!(storage.get_session("s1").await.is_some());
        assert!(storage.get_session("newest").await.is_some());
        assert!(storage.get_session("other").await.is_some());
    }

    #[tokio::test]
    async fn revoking_hands_back_the_dropped_sessions() {
        let mut storage = InMemorySessionStorage::new();
        let alice = uuid::Uuid::new_v4();
        storage
            .save_session("a".into(), session_of(alice, Some("sid-1")))
            .await;
        storage
            .save_session("b".into(), session_of(uuid::Uuid::new_v4(), None))
            .await;

        let dropped = storage.revoke(&SessionSelector::User(alice)).await;

        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].user_id, alice);
    }

    #[tokio::test]
    async fn revoking_a_login_session_keeps_the_users_other_ones() {
        let mut storage = InMemorySessionStorage::new();
        let (alice, bob) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        for (id, session) in [
            ("a-one", session_of(alice, Some("sid-1"))),
            ("a-two", session_of(alice, Some("sid-2"))),
            ("a-none", session_of(alice, None)),
            ("b-one", session_of(bob, Some("sid-1"))),
        ] {
            storage.save_session(id.to_string(), session).await;
        }

        storage
            .revoke(&SessionSelector::UserSession {
                user_id: alice,
                sid: "sid-1".into(),
            })
            .await;

        assert!(storage.get_session("a-one").await.is_none());
        assert!(
            storage.get_session("a-none").await.is_none(),
            "a session with no recorded sid can't be told apart, so it goes too"
        );
        assert!(storage.get_session("a-two").await.is_some());
        assert!(storage.get_session("b-one").await.is_some());
    }

    #[tokio::test]
    async fn revoking_by_sid_alone_never_touches_a_session_without_one() {
        let mut storage = InMemorySessionStorage::new();
        let alice = uuid::Uuid::new_v4();
        storage
            .save_session("one".into(), session_of(alice, Some("sid-1")))
            .await;
        storage
            .save_session("two".into(), session_of(alice, Some("sid-2")))
            .await;
        storage
            .save_session("none".into(), session_of(alice, None))
            .await;

        storage
            .revoke(&SessionSelector::Session {
                sid: "sid-1".into(),
            })
            .await;

        assert!(storage.get_session("one").await.is_none());
        assert!(storage.get_session("two").await.is_some());
        assert!(storage.get_session("none").await.is_some());
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
        assert_eq!(data.id_token.expose_secret(), "token-1-id");
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

    #[tokio::test]
    async fn update_replaces_an_existing_session_but_never_creates_one() {
        let mut storage = InMemorySessionStorage::new();
        storage
            .save_session("session-1".to_string(), sample_session("token-1"))
            .await;

        storage
            .update_session("session-1", sample_session("token-2"))
            .await
            .unwrap();
        let missing = storage
            .update_session("session-2", sample_session("token-3"))
            .await;

        assert_eq!(
            storage
                .get_session("session-1")
                .await
                .unwrap()
                .access_token
                .expose_secret(),
            "token-2"
        );
        assert_eq!(missing, Err(SessionGone));
        assert!(storage.get_session("session-2").await.is_none());
    }

    #[tokio::test]
    async fn take_session_removes_and_returns_it() {
        let mut storage = InMemorySessionStorage::new();
        storage
            .save_session("session-1".to_string(), sample_session("token-1"))
            .await;

        let taken = storage.take_session("session-1").await.unwrap();

        assert_eq!(taken.access_token.expose_secret(), "token-1");
        assert!(storage.get_session("session-1").await.is_none());
        assert!(storage.take_session("session-1").await.is_none());
    }

    #[tokio::test]
    async fn the_sweep_drops_only_sessions_whose_refresh_token_died() {
        let mut storage = InMemorySessionStorage::new();
        let mut live = sample_session("live");
        live.refresh_expires_at = Utc::now() + Duration::hours(1);
        let mut dead = sample_session("dead");
        dead.refresh_expires_at = Utc::now() - Duration::seconds(1);
        storage.save_session("live".into(), live).await;
        storage.save_session("dead".into(), dead).await;

        storage.sweep_expired().await;

        assert!(storage.get_session("live").await.is_some());
        assert!(storage.get_session("dead").await.is_none());
    }

    #[tokio::test]
    async fn the_sweep_drops_a_session_past_the_max_lifetime_whose_refresh_token_lives() {
        let mut storage = InMemorySessionStorage::new();
        let mut old = sample_session("old");
        old.created_at =
            Utc::now() - crate::model::session::MAX_SESSION_LIFETIME - Duration::seconds(1);
        old.refresh_expires_at = Utc::now() + Duration::hours(1);
        storage.save_session("old".into(), old).await;

        storage.sweep_expired().await;

        assert!(storage.get_session("old").await.is_none());
    }

    #[tokio::test]
    async fn the_user_index_follows_every_way_a_session_leaves() {
        let mut storage = InMemorySessionStorage::new();
        let user = uuid::Uuid::new_v4();
        let mut live = session_of(user, None);
        live.refresh_expires_at = Utc::now() + Duration::hours(1);
        let mut dead = session_of(user, None);
        dead.refresh_expires_at = Utc::now() - Duration::seconds(1);
        storage.save_session("taken".into(), live.clone()).await;
        storage.save_session("revoked".into(), live).await;
        storage.save_session("dead".into(), dead).await;
        assert_eq!(storage.sessions.lock().await.by_user[&user].len(), 3);

        storage.take_session("taken").await;
        assert_eq!(storage.sessions.lock().await.by_user[&user].len(), 2);
        storage.sweep_expired().await;
        assert_eq!(storage.sessions.lock().await.by_user[&user], ["revoked"]);
        storage.revoke(&SessionSelector::User(user)).await;
        assert!(storage.sessions.lock().await.by_user.is_empty());
    }

    #[tokio::test]
    async fn the_user_index_follows_an_eviction() {
        let mut storage = InMemorySessionStorage::new();
        let user = uuid::Uuid::new_v4();
        for n in 0..=MAX_SESSIONS_PER_USER {
            let mut session = session_of(user, None);
            session.created_at = Utc::now() - Duration::seconds(1000 - n as i64);
            storage.save_session(format!("s{n}"), session).await;
        }

        let sessions = storage.sessions.lock().await;
        assert_eq!(sessions.by_user[&user].len(), MAX_SESSIONS_PER_USER);
        assert!(!sessions.by_user[&user].contains(&"s0".to_string()));
    }

    #[tokio::test]
    async fn a_jti_can_be_recorded_once() {
        let mut jtis = InMemoryJtiStorage::new();
        let until = Utc::now() + Duration::minutes(10);

        assert_eq!(jtis.record("jti-1", until).await, Ok(()));
        assert_eq!(jtis.record("jti-1", until).await, Err(JtiReplayed));
        assert_eq!(jtis.record("jti-2", until).await, Ok(()));
    }

    #[tokio::test]
    async fn a_jti_whose_window_passed_is_forgotten_even_before_a_sweep() {
        let mut jtis = InMemoryJtiStorage::new();
        jtis.record("jti-1", Utc::now() - Duration::seconds(1))
            .await
            .unwrap();

        assert_eq!(
            jtis.record("jti-1", Utc::now() + Duration::minutes(1))
                .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn the_sweep_forgets_expired_jtis_only() {
        let mut jtis = InMemoryJtiStorage::new();
        jtis.record("old", Utc::now() - Duration::seconds(1))
            .await
            .unwrap();
        jtis.record("fresh", Utc::now() + Duration::minutes(5))
            .await
            .unwrap();

        jtis.sweep_expired().await;

        assert_eq!(jtis.used.lock().await.len(), 1);
        assert_eq!(
            jtis.record("fresh", Utc::now() + Duration::minutes(5))
                .await,
            Err(JtiReplayed)
        );
    }
}
