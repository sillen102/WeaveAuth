use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// One lock per session, so concurrent requests of a session whose access token expired
/// share a single refresh: Hydra revokes the whole token chain when a refresh token that was
/// already rotated is presented again, so two refreshes racing would log the user out.
#[derive(Clone, Default)]
pub(crate) struct RefreshLocks {
    locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

/// Held while a session is refreshed. Dropping it -- on success, failure or because the
/// request was cancelled -- lets the next waiter in, and forgets the session's lock when
/// nobody waits for it.
pub(crate) struct RefreshGuard {
    locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
    session_id: String,
    guard: Option<OwnedMutexGuard<()>>,
}

impl RefreshLocks {
    /// Waits for the session's turn to refresh.
    pub(crate) async fn acquire(&self, session_id: &str) -> RefreshGuard {
        let lock = self
            .map()
            .entry(session_id.to_string())
            .or_default()
            .clone();
        RefreshGuard {
            locks: self.locks.clone(),
            session_id: session_id.to_string(),
            guard: Some(lock.lock_owned().await),
        }
    }

    /// Forgets the locks nobody holds or waits for: ones whose request was cancelled between
    /// asking for the lock and having it.
    pub(crate) fn prune(&self) {
        self.map().retain(|_, lock| Arc::strong_count(lock) > 1);
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<AsyncMutex<()>>>> {
        // The map holds no invariant a panic could break.
        self.locks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map().len()
    }
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        // Release first: the guard owns a handle to the lock too. Then the map's is the
        // only one left unless somebody waits for the lock or is about to.
        drop(self.guard.take());
        if locks
            .get(&self.session_id)
            .is_some_and(|lock| Arc::strong_count(lock) == 1)
        {
            locks.remove(&self.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_second_refresh_of_the_same_session_waits_for_the_first() {
        let locks = RefreshLocks::default();
        let first = locks.acquire("s1").await;

        let second = tokio::time::timeout(Duration::from_millis(50), locks.acquire("s1")).await;
        assert!(second.is_err(), "the lock was not held");

        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(1), locks.acquire("s1")).await;
        assert!(second.is_ok(), "the lock was not released");
    }

    #[tokio::test]
    async fn other_sessions_do_not_wait() {
        let locks = RefreshLocks::default();
        let _first = locks.acquire("s1").await;

        let other = tokio::time::timeout(Duration::from_millis(500), locks.acquire("s2")).await;

        assert!(other.is_ok());
    }

    #[tokio::test]
    async fn a_cancelled_waiter_or_holder_does_not_leave_the_lock_stuck() {
        let locks = RefreshLocks::default();
        let holder = {
            let locks = locks.clone();
            tokio::spawn(async move {
                let _guard = locks.acquire("s1").await;
                std::future::pending::<()>().await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let waiter = {
            let locks = locks.clone();
            tokio::spawn(async move { locks.acquire("s1").await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The request holding the refresh goes away (client disconnect), and so does a waiter.
        holder.abort();
        waiter.abort();
        let _ = holder.await;
        let _ = waiter.await;

        let next = tokio::time::timeout(Duration::from_secs(1), locks.acquire("s1")).await;
        assert!(next.is_ok(), "the lock stayed held");
    }

    #[tokio::test]
    async fn a_lock_nobody_waits_for_is_forgotten() {
        let locks = RefreshLocks::default();

        drop(locks.acquire("s1").await);
        drop(locks.acquire("s2").await);

        assert_eq!(locks.len(), 0);
    }

    #[tokio::test]
    async fn pruning_forgets_only_locks_nobody_holds() {
        let locks = RefreshLocks::default();
        let held = locks.acquire("held").await;
        // What a request cancelled before it had the lock leaves behind.
        locks.map().insert("orphan".into(), Arc::default());

        locks.prune();

        assert_eq!(locks.len(), 1);
        drop(held);
        assert_eq!(locks.len(), 0);
    }

    #[tokio::test]
    async fn a_lock_somebody_waits_for_is_kept_until_the_last_waiter_is_done() {
        let locks = RefreshLocks::default();
        let first = locks.acquire("s1").await;
        let waiter = {
            let locks = locks.clone();
            tokio::spawn(async move { locks.acquire("s1").await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;

        drop(first);
        let second = waiter.await.unwrap();
        assert_eq!(locks.len(), 1);

        drop(second);
        assert_eq!(locks.len(), 0);
    }
}
