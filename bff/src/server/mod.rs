use crate::config::Config;
use crate::hydra::Hydra;
use crate::model::session::{SessionData, SessionSelector};
use crate::server::origin_check::trusted_origins;
use crate::server::rate_limit::RateLimits;
use crate::server::refresh_lock::RefreshLocks;
use crate::server::router::{internal_router, public_router};
use crate::storage::in_memory::{InMemoryJtiStorage, InMemorySessionStorage};
use crate::storage::{ExpiryMaintenance, SessionStorage};
use secrecy::ExposeSecret;
use std::sync::Arc;
use std::time::Duration;

mod api;
pub(crate) mod cookie;
pub(crate) mod login_cookie;
pub(crate) mod origin_check;
pub(crate) mod rate_limit;
pub(crate) mod refresh_lock;
pub mod router;
pub(crate) mod secrets;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) sessions: InMemorySessionStorage,
    /// The `jti`s of the back-channel logout tokens accepted so far.
    pub(crate) logout_jtis: InMemoryJtiStorage,
    pub(crate) hydra: Arc<Hydra>,
    pub(crate) refresh_locks: RefreshLocks,
    pub(crate) rate_limits: RateLimits,
    /// The origins `origin_check::require_trusted_origin` accepts and CORS allows.
    pub(crate) trusted_origins: Arc<[String]>,
}

impl AppState {
    pub(crate) fn new(config: Config) -> anyhow::Result<Self> {
        Ok(Self {
            rate_limits: RateLimits::new(&config)?,
            trusted_origins: trusted_origins(&config)?,
            hydra: Arc::new(Hydra::new(&config)?),
            config: Arc::new(config),
            sessions: InMemorySessionStorage::new(),
            logout_jtis: InMemoryJtiStorage::new(),
            refresh_locks: RefreshLocks::default(),
        })
    }

    /// Ends the session `session_id` names: dropped from the store and its refresh token revoked
    /// at Hydra, as in [`AppState::end_sessions`]. Hands back what it dropped.
    pub(crate) async fn end_session(&mut self, session_id: &str) -> Option<SessionData> {
        let session = self.sessions.take_session(session_id).await?;
        if let Err(error) = self
            .hydra
            .revoke(session.refresh_token.expose_secret())
            .await
        {
            tracing::warn!(%error, "could not revoke the refresh token of an ended session");
        }
        Some(session)
    }

    /// Ends every session `selector` matches: dropped from the store, which loses bff's copy of
    /// the refresh token, and revoked at Hydra, which ending its own login session does not do.
    /// A refresh token Hydra can't be asked to revoke ends with its TTL.
    pub(crate) async fn end_sessions(&mut self, selector: &SessionSelector) {
        let ended = self.sessions.revoke(selector).await;
        self.revoke_refresh_tokens(ended).await;
    }

    /// Revokes the refresh tokens of sessions already dropped from the store, all at once and
    /// in a task of their own, so a cancelled caller doesn't leave the later ones alive.
    pub(crate) async fn revoke_refresh_tokens(&self, ended: Vec<SessionData>) {
        let hydra = self.hydra.clone();
        let task = tokio::spawn(async move {
            let revokes = ended.iter().map(|session| async {
                if let Err(error) = hydra.revoke(session.refresh_token.expose_secret()).await {
                    tracing::warn!(%error, "could not revoke the refresh token of an ended session");
                }
            });
            futures_util::future::join_all(revokes).await;
        });
        // A panic in the task only loses revocations that were already best-effort.
        let _ = task.await;
    }
}

/// Serves the public listener on `port` and the internal one on `internal_port`, until one
/// of them fails.
pub async fn app_start(config: Config) -> anyhow::Result<()> {
    let public_addr = format!("0.0.0.0:{}", config.port);
    let internal_addr = format!("0.0.0.0:{}", config.internal_port);
    let public_listener = tokio::net::TcpListener::bind(&public_addr).await?;
    let internal_listener = tokio::net::TcpListener::bind(&internal_addr).await?;
    tracing::info!("listening on {public_addr} (public) and {internal_addr} (internal)");

    let state = AppState::new(config)?;
    let sweep_interval = Duration::from_secs(common::config::EXPIRY_SWEEP_INTERVAL_SECS);
    spawn_expiry_sweep(state.clone(), sweep_interval);

    // with_connect_info: the rate limiter needs the peer address, the only one
    // it trusts unless the peer is in `trusted_proxies`.
    let public = axum::serve(
        public_listener,
        public_router(state.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );
    let internal = axum::serve(internal_listener, internal_router(state));
    tokio::try_join!(public, internal)?;
    Ok(())
}

fn spawn_expiry_sweep(mut state: AppState, interval: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval);
        loop {
            interval.tick().await;
            state.sessions.sweep_expired().await;
            state.logout_jtis.sweep_expired().await;
            state.refresh_locks.prune();
            state.rate_limits.retain_recent();
        }
    });
}

/// Builds the public and the internal router over one fresh in-memory `AppState`. Exposed
/// for integration tests.
pub fn apps(config: Config) -> anyhow::Result<(axum::Router, axum::Router)> {
    let state = AppState::new(config)?;
    Ok((public_router(state.clone()), internal_router(state)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::session::SessionData;
    use crate::storage::SessionStorage;
    use std::net::IpAddr;

    #[tokio::test]
    async fn the_expiry_sweep_forgets_clients_whose_bucket_refilled() {
        // 60000 a minute: an attempt back every millisecond. governor drops a key
        // one replenish period after it refilled, so 2ms after a single hit.
        let state = AppState::new(Config {
            rate_limit_max_attempts: 60_000,
            rate_limit_proxy_max_attempts: 60_000,
            ..Config::default()
        })
        .unwrap();
        let limits = state.rate_limits.clone();
        let client: IpAddr = "198.51.100.1".parse().unwrap();
        for governor in [&limits.auth, &limits.proxy] {
            governor.limiter().check_key(&client).unwrap();
            assert_eq!(governor.limiter().len(), 1);
        }

        spawn_expiry_sweep(state, Duration::from_millis(10));

        // governor runs on its own clock, not tokio's, so this polls real time.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let total = || -> usize {
            [&limits.auth, &limits.proxy]
                .iter()
                .map(|governor| governor.limiter().len())
                .sum()
        };
        while total() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(total(), 0);
    }

    #[tokio::test]
    async fn the_expiry_sweep_forgets_dead_sessions() {
        let mut state = AppState::new(Config::default()).unwrap();
        let past = chrono::Utc::now() - chrono::Duration::seconds(5);
        state
            .sessions
            .save_session(
                "dead".into(),
                SessionData {
                    access_token: "a".to_string().into(),
                    refresh_token: "r".to_string().into(),
                    id_token: "i".to_string().into(),
                    expires_at: past,
                    created_at: past,
                    refresh_expires_at: past,
                    user_id: uuid::Uuid::new_v4(),
                    sid: None,
                },
            )
            .await;
        let sessions = state.sessions.clone();

        spawn_expiry_sweep(state, Duration::from_millis(10));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while sessions.get_session("dead").await.is_some() && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(sessions.get_session("dead").await.is_none());
    }
}
