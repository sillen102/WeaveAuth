use crate::config::Config;
use crate::server::api::proxy::proxy_trusted_origins;
use crate::server::rate_limit::RateLimits;
use crate::server::router::router;
use crate::storage::ExpiryMaintenance;
use crate::storage::in_memory::InMemorySessionStorage;
use std::sync::Arc;
use std::time::Duration;

mod api;
pub(crate) mod cookie;
pub(crate) mod origin_check;
pub(crate) mod rate_limit;
pub mod router;
pub(crate) mod verification;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) sessions: InMemorySessionStorage,
    pub(crate) http_client: reqwest::Client,
    pub(crate) rate_limits: RateLimits,
    pub(crate) proxy_trusted_origins: Arc<[String]>,
}

impl AppState {
    pub(crate) fn new(config: Config) -> anyhow::Result<Self> {
        Ok(Self {
            rate_limits: RateLimits::new(&config)?,
            proxy_trusted_origins: proxy_trusted_origins(&config)?,
            config: Arc::new(config),
            sessions: InMemorySessionStorage::new(),
            // No auto-follow: callers that hop through backend's
            // /oauth/authorize (e.g. /login, /register's auto-login path)
            // need the raw 303 to read `code` out of its Location header
            // themselves.
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
}

pub async fn app_start(config: Config) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");

    let state = AppState::new(config)?;
    let sweep_interval = Duration::from_secs(common::config::EXPIRY_SWEEP_INTERVAL_SECS);
    spawn_expiry_sweep(state.clone(), sweep_interval);

    // with_connect_info: the rate limiter needs the peer address, the only one
    // it trusts unless the peer is in `trusted_proxies`.
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn spawn_expiry_sweep(mut state: AppState, interval: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval);
        loop {
            interval.tick().await;
            state.sessions.sweep_expired().await;
            state.rate_limits.retain_recent();
        }
    });
}

/// Builds the router with a fresh in-memory `AppState`. Exposed for integration tests.
pub fn app(config: Config) -> anyhow::Result<axum::Router> {
    Ok(router(AppState::new(config)?))
}

#[cfg(test)]
mod tests {
    use super::*;
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
        for governor in [&limits.auth, &limits.proxy, &limits.docs] {
            governor.limiter().check_key(&client).unwrap();
            assert_eq!(governor.limiter().len(), 1);
        }

        spawn_expiry_sweep(state, Duration::from_millis(10));

        // governor runs on its own clock, not tokio's, so this polls real time.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let total = || -> usize {
            [&limits.auth, &limits.proxy, &limits.docs]
                .iter()
                .map(|governor| governor.limiter().len())
                .sum()
        };
        while total() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(total(), 0);
    }
}
