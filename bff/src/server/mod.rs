use crate::config::Config;
use crate::server::router::router;
use crate::storage::in_memory::InMemorySessionStorage;
use crate::storage::ExpiryMaintenance;
use std::sync::Arc;
use std::time::Duration;

mod api;
pub(crate) mod cookie;
pub(crate) mod origin_check;
pub mod router;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) sessions: InMemorySessionStorage,
    pub(crate) http_client: reqwest::Client,
}

impl AppState {
    pub(crate) fn new(config: Config) -> anyhow::Result<Self> {
        Ok(Self {
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
    let sweep_interval = Duration::from_secs(state.config.expiry_sweep_interval_secs);
    spawn_expiry_sweep(state.clone(), sweep_interval);

    // with_connect_info: the rate limiter keys on the real client IP
    // (extract::ConnectInfo), not a spoofable header.
    axum::serve(
        listener,
        router(state)?.into_make_service_with_connect_info::<std::net::SocketAddr>(),
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
        }
    });
}

/// Builds the router with a fresh in-memory `AppState`. Exposed for integration tests.
pub fn app(config: Config) -> anyhow::Result<axum::Router> {
    router(AppState::new(config)?)
}
