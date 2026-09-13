use crate::config::Config;
use crate::server::router::router;
use crate::storage::in_memory::InMemorySessionStorage;
use std::sync::Arc;

mod api;
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
            // No auto-follow: /login needs the raw 303 from backend's
            // /oauth/authorize to read `code` out of its Location header itself.
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

    // with_connect_info: the rate limiter keys on the real client IP
    // (extract::ConnectInfo), not a spoofable header.
    axum::serve(
        listener,
        app(config)?.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Builds the router with a fresh in-memory `AppState`. Exposed for integration tests.
pub fn app(config: Config) -> anyhow::Result<axum::Router> {
    router(AppState::new(config)?)
}
