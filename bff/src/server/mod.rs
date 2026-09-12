use crate::config::Config;
use crate::server::router::router;
use crate::storage::in_memory::InMemorySessionStorage;
use std::sync::Arc;

mod api;
pub mod router;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) sessions: InMemorySessionStorage,
    pub(crate) http_client: reqwest::Client,
}

impl AppState {
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            sessions: InMemorySessionStorage::new(),
            // No auto-follow: /login needs the raw 303 from backend's
            // /oauth/authorize to read `code` out of its Location header itself.
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("http client"),
        }
    }
}

pub async fn app_start(config: Config) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");

    axum::serve(listener, app(config)).await?;
    Ok(())
}

/// Builds the router with a fresh in-memory `AppState`. Exposed for integration tests.
pub fn app(config: Config) -> axum::Router {
    router(AppState::new(config))
}
