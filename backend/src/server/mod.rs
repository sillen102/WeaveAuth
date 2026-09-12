use crate::config::Config;
use crate::server::router::router;
use crate::storage::in_memory::InMemoryPkceStorage;

mod api;
pub mod router;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) pkce: InMemoryPkceStorage,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            pkce: InMemoryPkceStorage::new(),
        }
    }
}

pub async fn app_start(config: &Config) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");

    axum::serve(listener, router()).await?;
    Ok(())
}
