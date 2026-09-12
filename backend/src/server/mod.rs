use crate::config::Config;
use crate::server::router::router;
use crate::storage::in_memory::InMemoryPkceStorage;
use std::sync::Arc;

mod api;
pub mod router;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) pkce: InMemoryPkceStorage,
    pub(crate) redirect_uri_allowlist: Arc<Vec<String>>,
}

impl AppState {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            pkce: InMemoryPkceStorage::new(config.pkce_code_ttl_secs),
            redirect_uri_allowlist: Arc::new(config.redirect_uri_allowlist.clone()),
        }
    }
}

pub async fn app_start(config: &Config) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");

    axum::serve(listener, app(config)).await?;
    Ok(())
}

/// Builds the router with a fresh in-memory `AppState`. Exposed for integration tests.
pub fn app(config: &Config) -> axum::Router {
    router(AppState::new(config))
}
