use crate::config::Config;
use crate::server::router::router;
use crate::storage::in_memory::{
    InMemoryJwkStorage, InMemoryLoginSessionStorage, InMemoryPkceStorage, InMemoryUserStorage,
};
use std::sync::Arc;

mod api;
pub mod router;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) pkce: InMemoryPkceStorage,
    pub(crate) users: InMemoryUserStorage,
    pub(crate) login_sessions: InMemoryLoginSessionStorage,
    pub(crate) redirect_uri_allowlist: Arc<Vec<String>>,
    pub(crate) jwt_keys: InMemoryJwkStorage,
    pub(crate) access_token_ttl_secs: i64,
}

impl AppState {
    pub(crate) fn new(config: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            pkce: InMemoryPkceStorage::new(config.pkce_code_ttl_secs),
            users: InMemoryUserStorage::new(),
            login_sessions: InMemoryLoginSessionStorage::new(config.login_session_ttl_secs),
            redirect_uri_allowlist: Arc::new(config.redirect_uri_allowlist.clone()),
            jwt_keys: InMemoryJwkStorage::new()?,
            access_token_ttl_secs: config.access_token_ttl_secs,
        })
    }
}

pub async fn app_start(config: &Config) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");

    axum::serve(listener, app(config)?).await?;
    Ok(())
}

/// Builds the router with a fresh in-memory `AppState`. Exposed for integration tests.
pub fn app(config: &Config) -> anyhow::Result<axum::Router> {
    Ok(router(AppState::new(config)?))
}
