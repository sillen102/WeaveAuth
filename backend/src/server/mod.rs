use crate::config::Config;
use crate::oidc::{self, OidcClient};
use crate::server::router::router;
use crate::storage::in_memory::{
    InMemoryJwkStorage, InMemoryLoginSessionStorage, InMemoryOidcStateStorage,
    InMemoryPasswordResetTokenStorage, InMemoryPendingOidcLinkStorage, InMemoryPkceStorage,
    InMemoryRefreshTokenStorage, InMemoryUserStorage,
};
use crate::storage::ExpiryMaintenance;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

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
    pub(crate) refresh_tokens: InMemoryRefreshTokenStorage,
    pub(crate) refresh_token_ttl_secs: i64,
    pub(crate) oidc_providers: Arc<HashMap<String, OidcClient>>,
    pub(crate) oidc_state: InMemoryOidcStateStorage,
    pub(crate) pending_oidc_links: InMemoryPendingOidcLinkStorage,
    pub(crate) oidc_http_client: Arc<openidconnect::reqwest::Client>,
    pub(crate) password_reset_tokens: InMemoryPasswordResetTokenStorage,
    pub(crate) max_bcrypt_cost: u32,
}

impl AppState {
    /// Sweeps every TTL'd store once. Called on an interval by `app_start`;
    /// split out so tests can drive it directly without a real timer.
    pub(crate) async fn sweep_expired(&mut self) {
        self.pkce.sweep_expired().await;
        self.login_sessions.sweep_expired().await;
        self.refresh_tokens.sweep_expired().await;
        self.oidc_state.sweep_expired().await;
        self.pending_oidc_links.sweep_expired().await;
        self.password_reset_tokens.sweep_expired().await;
    }

    pub(crate) async fn new(config: &Config) -> anyhow::Result<Self> {
        // No redirects: an OIDC provider redirecting this server-side request
        // elsewhere would be a request-forgery vector, not a legitimate flow.
        let oidc_http_client = Arc::new(
            openidconnect::reqwest::ClientBuilder::new()
                .redirect(openidconnect::reqwest::redirect::Policy::none())
                .build()?,
        );
        let oidc_providers = oidc::build_providers(&config.oidc_providers, &oidc_http_client).await?;

        Ok(Self {
            pkce: InMemoryPkceStorage::new(config.pkce_code_ttl_secs),
            users: InMemoryUserStorage::new(),
            login_sessions: InMemoryLoginSessionStorage::new(config.login_session_ttl_secs),
            redirect_uri_allowlist: Arc::new(config.redirect_uri_allowlist.clone()),
            jwt_keys: InMemoryJwkStorage::new()?,
            access_token_ttl_secs: config.access_token_ttl_secs,
            refresh_tokens: InMemoryRefreshTokenStorage::new(config.refresh_token_ttl_secs),
            refresh_token_ttl_secs: config.refresh_token_ttl_secs,
            oidc_providers: Arc::new(oidc_providers),
            oidc_state: InMemoryOidcStateStorage::new(config.oidc_state_ttl_secs),
            pending_oidc_links: InMemoryPendingOidcLinkStorage::new(config.pending_oidc_link_ttl_secs),
            oidc_http_client,
            password_reset_tokens: InMemoryPasswordResetTokenStorage::new(config.password_reset_token_ttl_secs),
            max_bcrypt_cost: config.max_bcrypt_cost,
        })
    }
}

pub async fn app_start(config: &Config) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");

    let state = AppState::new(config).await?;
    spawn_expiry_sweep(state.clone(), Duration::from_secs(config.expiry_sweep_interval_secs));

    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn spawn_expiry_sweep(mut state: AppState, interval: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval);
        loop {
            interval.tick().await;
            state.sweep_expired().await;
        }
    });
}

/// Builds the router with a fresh in-memory `AppState`. Exposed for integration tests.
pub async fn app(config: &Config) -> anyhow::Result<axum::Router> {
    Ok(router(AppState::new(config).await?))
}
