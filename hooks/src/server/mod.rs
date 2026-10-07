use crate::clients::bff::BffInternal;
use crate::clients::http_client;
use crate::clients::hydra::HydraAdmin;
use crate::clients::kratos::KratosAdmin;
use crate::config::{Config, ProfileApiConfig};
use crate::webhook::WebhookHandler;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

mod api;
mod auth;
mod router;

#[derive(Clone)]
pub(crate) struct AppState {
    /// SHA-256 of the hooks API key, so the check never holds or compares the key itself.
    pub(crate) api_key_digest: Arc<[u8; 32]>,
    pub(crate) kratos: KratosAdmin,
    pub(crate) hydra: HydraAdmin,
    pub(crate) bff: BffInternal,
    /// For the provider profile APIs.
    pub(crate) http_client: reqwest::Client,
    pub(crate) registration: Option<WebhookHandler>,
    pub(crate) login_claims: Option<WebhookHandler>,
    pub(crate) profile_apis: Arc<HashMap<String, Vec<ProfileApiConfig>>>,
    pub(crate) request_timeout: Duration,
    pub(crate) require_verified_email: bool,
}

impl AppState {
    pub(crate) fn new(config: &Config) -> anyhow::Result<Self> {
        use secrecy::ExposeSecret;
        // An empty key would make `Bearer ` a valid credential.
        config.require_api_keys()?;
        let upstream = http_client(Duration::from_secs(config.upstream_timeout_secs))?;
        let webhook = |handler: &Option<_>| handler.as_ref().map(WebhookHandler::new).transpose();
        Ok(Self {
            api_key_digest: Arc::new(Sha256::digest(config.hooks_api_key.expose_secret()).into()),
            kratos: KratosAdmin::new(upstream.clone(), config.kratos_admin_url.clone()),
            hydra: HydraAdmin::new(upstream.clone(), config.hydra_admin_url.clone()),
            bff: BffInternal::new(
                upstream.clone(),
                config.bff_internal_url.clone(),
                config.bff_internal_api_key.clone(),
            ),
            http_client: upstream,
            registration: webhook(&config.registration_handler)?,
            login_claims: webhook(&config.login_claims_handler)?,
            profile_apis: Arc::new(config.profile_apis.clone()),
            request_timeout: Duration::from_secs(config.request_timeout_secs),
            require_verified_email: config.require_verified_email,
        })
    }
}

/// Serves until the process ends. Hooks is internal: bind it to a network
/// only Kratos, Hydra and the deployer's services can reach.
pub async fn app_start(config: &Config) -> anyhow::Result<()> {
    let app = app(config)?;
    tracing::info!(
        registration = config.registration_handler.is_some(),
        login_claims = config.login_claims_handler.is_some(),
        profile_api_providers = ?config.profile_apis.keys().collect::<Vec<_>>(),
        "configured handlers"
    );
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// The router with its upstream clients built from `config`. Exposed for integration tests.
pub fn app(config: &Config) -> anyhow::Result<axum::Router> {
    Ok(router::router(AppState::new(config)?))
}
