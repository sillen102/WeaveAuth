use crate::config::{Config, ExtraDataHandlerConfig, LoginClaimsHandlerConfig, OidcProviderConfig, ProfileApiConfig};
use crate::oidc::{self, OidcClient};
use crate::plugin::{PluginConfig, PluginProcess, forwarded_env};
use crate::server::api::register::{
    self, ExtraDataHandler, PLUGIN_NAME as EXTRA_DATA_PLUGIN_NAME,
};
use crate::server::api::token::{
    self, LoginClaimsHandler, PLUGIN_NAME as LOGIN_CLAIMS_PLUGIN_NAME,
};
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
    /// Per provider: `field name -> id_token claim name` (see `OidcProviderConfig::extra_claims`).
    pub(crate) oidc_extra_claims: Arc<HashMap<String, HashMap<String, String>>>,
    /// Per provider: scopes requested on the consent screen, besides `openid`.
    pub(crate) oidc_scopes: Arc<HashMap<String, Vec<String>>>,
    /// Per provider: calls made with the access token on a first login.
    pub(crate) oidc_profile_apis: Arc<HashMap<String, Vec<ProfileApiConfig>>>,
    pub(crate) oidc_state: InMemoryOidcStateStorage,
    pub(crate) pending_oidc_links: InMemoryPendingOidcLinkStorage,
    pub(crate) oidc_http_client: Arc<openidconnect::reqwest::Client>,
    pub(crate) password_reset_tokens: InMemoryPasswordResetTokenStorage,
    pub(crate) max_bcrypt_cost: u32,
    pub(crate) extra_data_handler: Option<Arc<dyn ExtraDataHandler>>,
    pub(crate) login_claims_handler: Option<Arc<dyn LoginClaimsHandler>>,
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
        // Fail at boot rather than silently dropping the claims on every login.
        let maps_extra_claims =
            |p: &OidcProviderConfig| !p.extra_claims.is_empty() || p.profile_apis.iter().any(|api| !api.claims.is_empty());
        if let Some((name, _)) = config.oidc_providers.iter().find(|(_, p)| maps_extra_claims(p)) {
            if config.extra_data_handler.is_none() {
                anyhow::bail!("oidc provider '{name}' maps extra claims but no extra_data_handler is configured");
            }
            if config.login_claims_handler.is_none() {
                anyhow::bail!("oidc provider '{name}' maps extra claims but no login_claims_handler is configured");
            }
        }
        for api in config.oidc_providers.values().flat_map(|p| &p.profile_apis) {
            crate::config::require_https_or_loopback("profile api url", &api.url)?;
        }

        // No redirects: an OIDC provider redirecting this server-side request
        // elsewhere would be a request-forgery vector, not a legitimate flow.
        let oidc_http_client = Arc::new(
            openidconnect::reqwest::ClientBuilder::new()
                .redirect(openidconnect::reqwest::redirect::Policy::none())
                .build()?,
        );
        let oidc_providers = oidc::build_providers(&config.oidc_providers, &oidc_http_client).await?;
        let extra_data_handler = build_extra_data_handler(config.extra_data_handler.as_ref()).await?;
        let login_claims_handler = build_login_claims_handler(config.login_claims_handler.as_ref()).await?;

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
            oidc_profile_apis: Arc::new(
                config.oidc_providers.iter().map(|(name, p)| (name.clone(), p.profile_apis.clone())).collect(),
            ),
            oidc_scopes: Arc::new(config.oidc_providers.iter().map(|(name, p)| (name.clone(), p.scopes.clone())).collect()),
            oidc_extra_claims: Arc::new(
                config.oidc_providers.iter().map(|(name, p)| (name.clone(), p.extra_claims.clone())).collect(),
            ),
            oidc_state: InMemoryOidcStateStorage::new(config.oidc_state_ttl_secs),
            pending_oidc_links: InMemoryPendingOidcLinkStorage::new(config.pending_oidc_link_ttl_secs),
            oidc_http_client,
            password_reset_tokens: InMemoryPasswordResetTokenStorage::new(config.password_reset_token_ttl_secs),
            max_bcrypt_cost: config.max_bcrypt_cost,
            extra_data_handler,
            login_claims_handler,
        })
    }
}

async fn build_extra_data_handler(
    config: Option<&ExtraDataHandlerConfig>,
) -> anyhow::Result<Option<Arc<dyn ExtraDataHandler>>> {
    let handler: Arc<dyn ExtraDataHandler> = match config {
        None => return Ok(None),
        Some(ExtraDataHandlerConfig::Webhook { url, timeout_secs }) => {
            Arc::new(register::WebhookHandler::new(url.clone(), Duration::from_secs(*timeout_secs))?)
        }
        Some(ExtraDataHandlerConfig::Process { command, args, env, timeout_secs, startup_timeout_secs, uid, gid }) => {
            // Ambient `WA_PLUGIN_REGISTRATION_ENV_*` first, then the config
            // file, so a deployer can override an inherited value without
            // unsetting it.
            let mut plugin_env: HashMap<_, _> = forwarded_env(std::env::vars_os(), EXTRA_DATA_PLUGIN_NAME)
                .into_iter()
                .map(|(key, value)| (key, value.to_string_lossy().into_owned()))
                .collect();
            plugin_env.extend(env.clone());

            let plugin = PluginProcess::start(PluginConfig {
                command: command.clone(),
                args: args.clone(),
                env: plugin_env,
                timeout: Duration::from_secs(*timeout_secs),
                startup_timeout: Duration::from_secs(*startup_timeout_secs),
                uid: *uid,
                gid: *gid,
            })
            .await?;
            Arc::new(register::ProcessHandler::new(plugin))
        }
    };
    Ok(Some(handler))
}

async fn build_login_claims_handler(
    config: Option<&LoginClaimsHandlerConfig>,
) -> anyhow::Result<Option<Arc<dyn LoginClaimsHandler>>> {
    let handler: Arc<dyn LoginClaimsHandler> = match config {
        None => return Ok(None),
        Some(LoginClaimsHandlerConfig::Webhook { url, timeout_secs }) => {
            Arc::new(token::WebhookHandler::new(url.clone(), Duration::from_secs(*timeout_secs))?)
        }
        Some(LoginClaimsHandlerConfig::Process { command, args, env, timeout_secs, startup_timeout_secs, uid, gid }) => {
            // Ambient `WA_PLUGIN_LOGIN_CLAIMS_ENV_*` first, then the config
            // file, so a deployer can override an inherited value without
            // unsetting it.
            let mut plugin_env: HashMap<_, _> = forwarded_env(std::env::vars_os(), LOGIN_CLAIMS_PLUGIN_NAME)
                .into_iter()
                .map(|(key, value)| (key, value.to_string_lossy().into_owned()))
                .collect();
            plugin_env.extend(env.clone());

            let plugin = PluginProcess::start(PluginConfig {
                command: command.clone(),
                args: args.clone(),
                env: plugin_env,
                timeout: Duration::from_secs(*timeout_secs),
                startup_timeout: Duration::from_secs(*startup_timeout_secs),
                uid: *uid,
                gid: *gid,
            })
            .await?;
            Arc::new(token::ProcessHandler::new(plugin))
        }
    };
    Ok(Some(handler))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn webhook_pair() -> (ExtraDataHandlerConfig, LoginClaimsHandlerConfig) {
        (
            ExtraDataHandlerConfig::Webhook { url: "http://localhost:1/hook".to_string(), timeout_secs: 1 },
            LoginClaimsHandlerConfig::Webhook { url: "http://localhost:1/claims".to_string(), timeout_secs: 1 },
        )
    }

    fn config_with_extra_claims(
        handler: Option<ExtraDataHandlerConfig>,
        login_claims: Option<LoginClaimsHandlerConfig>,
    ) -> Config {
        let provider = OidcProviderConfig {
            client_id: "id".to_string(),
            client_secret: "secret".to_string().into(),
            // Unreachable: the check under test must fire before discovery.
            issuer: "http://127.0.0.1:1".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
            extra_claims: [("last_name".to_string(), "family_name".to_string())].into(),
            scopes: vec!["email".to_string()],
                profile_apis: Vec::new(),
        };
        Config {
            oidc_providers: [("google".to_string(), provider)].into(),
            extra_data_handler: handler,
            login_claims_handler: login_claims,
            ..Config::default()
        }
    }

    fn config_with_profile_api(url: &str, handlers: bool) -> Config {
        let mut config = config_with_extra_claims(None, None);
        let provider = config.oidc_providers.get_mut("google").expect("provider");
        provider.extra_claims.clear();
        provider.profile_apis = vec![ProfileApiConfig {
            url: url.to_string(),
            claims: [("phone_number".to_string(), "/phone".to_string())].into(),
            required: false,
            scope: None,
        }];
        if handlers {
            let (extra, login) = webhook_pair();
            config.extra_data_handler = Some(extra);
            config.login_claims_handler = Some(login);
        }
        config
    }

    #[tokio::test]
    async fn refuses_to_start_with_profile_apis_but_no_handlers() {
        let config = config_with_profile_api("https://people.test/me", false);

        let error = AppState::new(&config).await.err().expect("startup fails");

        assert!(error.to_string().contains("extra_data_handler"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn refuses_a_plaintext_profile_api_url_to_a_non_local_host() {
        let config = config_with_profile_api("http://people.test/me", true);

        let error = AppState::new(&config).await.err().expect("startup fails");

        assert!(error.to_string().contains("profile api url"), "unexpected error: {error}");
    }

    // Positive control: https passes the url check, so startup only fails
    // later at the (unreachable) provider's discovery.
    #[tokio::test]
    async fn accepts_an_https_profile_api_url() {
        let config = config_with_profile_api("https://people.test/me", true);

        let error = AppState::new(&config).await.err().expect("discovery fails");

        assert!(!error.to_string().contains("profile api url"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn refuses_to_start_with_extra_claims_but_no_extra_data_handler() {
        let error = AppState::new(&config_with_extra_claims(None, Some(webhook_pair().1))).await.err().expect("startup fails");

        assert!(error.to_string().contains("extra_data_handler"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn refuses_to_start_with_extra_claims_but_no_login_claims_handler() {
        let error = AppState::new(&config_with_extra_claims(Some(webhook_pair().0), None)).await.err().expect("startup fails");

        assert!(error.to_string().contains("login_claims_handler"), "unexpected error: {error}");
    }

    // Positive control: with both handlers the check passes and startup only
    // fails later, at the (unreachable) provider's discovery.
    #[tokio::test]
    async fn extra_claims_check_passes_when_both_handlers_are_configured() {
        let (extra, login) = webhook_pair();
        let error = AppState::new(&config_with_extra_claims(Some(extra), Some(login))).await.err().expect("discovery fails");

        assert!(!error.to_string().contains("extra_claims"), "unexpected error: {error}");
    }
}
