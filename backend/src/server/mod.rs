use crate::config::{
    Config, EmailHandlerConfig, HandlerConfig, JWT_KEY_PUBLISH_AHEAD_SECS, OidcProviderConfig,
    PluginHook, PluginSettings, ProfileApiConfig, WebhookConfig, jwt_key_grace_secs,
};
use crate::email::EmailHandler;
use crate::oidc::{self, OidcClient};
use crate::plugin::{PluginConfig, PluginProcess, forwarded_env};
use crate::server::api::email_verification::EmailVerification;
use crate::server::api::register::{self, ExtraDataHandler};
use crate::server::api::token::{self, LoginClaimsHandler};
use crate::server::router::router;
use crate::storage::in_memory::{
    InMemoryEmailVerificationCodeStorage, InMemoryJwkStorage, InMemoryLoginSessionStorage,
    InMemoryOidcStateStorage, InMemoryPasswordResetTokenStorage, InMemoryPendingOidcLinkStorage,
    InMemoryPkceStorage, InMemoryRefreshTokenStorage, InMemoryUserStorage,
    InMemoryVerificationSessionStorage,
};
use crate::storage::{ExpiryMaintenance, JwkStorage};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::PathBuf;
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
    pub(crate) jwt_key_rotation_interval_secs: i64,
    pub(crate) issuer: Arc<str>,
    pub(crate) oidc_providers: Arc<HashMap<String, OidcClient>>,
    /// Per provider: `field name -> id_token claim name` (see `OidcProviderConfig::extra_claims`).
    pub(crate) oidc_extra_claims: Arc<HashMap<String, HashMap<String, String>>>,
    /// Per provider: scopes requested on the consent screen, besides `openid`.
    pub(crate) oidc_scopes: Arc<HashMap<String, Vec<String>>>,
    /// Per provider: how login pages name it, ordered by key.
    pub(crate) oidc_display_names: Arc<std::collections::BTreeMap<String, String>>,
    /// Per provider: calls made with the access token on a first login.
    pub(crate) oidc_profile_apis: Arc<HashMap<String, Vec<ProfileApiConfig>>>,
    pub(crate) oidc_state: InMemoryOidcStateStorage,
    pub(crate) pending_oidc_links: InMemoryPendingOidcLinkStorage,
    pub(crate) oidc_http_client: Arc<openidconnect::reqwest::Client>,
    pub(crate) password_reset_tokens: InMemoryPasswordResetTokenStorage,
    pub(crate) max_bcrypt_cost: u32,
    pub(crate) extra_data_handler: Option<Arc<dyn ExtraDataHandler>>,
    pub(crate) login_claims_handler: Option<Arc<dyn LoginClaimsHandler>>,
    /// Sends every email (verification codes, reset links). `None`: none is sent.
    pub(crate) email_handler: Option<Arc<dyn EmailHandler>>,
    /// Login's public origin, without a trailing `/` (see `Config::load`); emails link to its pages.
    pub(crate) login_public_url: String,
    pub(crate) email_verification: EmailVerification,
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
        self.email_verification.codes.sweep_expired().await;
        self.email_verification.sessions.sweep_expired().await;
        self.rotate_keys_if_due(Utc::now()).await;
    }

    /// Keeps the signing key rotating, one step per call as each falls due.
    ///
    /// Stage: [`JWT_KEY_PUBLISH_AHEAD_SECS`] before the active key is
    /// `jwt_key_rotation_interval_secs` old, the next key is published
    /// without signing.
    ///
    /// Promote: once the active key is that old and the staged key has been
    /// published for that long, the staged key takes over.
    ///
    /// Prune: a replaced key stays published for [`jwt_key_grace_secs`]
    /// after that, by which time every access token it signed has expired.
    pub(crate) async fn rotate_keys_if_due(&self, now: DateTime<Utc>) {
        self.jwt_keys
            .prune_retired(
                now,
                chrono::Duration::seconds(jwt_key_grace_secs(self.access_token_ttl_secs)),
            )
            .await;
        let ahead = chrono::Duration::seconds(JWT_KEY_PUBLISH_AHEAD_SECS);
        let interval = chrono::Duration::seconds(self.jwt_key_rotation_interval_secs);
        let active_for = now - self.jwt_keys.active_since().await;

        let staged_at = match self.jwt_keys.next_since().await {
            Some(at) => at,
            None if active_for >= interval - ahead => {
                if let Err(error) = self.jwt_keys.stage_next(now).await {
                    tracing::error!(%error, "staging the next JWT signing key failed; retrying on the next sweep");
                    return;
                }
                now
            }
            None => return,
        };
        if active_for >= interval
            && now - staged_at >= ahead
            && let Err(error) = self.jwt_keys.promote_next(now).await
        {
            tracing::error!(%error, "JWT signing key rotation failed; keeping the current key");
        }
    }

    /// A fully wired state with default config and no handlers.
    #[cfg(test)]
    pub(crate) async fn for_test() -> Self {
        Self::new(&Config::default())
            .await
            .expect("default config boots")
    }

    pub(crate) async fn new(config: &Config) -> anyhow::Result<Self> {
        // Earlier reset tokens stay valid, so the cooldown is the only bound on
        // how many one user holds.
        anyhow::ensure!(
            config.tuning.password_reset_resend_cooldown_secs > 0,
            "password_reset_resend_cooldown_secs must be positive"
        );
        // Fail at boot rather than silently dropping the claims on every login.
        let maps_extra_claims = |p: &OidcProviderConfig| {
            !p.extra_claims.is_empty() || p.profile_apis.iter().any(|api| !api.claims.is_empty())
        };
        if let Some((name, _)) = config
            .oidc_providers
            .iter()
            .find(|(_, p)| maps_extra_claims(p))
        {
            if config.extra_data_handler.is_none() {
                anyhow::bail!(
                    "oidc provider '{name}' maps extra claims but no extra_data_handler is configured"
                );
            }
            if config.login_claims_handler.is_none() {
                anyhow::bail!(
                    "oidc provider '{name}' maps extra claims but no login_claims_handler is configured"
                );
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
        let oidc_providers =
            oidc::build_providers(&config.oidc_providers, &config.bff_url, &oidc_http_client)
                .await?;
        let extra_data_handler = build_extra_data_handler(
            config.extra_data_handler.as_ref(),
            config.setuid_helper.as_deref(),
        )
        .await?;
        let login_claims_handler = build_login_claims_handler(
            config.login_claims_handler.as_ref(),
            config.setuid_helper.as_deref(),
        )
        .await?;
        let email_handler = build_email_handler(
            config.email_handler.as_ref(),
            config.setuid_helper.as_deref(),
        )
        .await?;

        Ok(Self {
            pkce: InMemoryPkceStorage::new(config.tuning.pkce_code_ttl_secs),
            users: InMemoryUserStorage::new(),
            login_sessions: InMemoryLoginSessionStorage::new(config.tuning.login_session_ttl_secs),
            redirect_uri_allowlist: Arc::new(config.redirect_uri_allowlist.clone()),
            jwt_keys: InMemoryJwkStorage::new()?,
            access_token_ttl_secs: config.access_token_ttl_secs,
            refresh_tokens: InMemoryRefreshTokenStorage::new(config.refresh_token_ttl_secs),
            refresh_token_ttl_secs: config.refresh_token_ttl_secs,
            jwt_key_rotation_interval_secs: config.rotation_interval_secs(),
            issuer: config.issuer.as_str().into(),
            oidc_providers: Arc::new(oidc_providers),
            oidc_profile_apis: Arc::new(
                config
                    .oidc_providers
                    .iter()
                    .map(|(name, p)| (name.clone(), p.profile_apis.clone()))
                    .collect(),
            ),
            oidc_scopes: Arc::new(
                config
                    .oidc_providers
                    .iter()
                    .map(|(name, p)| (name.clone(), p.scopes.clone()))
                    .collect(),
            ),
            oidc_display_names: Arc::new(
                config
                    .oidc_providers
                    .iter()
                    .map(|(name, p)| (name.clone(), p.display_name_for(name)))
                    .collect(),
            ),
            oidc_extra_claims: Arc::new(
                config
                    .oidc_providers
                    .iter()
                    .map(|(name, p)| (name.clone(), p.extra_claims.clone()))
                    .collect(),
            ),
            oidc_state: InMemoryOidcStateStorage::new(config.tuning.oidc_state_ttl_secs),
            pending_oidc_links: InMemoryPendingOidcLinkStorage::new(
                config.tuning.pending_oidc_link_ttl_secs,
            ),
            oidc_http_client,
            password_reset_tokens: InMemoryPasswordResetTokenStorage::new(
                config.tuning.password_reset_token_ttl_secs,
                config.tuning.password_reset_resend_cooldown_secs,
            ),
            max_bcrypt_cost: config.tuning.max_bcrypt_cost,
            extra_data_handler,
            login_claims_handler,
            email_handler,
            login_public_url: config.login_public_url.clone(),
            email_verification: EmailVerification {
                codes: InMemoryEmailVerificationCodeStorage::new(
                    config.tuning.email_verification_code_ttl_secs,
                    config.tuning.email_verification_resend_cooldown_secs,
                ),
                sessions: InMemoryVerificationSessionStorage::new(
                    config.tuning.email_verification_session_ttl_secs,
                ),
                code_ttl_secs: config.tuning.email_verification_code_ttl_secs,
                required: config.require_verified_email,
            },
        })
    }
}

async fn build_extra_data_handler(
    config: Option<&HandlerConfig>,
    setuid_helper: Option<&str>,
) -> anyhow::Result<Option<Arc<dyn ExtraDataHandler>>> {
    let handler: Arc<dyn ExtraDataHandler> = match config {
        None => return Ok(None),
        Some(HandlerConfig::Webhook(WebhookConfig { url, timeout_secs })) => Arc::new(
            register::WebhookHandler::new(url.clone(), Duration::from_secs(*timeout_secs))?,
        ),
        Some(HandlerConfig::Plugin(settings)) => {
            let plugin = start_plugin(settings, PluginHook::Registration, setuid_helper).await?;
            Arc::new(register::PluginHandler::new(plugin))
        }
    };
    Ok(Some(handler))
}

async fn build_login_claims_handler(
    config: Option<&HandlerConfig>,
    setuid_helper: Option<&str>,
) -> anyhow::Result<Option<Arc<dyn LoginClaimsHandler>>> {
    let handler: Arc<dyn LoginClaimsHandler> = match config {
        None => return Ok(None),
        Some(HandlerConfig::Webhook(WebhookConfig { url, timeout_secs })) => Arc::new(
            token::WebhookHandler::new(url.clone(), Duration::from_secs(*timeout_secs))?,
        ),
        Some(HandlerConfig::Plugin(settings)) => {
            let plugin = start_plugin(settings, PluginHook::LoginClaims, setuid_helper).await?;
            Arc::new(token::PluginHandler::new(plugin))
        }
    };
    Ok(Some(handler))
}

async fn build_email_handler(
    config: Option<&EmailHandlerConfig>,
    setuid_helper: Option<&str>,
) -> anyhow::Result<Option<Arc<dyn EmailHandler>>> {
    let handler: Arc<dyn EmailHandler> = match config {
        None => {
            tracing::warn!(
                "no email_handler configured: verification codes and password reset links are not sent"
            );
            return Ok(None);
        }
        Some(EmailHandlerConfig::Smtp {
            host,
            port,
            tls,
            username,
            password,
            from,
            timeout_secs,
        }) => Arc::new(crate::email::SmtpHandler::new(
            host,
            *port,
            *tls,
            smtp_credentials(username, password)?,
            from,
            Duration::from_secs(*timeout_secs),
            crate::email::TEMPLATES_GLOB,
        )?),
        Some(EmailHandlerConfig::Webhook(WebhookConfig { url, timeout_secs })) => Arc::new(
            crate::email::WebhookHandler::new(url.clone(), Duration::from_secs(*timeout_secs))?,
        ),
        Some(EmailHandlerConfig::Plugin(settings)) => {
            let plugin = start_plugin(settings, PluginHook::Email, setuid_helper).await?;
            Arc::new(crate::email::PluginHandler::new(plugin))
        }
    };
    Ok(Some(handler))
}

/// Starts the plugin for `hook`. The ambient `WA_PLUGIN_<NAME>_ENV_*`
/// variables go in first, then the config file's `env`, so a deployer can
/// override an inherited value without unsetting it.
async fn start_plugin(
    settings: &PluginSettings,
    hook: PluginHook,
    setuid_helper: Option<&str>,
) -> anyhow::Result<PluginProcess> {
    let mut env: HashMap<_, _> = forwarded_env(std::env::vars_os(), hook.name())
        .into_iter()
        .map(|(key, value)| (key, value.to_string_lossy().into_owned()))
        .collect();
    env.extend(settings.env.clone());

    PluginProcess::start(PluginConfig {
        command: settings.command.clone(),
        args: settings.args.clone(),
        env,
        timeout: Duration::from_secs(settings.timeout_secs),
        startup_timeout: Duration::from_secs(settings.startup_timeout_secs),
        uid: settings.uid.unwrap_or_else(|| hook.default_id()),
        gid: settings.gid.unwrap_or_else(|| hook.default_id()),
        setuid_helper: setuid_helper.map(PathBuf::from),
    })
    .await
}

fn smtp_credentials(
    username: &Option<String>,
    password: &Option<secrecy::SecretString>,
) -> anyhow::Result<Option<(String, secrecy::SecretString)>> {
    match (username, password) {
        (Some(username), Some(password)) => Ok(Some((username.clone(), password.clone()))),
        (None, None) => Ok(None),
        _ => anyhow::bail!("smtp email_handler needs both username and password, or neither"),
    }
}

pub async fn app_start(config: &Config) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");

    let state = AppState::new(config).await?;
    spawn_expiry_sweep(
        state.clone(),
        Duration::from_secs(common::config::EXPIRY_SWEEP_INTERVAL_SECS),
    );

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

    async fn published(state: &AppState) -> usize {
        state.jwt_keys.jwk_set().await["keys"]
            .as_array()
            .unwrap()
            .len()
    }

    fn secs(n: i64) -> chrono::Duration {
        chrono::Duration::seconds(n)
    }

    #[tokio::test]
    async fn next_key_is_staged_one_publish_ahead_before_the_interval_without_signing() {
        let state = AppState::for_test().await;
        let kid = state.jwt_keys.active_key().await.kid.clone();
        let since = state.jwt_keys.active_since().await;
        let stage_at =
            since + secs(state.jwt_key_rotation_interval_secs - JWT_KEY_PUBLISH_AHEAD_SECS);

        state.rotate_keys_if_due(stage_at - secs(1)).await;
        assert_eq!(published(&state).await, 1);

        state.rotate_keys_if_due(stage_at).await;
        assert_eq!(published(&state).await, 2);
        assert_eq!(state.jwt_keys.active_key().await.kid, kid);

        state
            .rotate_keys_if_due(since + secs(state.jwt_key_rotation_interval_secs - 1))
            .await;
        assert_eq!(state.jwt_keys.active_key().await.kid, kid);
    }

    #[tokio::test]
    async fn staged_key_takes_over_at_the_interval_and_the_old_one_drops_after_the_grace_period() {
        let state = AppState::for_test().await;
        let old_kid = state.jwt_keys.active_key().await.kid.clone();
        let since = state.jwt_keys.active_since().await;
        state
            .rotate_keys_if_due(
                since + secs(state.jwt_key_rotation_interval_secs - JWT_KEY_PUBLISH_AHEAD_SECS),
            )
            .await;
        let staged_kid = state.jwt_keys.jwk_set().await["keys"][1]["kid"]
            .as_str()
            .unwrap()
            .to_string();

        let rotate_at = since + secs(state.jwt_key_rotation_interval_secs);
        state.rotate_keys_if_due(rotate_at).await;
        assert_eq!(state.jwt_keys.active_key().await.kid, staged_kid);
        assert_eq!(published(&state).await, 2);

        let grace = jwt_key_grace_secs(state.access_token_ttl_secs);
        state.rotate_keys_if_due(rotate_at + secs(grace - 1)).await;
        assert_eq!(published(&state).await, 2);

        state.rotate_keys_if_due(rotate_at + secs(grace)).await;
        assert_eq!(published(&state).await, 1);
        assert_ne!(state.jwt_keys.active_key().await.kid, old_kid);
    }

    #[tokio::test]
    async fn a_key_staged_late_is_published_for_the_full_publish_ahead_before_it_signs() {
        let state = AppState::for_test().await;
        let kid = state.jwt_keys.active_key().await.kid.clone();
        let late =
            state.jwt_keys.active_since().await + secs(state.jwt_key_rotation_interval_secs + 10);

        state.rotate_keys_if_due(late).await;
        assert_eq!(published(&state).await, 2);
        assert_eq!(state.jwt_keys.active_key().await.kid, kid);

        state
            .rotate_keys_if_due(late + secs(JWT_KEY_PUBLISH_AHEAD_SECS - 1))
            .await;
        assert_eq!(state.jwt_keys.active_key().await.kid, kid);

        state
            .rotate_keys_if_due(late + secs(JWT_KEY_PUBLISH_AHEAD_SECS))
            .await;
        assert_ne!(state.jwt_keys.active_key().await.kid, kid);
    }

    fn webhook_pair() -> (HandlerConfig, HandlerConfig) {
        (
            HandlerConfig::Webhook(WebhookConfig {
                url: "http://localhost:1/hook".to_string(),
                timeout_secs: 1,
            }),
            HandlerConfig::Webhook(WebhookConfig {
                url: "http://localhost:1/claims".to_string(),
                timeout_secs: 1,
            }),
        )
    }

    fn config_with_extra_claims(
        handler: Option<HandlerConfig>,
        login_claims: Option<HandlerConfig>,
    ) -> Config {
        let provider = OidcProviderConfig {
            client_id: "id".to_string(),
            client_secret: "secret".to_string().into(),
            // Unreachable: the check under test must fire before discovery.
            issuer: "http://127.0.0.1:1".to_string(),
            redirect_uri: Some("http://localhost/callback".to_string()),
            display_name: None,
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
    async fn refuses_to_start_without_a_password_reset_cooldown() {
        let mut config = Config::default();
        config.tuning.password_reset_resend_cooldown_secs = 0;

        let error = AppState::new(&config).await.err().expect("must fail");

        assert!(
            error
                .to_string()
                .contains("password_reset_resend_cooldown_secs"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn starts_with_a_webhook_email_handler() {
        let config = Config {
            email_handler: Some(EmailHandlerConfig::Webhook(WebhookConfig {
                url: "http://localhost:1/email".to_string(),
                timeout_secs: 1,
            })),
            ..Config::default()
        };

        let state = AppState::new(&config).await.expect("startup succeeds");

        assert!(state.email_handler.is_some());
    }

    #[tokio::test]
    async fn starts_with_an_smtp_email_handler_using_the_bundled_templates() {
        let config = Config {
            email_handler: Some(EmailHandlerConfig::Smtp {
                host: "127.0.0.1".to_string(),
                port: 1025,
                tls: crate::config::SmtpTls::None,
                username: Some("u".to_string()),
                password: Some("p".to_string().into()),
                from: "no-reply@example.com".to_string(),
                timeout_secs: 1,
            }),
            ..Config::default()
        };

        let state = AppState::new(&config).await.expect("startup succeeds");

        assert!(state.email_handler.is_some());
    }

    #[tokio::test]
    async fn refuses_a_missing_email_plugin_command_at_startup() {
        let config = Config {
            email_handler: Some(EmailHandlerConfig::Plugin(PluginSettings {
                command: "/nonexistent/mailer".to_string(),
                args: vec![],
                env: HashMap::new(),
                timeout_secs: 1,
                startup_timeout_secs: 1,
                uid: Some(1003),
                gid: Some(1003),
            })),
            ..Config::default()
        };

        assert!(AppState::new(&config).await.is_err());
    }

    #[tokio::test]
    async fn refuses_smtp_credentials_with_only_a_username() {
        let config = Config {
            email_handler: Some(EmailHandlerConfig::Smtp {
                host: "127.0.0.1".to_string(),
                port: 1025,
                tls: crate::config::SmtpTls::None,
                username: Some("u".to_string()),
                password: None,
                from: "no-reply@example.com".to_string(),
                timeout_secs: 1,
            }),
            ..Config::default()
        };

        let error = AppState::new(&config).await.err().expect("startup fails");

        assert!(
            error.to_string().contains("username and password"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn refuses_to_start_with_profile_apis_but_no_handlers() {
        let config = config_with_profile_api("https://people.test/me", false);

        let error = AppState::new(&config).await.err().expect("startup fails");

        assert!(
            error.to_string().contains("extra_data_handler"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn refuses_a_plaintext_profile_api_url_to_a_non_local_host() {
        let config = config_with_profile_api("http://people.test/me", true);

        let error = AppState::new(&config).await.err().expect("startup fails");

        assert!(
            error.to_string().contains("profile api url"),
            "unexpected error: {error}"
        );
    }

    // Positive control: https passes the url check, so startup only fails
    // later at the (unreachable) provider's discovery.
    #[tokio::test]
    async fn accepts_an_https_profile_api_url() {
        let config = config_with_profile_api("https://people.test/me", true);

        let error = AppState::new(&config).await.err().expect("discovery fails");

        assert!(
            !error.to_string().contains("profile api url"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn refuses_to_start_with_extra_claims_but_no_extra_data_handler() {
        let error = AppState::new(&config_with_extra_claims(None, Some(webhook_pair().1)))
            .await
            .err()
            .expect("startup fails");

        assert!(
            error.to_string().contains("extra_data_handler"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn refuses_to_start_with_extra_claims_but_no_login_claims_handler() {
        let error = AppState::new(&config_with_extra_claims(Some(webhook_pair().0), None))
            .await
            .err()
            .expect("startup fails");

        assert!(
            error.to_string().contains("login_claims_handler"),
            "unexpected error: {error}"
        );
    }

    // Positive control: with both handlers the check passes and startup only
    // fails later, at the (unreachable) provider's discovery.
    #[tokio::test]
    async fn extra_claims_check_passes_when_both_handlers_are_configured() {
        let (extra, login) = webhook_pair();
        let error = AppState::new(&config_with_extra_claims(Some(extra), Some(login)))
            .await
            .err()
            .expect("discovery fails");

        assert!(
            !error.to_string().contains("extra_claims"),
            "unexpected error: {error}"
        );
    }
}
