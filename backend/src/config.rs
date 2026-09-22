use figment::Figment;
use figment::providers::{Env, Format, Serialized, Yaml};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub redirect_uri_allowlist: Vec<String>,
    pub pkce_code_ttl_secs: i64,
    /// How long a `/oauth/login` session token stays valid for the follow-up
    /// `/oauth/authorize` call -- just a server-to-server hop, so this is
    /// deliberately short-lived.
    pub login_session_ttl_secs: i64,
    /// How long an access token issued by `/oauth/token` stays valid for.
    pub access_token_ttl_secs: i64,
    /// How long a refresh token stays redeemable before it must be re-issued
    /// via a fresh login.
    pub refresh_token_ttl_secs: i64,
    /// How long a state entry for an in-flight `/oauth/oidc/{provider}/login`
    /// redirect stays valid while the user is off at the provider's consent
    /// screen.
    pub oidc_state_ttl_secs: i64,
    /// How long a pending OIDC-to-password-account link (see
    /// `/oauth/oidc/confirm-link`) stays valid while waiting for the caller
    /// to supply the existing account's password. Deliberately roomier than
    /// `oidc_state_ttl_secs` -- this one waits on a human reading a prompt
    /// and typing a password, not just a redirect round-trip.
    pub pending_oidc_link_ttl_secs: i64,
    /// How long a `/oauth/password-reset/request` token stays redeemable via
    /// `/oauth/password-reset/confirm`. Deliberately roomier than
    /// `oidc_state_ttl_secs` -- this one waits on a human reading an email
    /// and clicking a link, not just a redirect round-trip.
    pub password_reset_token_ttl_secs: i64,
    /// How often the background task sweeps expired entries out of the
    /// TTL'd stores (PKCE challenges, OIDC state, login sessions, ...).
    /// Bounds how long an abandoned flow's leftovers linger.
    pub expiry_sweep_interval_secs: u64,
    /// Third-party OIDC login providers, keyed by a short name used in the
    /// route path (e.g. "google" for `/oauth/oidc/google/login`). Empty by
    /// default -- third-party login is a no-op unless a provider is
    /// configured here.
    ///
    /// `skip_serializing` because `OidcProviderConfig` doesn't derive
    /// `Serialize` (it holds a `SecretString`, and serializing it would
    /// expose the client secret) -- `default` fills it back in from
    /// `Config::default()` on the deserialize side, since `Config::load`'s
    /// defaults layer never sees it.
    #[serde(default, skip_serializing)]
    pub oidc_providers: HashMap<String, OidcProviderConfig>,
    /// Highest bcrypt cost factor accepted when verifying an imported
    /// legacy-user hash (see `crypto::verify_password`) -- caps how long a
    /// single login can tie up a blocking-pool thread.
    pub max_bcrypt_cost: u32,
    /// How extra fields on a register request (anything beyond
    /// `email`/`password`) are handled. `None` means extra fields aren't
    /// supported -- a register request carrying any is rejected.
    #[serde(default)]
    pub extra_data_handler: Option<ExtraDataHandlerConfig>,
}

/// Where extra registration fields are forwarded. An error from either kind
/// fails the whole registration; nothing is ever persisted by WeaveAuth
/// itself -- see `extra_data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExtraDataHandlerConfig {
    /// POSTs the extra fields as JSON to this URL. Must be `https://` unless
    /// the host is loopback (`localhost`/127.0.0.1/::1) -- registration
    /// fields include the user's email and whatever the deployer's form
    /// collects, so a plaintext `http://` hop to a non-local host would ship
    /// that over the wire in the clear.
    Webhook {
        url: String,
        /// How long to wait for the webhook before failing the
        /// registration -- a hung endpoint must not hold the request open
        /// indefinitely.
        #[serde(default = "default_webhook_timeout_secs")]
        timeout_secs: u64,
    },
    /// Runs the executable at `command` as a child process and calls it
    /// over gRPC (see `plugin`).
    Process {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        /// The plugin's entire environment -- it inherits nothing from
        /// WeaveAuth, so a database URL or an API token the plugin needs
        /// goes here.
        #[serde(default)]
        env: HashMap<String, String>,
        /// How long a single call to the plugin may take before the
        /// registration fails.
        #[serde(default = "default_plugin_timeout_secs")]
        timeout_secs: u64,
        /// How long the plugin has to start listening at startup. A plugin
        /// that misses it stops the server from booting, rather than
        /// surfacing as failed registrations later.
        #[serde(default = "default_plugin_startup_timeout_secs")]
        startup_timeout_secs: u64,
    },
}

fn default_webhook_timeout_secs() -> u64 {
    10
}

fn default_plugin_timeout_secs() -> u64 {
    5
}

fn default_plugin_startup_timeout_secs() -> u64 {
    10
}

/// Config for a single third-party OIDC login provider. Discovered at
/// startup via `{issuer}/.well-known/openid-configuration`, so only the
/// issuer and this app's own client registration need to be given here.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfig {
    pub client_id: String,
    pub client_secret: SecretString,
    pub issuer: String,
    /// This provider's callback redirect URL, as registered with it --
    /// backend isn't meant to be internet-exposed, so this must be bff's
    /// public URL (e.g. "https://bff.example.com/oidc/google/callback"),
    /// not backend's own address. bff forwards the provider's callback
    /// request to backend's matching route server-to-server.
    pub redirect_uri: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 1983,
            redirect_uri_allowlist: vec!["http://localhost:8081/".to_string()],
            pkce_code_ttl_secs: 300,
            login_session_ttl_secs: 60,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 2_592_000,
            oidc_state_ttl_secs: 300,
            pending_oidc_link_ttl_secs: 600,
            password_reset_token_ttl_secs: 1_800,
            expiry_sweep_interval_secs: 60,
            oidc_providers: HashMap::new(),
            max_bcrypt_cost: bcrypt::DEFAULT_COST,
            extra_data_handler: None,
        }
    }
}

impl Config {
    /// Loads config, layering (highest precedence last): built-in defaults,
    /// then the YAML file at `WA_CONFIG_FILE` (default `config.yaml`, missing
    /// file is not an error), then `WA_*` env vars.
    pub fn load() -> Result<Self, anyhow::Error> {
        dotenvy::dotenv().ok();

        let path = env::var("WA_CONFIG_FILE").unwrap_or_else(|_| "config.yaml".into());

        // `WA_LOGIN_PUBLIC_URL` is login's own public origin (see
        // `login::Config::own_origin`) -- when the two run side by side, it's
        // also the redirect_uri login sends by default (with a trailing `/`,
        // matching login's own fallback), so seed the built-in default from
        // it before the YAML file/`WA_REDIRECT_URI_ALLOWLIST` env var (below)
        // get a chance to override it. The allowlist check is an exact
        // string match, so the trailing slash isn't optional here.
        let mut defaults = Config::default();
        if let Ok(login_url) = env::var("WA_LOGIN_PUBLIC_URL") {
            defaults.redirect_uri_allowlist = vec![format!("{login_url}/")];
        }

        let mut config: Config = Figment::from(Serialized::defaults(defaults))
            .merge(Yaml::file(&path))
            // `WA_PLUGIN_*` belongs to the plugin process, not to this
            // config -- see `plugin::forwarded_env`. Filtered rather than
            // merely unmatched, so adding a `plugin` field here later can't
            // silently start capturing a deployer's plugin variables.
            .merge(
                Env::prefixed("WA_")
                    .ignore(&["config_file", "redirect_uri_allowlist"])
                    .filter(|key| !key.starts_with("plugin_")),
            )
            .extract()?;

        if let Ok(raw) = env::var("WA_REDIRECT_URI_ALLOWLIST") {
            config.redirect_uri_allowlist = raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        for (name, provider) in config.oidc_providers.iter_mut() {
            let key = name.to_uppercase();
            if let Ok(client_id) = env::var(format!("WA_OIDC_{key}_CLIENT_ID")) {
                provider.client_id = client_id;
            }
            if let Ok(client_secret) = env::var(format!("WA_OIDC_{key}_CLIENT_SECRET")) {
                provider.client_secret = client_secret.into();
            }
        }

        // bcrypt's own hard cap on the cost factor -- not exported by the
        // `bcrypt` crate, so mirrored here. Anything above it would make the
        // configured cap inert (bcrypt would refuse to hash at that cost anyway).
        const BCRYPT_MAX_COST: u32 = 31;
        if config.max_bcrypt_cost > BCRYPT_MAX_COST {
            tracing::warn!(
                configured = config.max_bcrypt_cost,
                clamped_to = BCRYPT_MAX_COST,
                "WA_MAX_BCRYPT_COST exceeds bcrypt's own maximum cost; clamping"
            );
            config.max_bcrypt_cost = BCRYPT_MAX_COST;
        }

        Ok(config)
    }
}

#[cfg(test)]
// figment::Jail::expect_with's closure signature is fixed by the crate; its
// Result<(), figment::Error> can't be shrunk from call sites.
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use figment::Jail;
    use secrecy::ExposeSecret;

    #[test]
    fn defaults_when_no_env_and_no_file() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 1983);
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://localhost:8081/".to_string()]
            );
            assert_eq!(config.pkce_code_ttl_secs, 300);
            assert_eq!(config.login_session_ttl_secs, 60);
            assert_eq!(config.access_token_ttl_secs, 900);
            assert_eq!(config.refresh_token_ttl_secs, 2_592_000);
            assert_eq!(config.max_bcrypt_cost, bcrypt::DEFAULT_COST);
            Ok(())
        });
    }

    #[test]
    fn max_bcrypt_cost_is_overridable_from_env() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_MAX_BCRYPT_COST", "10");

            let config = Config::load().unwrap();
            assert_eq!(config.max_bcrypt_cost, 10);
            Ok(())
        });
    }

    #[test]
    fn max_bcrypt_cost_above_bcrypts_own_maximum_is_clamped() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_MAX_BCRYPT_COST", "99");

            let config = Config::load().unwrap();
            assert_eq!(config.max_bcrypt_cost, 31);
            Ok(())
        });
    }

    #[test]
    fn file_values_are_used_when_no_env_override() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "port: 9999\nredirect_uri_allowlist:\n  - http://file.test/callback\npkce_code_ttl_secs: 42\nlogin_session_ttl_secs: 30\naccess_token_ttl_secs: 120\nrefresh_token_ttl_secs: 86400\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 9999);
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://file.test/callback".to_string()]
            );
            assert_eq!(config.pkce_code_ttl_secs, 42);
            assert_eq!(config.login_session_ttl_secs, 30);
            assert_eq!(config.access_token_ttl_secs, 120);
            assert_eq!(config.refresh_token_ttl_secs, 86400);
            Ok(())
        });
    }

    #[test]
    fn env_vars_override_file_values() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "port: 9999\nredirect_uri_allowlist:\n  - http://file.test/callback\npkce_code_ttl_secs: 42\nlogin_session_ttl_secs: 30\naccess_token_ttl_secs: 120\nrefresh_token_ttl_secs: 86400\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PORT", "7000");
            jail.set_env("WA_REDIRECT_URI_ALLOWLIST", "http://env.test/callback");
            jail.set_env("WA_PKCE_CODE_TTL_SECS", "11");
            jail.set_env("WA_LOGIN_SESSION_TTL_SECS", "5");
            jail.set_env("WA_ACCESS_TOKEN_TTL_SECS", "3");
            jail.set_env("WA_REFRESH_TOKEN_TTL_SECS", "7");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 7000);
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://env.test/callback".to_string()]
            );
            assert_eq!(config.pkce_code_ttl_secs, 11);
            assert_eq!(config.login_session_ttl_secs, 5);
            assert_eq!(config.access_token_ttl_secs, 3);
            assert_eq!(config.refresh_token_ttl_secs, 7);
            Ok(())
        });
    }

    #[test]
    fn defaults_to_no_oidc_providers() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let config = Config::load().unwrap();
            assert!(config.oidc_providers.is_empty());
            Ok(())
        });
    }

    #[test]
    fn loads_an_oidc_provider_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "oidc_providers:\n  \
                 google:\n    \
                 client_id: my-client-id\n    \
                 client_secret: my-client-secret\n    \
                 issuer: https://accounts.google.com\n    \
                 redirect_uri: http://bff.test/oidc/google/callback\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            let google = config.oidc_providers.get("google").expect("google provider loaded");
            assert_eq!(google.client_id, "my-client-id");
            assert_eq!(google.client_secret.expose_secret(), "my-client-secret");
            assert_eq!(google.issuer, "https://accounts.google.com");
            assert_eq!(google.redirect_uri, "http://bff.test/oidc/google/callback");
            Ok(())
        });
    }

    #[test]
    fn oidc_provider_client_id_and_secret_are_overridable_from_env() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "oidc_providers:\n  \
                 google:\n    \
                 client_id: placeholder-id\n    \
                 client_secret: placeholder-secret\n    \
                 issuer: https://accounts.google.com\n    \
                 redirect_uri: http://bff.test/oidc/google/callback\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_OIDC_GOOGLE_CLIENT_ID", "env-client-id");
            jail.set_env("WA_OIDC_GOOGLE_CLIENT_SECRET", "env-client-secret");

            let config = Config::load().unwrap();
            let google = config.oidc_providers.get("google").expect("google provider loaded");
            assert_eq!(google.client_id, "env-client-id");
            assert_eq!(google.client_secret.expose_secret(), "env-client-secret");
            // Non-secret fields still come from the file, untouched.
            assert_eq!(google.issuer, "https://accounts.google.com");
            Ok(())
        });
    }

    #[test]
    fn defaults_to_no_extra_data_handler() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let config = Config::load().unwrap();
            assert!(config.extra_data_handler.is_none());
            Ok(())
        });
    }

    #[test]
    fn loads_a_webhook_extra_data_handler_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "extra_data_handler:\n  kind: webhook\n  url: https://internal.test/hook\n  timeout_secs: 3\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                ExtraDataHandlerConfig::Webhook { url, timeout_secs } => {
                    assert_eq!(url, "https://internal.test/hook");
                    assert_eq!(timeout_secs, 3);
                }
                other => unreachable!("only a webhook handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn webhook_timeout_secs_defaults_when_omitted() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "extra_data_handler:\n  kind: webhook\n  url: https://internal.test/hook\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                ExtraDataHandlerConfig::Webhook { timeout_secs, .. } => assert_eq!(timeout_secs, 10),
                other => unreachable!("only a webhook handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn loads_a_process_extra_data_handler_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "extra_data_handler:\n  kind: process\n  command: /opt/plugins/register\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                ExtraDataHandlerConfig::Process { command, args, env, timeout_secs, startup_timeout_secs } => {
                    assert_eq!(command, "/opt/plugins/register");
                    assert_eq!(timeout_secs, 5);
                    assert_eq!(startup_timeout_secs, 10);
                    assert!(args.is_empty());
                    assert!(env.is_empty(), "a plugin is given no environment unless the deployer sets one");
                }
                other => unreachable!("only a process handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn loads_the_plugin_command_line_and_environment_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "extra_data_handler:\n  kind: process\n  command: /opt/plugins/register\n  args:\n    - --verbose\n  env:\n    DATABASE_URL: postgres://plugin@db/appdata\n  timeout_secs: 20\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                ExtraDataHandlerConfig::Process { args, env, timeout_secs, .. } => {
                    assert_eq!(args, vec!["--verbose".to_string()]);
                    assert_eq!(env.get("DATABASE_URL").map(String::as_str), Some("postgres://plugin@db/appdata"));
                    assert_eq!(timeout_secs, 20);
                }
                other => unreachable!("only a process handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn redirect_uri_allowlist_env_splits_trims_and_drops_empties() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env(
                "WA_REDIRECT_URI_ALLOWLIST",
                "http://a.test , http://b.test,,",
            );

            let config = Config::load().unwrap();
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://a.test".to_string(), "http://b.test".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn redirect_uri_allowlist_defaults_to_login_public_url_with_trailing_slash() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");

            let config = Config::load().unwrap();
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["https://login.env.test/".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn explicit_redirect_uri_allowlist_still_wins_over_login_public_url() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");
            jail.set_env("WA_REDIRECT_URI_ALLOWLIST", "https://other.test/callback");

            let config = Config::load().unwrap();
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["https://other.test/callback".to_string()]
            );
            Ok(())
        });
    }
}
