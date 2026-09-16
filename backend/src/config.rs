use figment::Figment;
use figment::providers::{Env, Format, Serialized, Yaml};
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
    /// to supply the existing account's password. Longer than
    /// `oidc_state_ttl_secs` -- this one waits on a human reading a prompt
    /// and typing a password, not just a redirect round-trip.
    pub pending_oidc_link_ttl_secs: i64,
    /// How often the background task sweeps expired entries out of the
    /// TTL'd stores (PKCE challenges, OIDC state, login sessions, ...).
    /// Bounds how long an abandoned flow's leftovers linger.
    pub expiry_sweep_interval_secs: u64,
    /// Third-party OIDC login providers, keyed by a short name used in the
    /// route path (e.g. "google" for `/oauth/oidc/google/login`). Empty by
    /// default -- third-party login is a no-op unless a provider is
    /// configured here.
    pub oidc_providers: HashMap<String, OidcProviderConfig>,
}

/// Config for a single third-party OIDC login provider. Discovered at
/// startup via `{issuer}/.well-known/openid-configuration`, so only the
/// issuer and this app's own client registration need to be given here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    pub client_id: String,
    pub client_secret: String,
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
            expiry_sweep_interval_secs: 60,
            oidc_providers: HashMap::new(),
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
            .merge(Env::prefixed("WA_").ignore(&["config_file", "redirect_uri_allowlist"]))
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
                provider.client_secret = client_secret;
            }
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
            assert_eq!(google.client_secret, "my-client-secret");
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
            assert_eq!(google.client_secret, "env-client-secret");
            // Non-secret fields still come from the file, untouched.
            assert_eq!(google.issuer, "https://accounts.google.com");
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
