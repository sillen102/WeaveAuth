use figment::Figment;
use figment::providers::{Env, Format, Serialized, Yaml};
use serde::{Deserialize, Serialize};
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
        }
    }
}

impl Config {
    /// Loads config, layering (highest precedence last): built-in defaults,
    /// then the YAML file at `WA_CONFIG_FILE` (default `config.yaml`, missing
    /// file is not an error), then `WA_*` env vars.
    pub fn load() -> Result<Self, anyhow::Error> {
        let path = env::var("WA_CONFIG_FILE").unwrap_or_else(|_| "config.yaml".into());

        let mut config: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Yaml::file(&path))
            // `redirect_uri_allowlist` has no sane single-value env-var shape
            // (a comma-separated string, not Figment's `[a, b]` array syntax),
            // so it's applied by hand below instead.
            .merge(Env::prefixed("WA_").ignore(&["config_file", "redirect_uri_allowlist"]))
            .extract()?;

        if let Ok(raw) = env::var("WA_REDIRECT_URI_ALLOWLIST") {
            config.redirect_uri_allowlist = raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
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
}
