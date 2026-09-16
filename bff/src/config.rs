use std::env;

use figment::providers::{Env, Format, Serialized, Yaml};
use figment::Figment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteConfig {
    pub path_prefix: String,
    pub upstream_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub bff_url: String,
    pub backend_url: String,
    pub session_cookie_name: String,
    /// Proxy routes: incoming requests whose path starts with `path_prefix` are
    /// forwarded to `upstream_url` (prefix stripped) with the session's access
    /// token swapped in as `Authorization: Bearer <token>`, replacing the cookie.
    /// Only configurable via the YAML file -- there's no sane env-var shape for a list.
    pub routes: Vec<RouteConfig>,
    /// Origins allowed to POST to `/login` and `/register` (checked against the
    /// request's `Origin` header, falling back to `Referer`) -- these are plain
    /// cross-origin form POSTs by design, so without this check any site could
    /// auto-submit one and log a victim into an attacker-controlled account
    /// ("login CSRF").
    pub trusted_origins: Vec<String>,
    /// Max `/login` or `/register` attempts a single client IP gets within
    /// `rate_limit_window_secs`, independently for each endpoint -- Argon2 raises
    /// the cost of a single guess, but doesn't stop a flood of guesses or
    /// registration spam on its own.
    pub rate_limit_max_attempts: u32,
    pub rate_limit_window_secs: u64,
    /// How often the background task sweeps expired sessions out of the
    /// session store. Bounds how long a dead session's leftovers linger.
    pub expiry_sweep_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8080,
            bff_url: "http://localhost:8080".to_string(),
            backend_url: "http://localhost:1983".to_string(),
            session_cookie_name: "wa_session".to_string(),
            routes: Vec::new(),
            trusted_origins: vec!["http://localhost:8081".to_string()],
            rate_limit_max_attempts: 10,
            rate_limit_window_secs: 60,
            expiry_sweep_interval_secs: 60,
        }
    }
}

impl Config {
    /// Whether cookies should carry the `Secure` flag -- derived from `bff_url`
    /// so plain HTTP local dev keeps working without a separate setting.
    pub(crate) fn secure_cookies(&self) -> bool {
        self.bff_url.starts_with("https://")
    }

    /// Loads config, layering (highest precedence last): built-in defaults,
    /// then the YAML file at `WA_CONFIG_FILE` (default `config.yaml`, missing
    /// file is not an error), then `WA_*` env vars.
    pub fn load() -> Result<Self, anyhow::Error> {
        dotenvy::dotenv().ok();

        let path = env::var("WA_CONFIG_FILE").unwrap_or_else(|_| "config.yaml".into());

        // `WA_LOGIN_PUBLIC_URL` is login's own public origin (see
        // `login::Config::own_origin`) -- when the two run side by side, it's
        // also the one bff should trust by default, so seed the built-in
        // default from it before the YAML file/`WA_TRUSTED_ORIGINS` env var
        // (below) get a chance to override it.
        let mut defaults = Config::default();
        if let Ok(login_url) = env::var("WA_LOGIN_PUBLIC_URL") {
            defaults.trusted_origins = vec![login_url];
        }

        let mut config: Config = Figment::from(Serialized::defaults(defaults))
            .merge(Yaml::file(&path))
            // `WA_BFF_PORT`/`WA_BACKEND_URL` etc don't map 1:1 to their field
            // names, and `routes`/`trusted_origins` need custom handling below
            // (routes has no env shape at all; trusted_origins is a
            // comma-separated string, not Figment's `[a, b]` array syntax).
            .merge(
                Env::raw()
                    .map(|k| match k.as_str() {
                        "WA_BFF_PORT" => "port".into(),
                        "WA_BFF_URL" => "bff_url".into(),
                        "WA_BACKEND_URL" => "backend_url".into(),
                        "WA_SESSION_COOKIE_NAME" => "session_cookie_name".into(),
                        "WA_RATE_LIMIT_MAX_ATTEMPTS" => "rate_limit_max_attempts".into(),
                        "WA_RATE_LIMIT_WINDOW_SECS" => "rate_limit_window_secs".into(),
                        "WA_EXPIRY_SWEEP_INTERVAL_SECS" => "expiry_sweep_interval_secs".into(),
                        _ => "_ignored".into(),
                    })
                    .ignore(&["_ignored"]),
            )
            .extract()?;

        if let Ok(raw) = env::var("WA_TRUSTED_ORIGINS") {
            config.trusted_origins = raw
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
            assert_eq!(config.port, 8080);
            assert_eq!(config.bff_url, "http://localhost:8080");
            assert_eq!(config.backend_url, "http://localhost:1983");
            assert_eq!(config.session_cookie_name, "wa_session");
            assert!(config.routes.is_empty());
            assert_eq!(config.trusted_origins, vec!["http://localhost:8081".to_string()]);
            assert_eq!(config.rate_limit_max_attempts, 10);
            assert_eq!(config.rate_limit_window_secs, 60);
            Ok(())
        });
    }

    #[test]
    fn file_values_are_used_when_no_env_override() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
port: 9999
bff_url: "http://file.test:9999"
backend_url: "http://backend.file.test"
session_cookie_name: "file_cookie"
routes:
  - path_prefix: /api
    upstream_url: http://upstream.file.test
trusted_origins:
  - "http://file-login.test"
rate_limit_max_attempts: 5
rate_limit_window_secs: 30
"#,
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 9999);
            assert_eq!(config.bff_url, "http://file.test:9999");
            assert_eq!(config.backend_url, "http://backend.file.test");
            assert_eq!(config.session_cookie_name, "file_cookie");
            assert_eq!(
                config.routes,
                vec![RouteConfig {
                    path_prefix: "/api".to_string(),
                    upstream_url: "http://upstream.file.test".to_string(),
                }]
            );
            assert_eq!(
                config.trusted_origins,
                vec!["http://file-login.test".to_string()]
            );
            assert_eq!(config.rate_limit_max_attempts, 5);
            assert_eq!(config.rate_limit_window_secs, 30);
            Ok(())
        });
    }

    #[test]
    fn env_vars_override_file_scalars_but_routes_stay_file_only() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
port: 9999
bff_url: "http://file.test:9999"
routes:
  - path_prefix: /api
    upstream_url: http://upstream.file.test
"#,
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_BFF_PORT", "7000");
            jail.set_env("WA_BFF_URL", "http://env.test:7000");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 7000);
            assert_eq!(config.bff_url, "http://env.test:7000");
            // No env var shape for routes -- the file's list always wins.
            assert_eq!(config.routes.len(), 1);
            Ok(())
        });
    }

    #[test]
    fn missing_file_falls_back_to_defaults_even_with_other_env_set() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_SESSION_COOKIE_NAME", "custom_cookie");

            let config = Config::load().unwrap();
            assert_eq!(config.session_cookie_name, "custom_cookie");
            assert!(config.routes.is_empty());
            Ok(())
        });
    }

    #[test]
    fn trusted_origins_env_overrides_file_and_splits_trims_and_drops_empties() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
trusted_origins:
  - "http://file-login.test"
"#,
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_TRUSTED_ORIGINS", "http://a.test , http://b.test,,");

            let config = Config::load().unwrap();
            assert_eq!(
                config.trusted_origins,
                vec!["http://a.test".to_string(), "http://b.test".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn trusted_origins_defaults_to_login_public_url_when_unset() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");

            let config = Config::load().unwrap();
            assert_eq!(
                config.trusted_origins,
                vec!["https://login.env.test".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn explicit_trusted_origins_still_wins_over_login_public_url() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");
            jail.set_env("WA_TRUSTED_ORIGINS", "https://other.test");

            let config = Config::load().unwrap();
            assert_eq!(config.trusted_origins, vec!["https://other.test".to_string()]);
            Ok(())
        });
    }

    #[test]
    fn rate_limit_env_vars_override_file_values() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
rate_limit_max_attempts: 5
rate_limit_window_secs: 30
"#,
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_RATE_LIMIT_MAX_ATTEMPTS", "3");
            jail.set_env("WA_RATE_LIMIT_WINDOW_SECS", "15");

            let config = Config::load().unwrap();
            assert_eq!(config.rate_limit_max_attempts, 3);
            assert_eq!(config.rate_limit_window_secs, 15);
            Ok(())
        });
    }
}
