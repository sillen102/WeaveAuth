use std::env;
use std::fs;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RouteConfig {
    pub path_prefix: String,
    pub upstream_url: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub bff_url: String,
    pub backend_url: String,
    pub session_cookie_name: String,
    /// Proxy routes: incoming requests whose path starts with `path_prefix` are
    /// forwarded to `upstream_url` (prefix stripped) with the session's access
    /// token swapped in as `Authorization: Bearer <token>`, replacing the cookie.
    /// Only configurable via the YAML file — there's no sane env-var shape for a list.
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
}

/// Optional YAML overlay, read before env vars are applied. Path is
/// `WA_CONFIG_FILE` (default `config.yaml`, relative to cwd); missing file is not an error.
#[derive(Debug, Clone, Default, Deserialize)]
struct FileConfig {
    port: Option<u16>,
    bff_url: Option<String>,
    backend_url: Option<String>,
    session_cookie_name: Option<String>,
    #[serde(default)]
    routes: Vec<RouteConfig>,
    trusted_origins: Option<Vec<String>>,
    rate_limit_max_attempts: Option<u32>,
    rate_limit_window_secs: Option<u64>,
}

fn load_file_config() -> Result<FileConfig, anyhow::Error> {
    let path = env::var("WA_CONFIG_FILE").unwrap_or_else(|_| "config.yaml".into());
    match fs::read_to_string(&path) {
        Ok(contents) => Ok(serde_yaml::from_str(&contents)?),
        Err(_) => Ok(FileConfig::default()),
    }
}

impl Config {
    pub fn load() -> Result<Self, anyhow::Error> {
        let file = load_file_config()?;

        let port = env::var("WA_BFF_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .or(file.port)
            .unwrap_or(8080);
        let bff_url = env::var("WA_BFF_URL")
            .ok()
            .or(file.bff_url)
            .unwrap_or_else(|| "http://localhost:8080".into());
        let backend_url = env::var("WA_BACKEND_URL")
            .ok()
            .or(file.backend_url)
            .unwrap_or_else(|| "http://localhost:1983".into());
        let session_cookie_name = env::var("WA_SESSION_COOKIE_NAME")
            .ok()
            .or(file.session_cookie_name)
            .unwrap_or_else(|| "wa_session".into());
        let trusted_origins = env::var("WA_TRUSTED_ORIGINS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .or(file.trusted_origins)
            .unwrap_or_else(|| vec!["http://localhost:8081".to_string()]);
        let rate_limit_max_attempts = env::var("WA_RATE_LIMIT_MAX_ATTEMPTS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.rate_limit_max_attempts)
            .unwrap_or(10);
        let rate_limit_window_secs = env::var("WA_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.rate_limit_window_secs)
            .unwrap_or(60);

        Ok(Self {
            port,
            bff_url,
            backend_url,
            session_cookie_name,
            routes: file.routes,
            trusted_origins,
            rate_limit_max_attempts,
            rate_limit_window_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `Config::load()` reads process-global env vars, so tests that touch them
    /// must not run concurrently with each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        keys: Vec<&'static str>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&'static str, &str)]) -> Self {
            for (k, v) in pairs {
                unsafe { env::set_var(k, v) };
            }
            Self {
                keys: pairs.iter().map(|(k, _)| *k).collect(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for k in &self.keys {
                unsafe { env::remove_var(k) };
            }
        }
    }

    const ALL_KEYS: &[&str] = &[
        "WA_BFF_PORT",
        "WA_BFF_URL",
        "WA_BACKEND_URL",
        "WA_SESSION_COOKIE_NAME",
        "WA_TRUSTED_ORIGINS",
        "WA_RATE_LIMIT_MAX_ATTEMPTS",
        "WA_RATE_LIMIT_WINDOW_SECS",
        "WA_CONFIG_FILE",
    ];

    fn clear_env() -> EnvGuard {
        for k in ALL_KEYS {
            unsafe { env::remove_var(k) };
        }
        EnvGuard { keys: vec![] }
    }

    fn temp_yaml(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "weaveauth-bff-config-test-{}-{}.yaml",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn defaults_when_no_env_and_no_file() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let _guard = EnvGuard::set(&[("WA_CONFIG_FILE", "/nonexistent/path.yaml")]);

        let config = Config::load().unwrap();
        assert_eq!(config.port, 8080);
        assert_eq!(config.bff_url, "http://localhost:8080");
        assert_eq!(config.backend_url, "http://localhost:1983");
        assert_eq!(config.session_cookie_name, "wa_session");
        assert!(config.routes.is_empty());
        assert_eq!(config.trusted_origins, vec!["http://localhost:8081".to_string()]);
        assert_eq!(config.rate_limit_max_attempts, 10);
        assert_eq!(config.rate_limit_window_secs, 60);
    }

    #[test]
    fn file_values_are_used_when_no_env_override() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let path = temp_yaml(
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
        );
        let _guard = EnvGuard::set(&[("WA_CONFIG_FILE", path.to_str().unwrap())]);

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

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn env_vars_override_file_scalars_but_routes_stay_file_only() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let path = temp_yaml(
            r#"
port: 9999
bff_url: "http://file.test:9999"
routes:
  - path_prefix: /api
    upstream_url: http://upstream.file.test
"#,
        );
        let _guard = EnvGuard::set(&[
            ("WA_CONFIG_FILE", path.to_str().unwrap()),
            ("WA_BFF_PORT", "7000"),
            ("WA_BFF_URL", "http://env.test:7000"),
        ]);

        let config = Config::load().unwrap();
        assert_eq!(config.port, 7000);
        assert_eq!(config.bff_url, "http://env.test:7000");
        // No env var shape for routes -- the file's list always wins.
        assert_eq!(config.routes.len(), 1);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_file_falls_back_to_defaults_even_with_other_env_set() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let _guard = EnvGuard::set(&[
            ("WA_CONFIG_FILE", "/nonexistent/path.yaml"),
            ("WA_SESSION_COOKIE_NAME", "custom_cookie"),
        ]);

        let config = Config::load().unwrap();
        assert_eq!(config.session_cookie_name, "custom_cookie");
        assert!(config.routes.is_empty());
    }

    #[test]
    fn trusted_origins_env_overrides_file_and_splits_trims_and_drops_empties() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let path = temp_yaml(
            r#"
trusted_origins:
  - "http://file-login.test"
"#,
        );
        let _guard = EnvGuard::set(&[
            ("WA_CONFIG_FILE", path.to_str().unwrap()),
            (
                "WA_TRUSTED_ORIGINS",
                "http://a.test , http://b.test,,",
            ),
        ]);

        let config = Config::load().unwrap();
        assert_eq!(
            config.trusted_origins,
            vec!["http://a.test".to_string(), "http://b.test".to_string()]
        );

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rate_limit_env_vars_override_file_values() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let path = temp_yaml(
            r#"
rate_limit_max_attempts: 5
rate_limit_window_secs: 30
"#,
        );
        let _guard = EnvGuard::set(&[
            ("WA_CONFIG_FILE", path.to_str().unwrap()),
            ("WA_RATE_LIMIT_MAX_ATTEMPTS", "3"),
            ("WA_RATE_LIMIT_WINDOW_SECS", "15"),
        ]);

        let config = Config::load().unwrap();
        assert_eq!(config.rate_limit_max_attempts, 3);
        assert_eq!(config.rate_limit_window_secs, 15);

        std::fs::remove_file(path).unwrap();
    }
}
