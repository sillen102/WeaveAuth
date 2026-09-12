use std::env;
use std::fs;

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub redirect_uri_allowlist: Vec<String>,
    pub pkce_code_ttl_secs: i64,
    /// How long a `/oauth/login` session token stays valid for the follow-up
    /// `/oauth/authorize` call -- just a server-to-server hop, so this is
    /// deliberately short-lived.
    pub login_session_ttl_secs: i64,
}

/// Optional YAML overlay, read before env vars are applied. Path is
/// `WA_CONFIG_FILE` (default `config.yaml`, relative to cwd); missing file is not an error.
#[derive(Debug, Clone, Default, Deserialize)]
struct FileConfig {
    port: Option<u16>,
    redirect_uri_allowlist: Option<Vec<String>>,
    pkce_code_ttl_secs: Option<i64>,
    login_session_ttl_secs: Option<i64>,
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

        let port = env::var("WA_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .or(file.port)
            .unwrap_or(1983);

        let redirect_uri_allowlist = env::var("WA_REDIRECT_URI_ALLOWLIST")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .or(file.redirect_uri_allowlist)
            .unwrap_or_else(|| vec!["http://localhost:8081/".to_string()]);

        let pkce_code_ttl_secs = env::var("WA_PKCE_CODE_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.pkce_code_ttl_secs)
            .unwrap_or(300);

        let login_session_ttl_secs = env::var("WA_LOGIN_SESSION_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.login_session_ttl_secs)
            .unwrap_or(60);

        Ok(Self {
            port,
            redirect_uri_allowlist,
            pkce_code_ttl_secs,
            login_session_ttl_secs,
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
        "WA_PORT",
        "WA_REDIRECT_URI_ALLOWLIST",
        "WA_PKCE_CODE_TTL_SECS",
        "WA_LOGIN_SESSION_TTL_SECS",
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
            "weaveauth-backend-config-test-{}-{}.yaml",
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
        assert_eq!(config.port, 1983);
        assert_eq!(
            config.redirect_uri_allowlist,
            vec!["http://localhost:8081/".to_string()]
        );
        assert_eq!(config.pkce_code_ttl_secs, 300);
        assert_eq!(config.login_session_ttl_secs, 60);
    }

    #[test]
    fn file_values_are_used_when_no_env_override() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let path = temp_yaml(
            "port: 9999\nredirect_uri_allowlist:\n  - http://file.test/callback\npkce_code_ttl_secs: 42\nlogin_session_ttl_secs: 30\n",
        );
        let _guard = EnvGuard::set(&[("WA_CONFIG_FILE", path.to_str().unwrap())]);

        let config = Config::load().unwrap();
        assert_eq!(config.port, 9999);
        assert_eq!(
            config.redirect_uri_allowlist,
            vec!["http://file.test/callback".to_string()]
        );
        assert_eq!(config.pkce_code_ttl_secs, 42);
        assert_eq!(config.login_session_ttl_secs, 30);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn env_vars_override_file_values() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let path = temp_yaml(
            "port: 9999\nredirect_uri_allowlist:\n  - http://file.test/callback\npkce_code_ttl_secs: 42\nlogin_session_ttl_secs: 30\n",
        );
        let _guard = EnvGuard::set(&[
            ("WA_CONFIG_FILE", path.to_str().unwrap()),
            ("WA_PORT", "7000"),
            ("WA_REDIRECT_URI_ALLOWLIST", "http://env.test/callback"),
            ("WA_PKCE_CODE_TTL_SECS", "11"),
            ("WA_LOGIN_SESSION_TTL_SECS", "5"),
        ]);

        let config = Config::load().unwrap();
        assert_eq!(config.port, 7000);
        assert_eq!(
            config.redirect_uri_allowlist,
            vec!["http://env.test/callback".to_string()]
        );
        assert_eq!(config.pkce_code_ttl_secs, 11);
        assert_eq!(config.login_session_ttl_secs, 5);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn redirect_uri_allowlist_env_splits_trims_and_drops_empties() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let _guard = EnvGuard::set(&[
            ("WA_CONFIG_FILE", "/nonexistent/path.yaml"),
            ("WA_REDIRECT_URI_ALLOWLIST", "http://a.test , http://b.test,,"),
        ]);

        let config = Config::load().unwrap();
        assert_eq!(
            config.redirect_uri_allowlist,
            vec!["http://a.test".to_string(), "http://b.test".to_string()]
        );
    }
}
