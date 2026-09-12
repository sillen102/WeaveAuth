use std::env;

use axum::extract::{Query, State};
use axum::response::Redirect;
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use tower_http::services::ServeDir;

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub bff_url: String,
}

impl Config {
    pub fn load() -> Self {
        let port = env::var("WA_LOGIN_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8081);
        let bff_url = env::var("WA_BFF_URL").unwrap_or_else(|_| "http://localhost:8080".into());
        Self { port, bff_url }
    }
}

pub fn app(config: Config) -> Router {
    let files = ServeDir::new(STATIC_DIR);
    Router::new()
        .route("/login", get(start_login))
        .nest_service("/static", files.clone())
        .fallback_service(files)
        .with_state(config)
}

#[derive(Deserialize)]
struct LoginQuery {
    redirect_uri: String,
}

async fn start_login(State(config): State<Config>, Query(query): Query<LoginQuery>) -> Redirect {
    let redirect_uri = query.redirect_uri;

    let qs = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_uri", &redirect_uri)
        .finish();

    Redirect::to(&format!("{}/login?{}", config.bff_url, qs))
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

    const ALL_KEYS: &[&str] = &["WA_LOGIN_PORT", "WA_BFF_URL"];

    fn clear_env() -> EnvGuard {
        for k in ALL_KEYS {
            unsafe { env::remove_var(k) };
        }
        EnvGuard { keys: vec![] }
    }

    #[test]
    fn defaults_when_no_env_set() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();

        let config = Config::load();
        assert_eq!(config.port, 8081);
        assert_eq!(config.bff_url, "http://localhost:8080");
    }

    #[test]
    fn env_vars_override_defaults() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let _guard = EnvGuard::set(&[
            ("WA_LOGIN_PORT", "9999"),
            ("WA_BFF_URL", "http://bff.env.test"),
        ]);

        let config = Config::load();
        assert_eq!(config.port, 9999);
        assert_eq!(config.bff_url, "http://bff.env.test");
    }

    #[test]
    fn invalid_port_falls_back_to_default() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = clear_env();
        let _guard = EnvGuard::set(&[("WA_LOGIN_PORT", "not-a-port")]);

        assert_eq!(Config::load().port, 8081);
    }
}
