#![forbid(unsafe_code)]
#![deny(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::unnecessary_unwrap,
    clippy::redundant_clone,
    clippy::todo,
    clippy::unimplemented
)]

use std::env;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use figment::providers::{Env, Serialized};
use figment::Figment;
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub bff_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8081,
            bff_url: "http://localhost:8080".to_string(),
        }
    }
}

impl Config {
    /// Loads config from `WA_LOGIN_PORT` / `WA_BFF_URL` env vars, falling back
    /// to defaults for anything unset.
    pub fn load() -> Self {
        let defaults = Config::default();

        let mut config: Config = Figment::from(Serialized::defaults(defaults.clone()))
            // `WA_LOGIN_PORT` needs parse-or-fallback semantics (an invalid
            // value should keep the default rather than fail the whole
            // config), so it's applied by hand below instead.
            .merge(
                Env::raw()
                    .map(|k| match k.as_str() {
                        "WA_BFF_URL" => "bff_url".into(),
                        _ => "_ignored".into(),
                    })
                    .ignore(&["_ignored"]),
            )
            .extract()
            .unwrap_or(defaults);

        if let Some(port) = env::var("WA_LOGIN_PORT").ok().and_then(|p| p.parse().ok()) {
            config.port = port;
        }

        config
    }
}

pub fn app(config: Config) -> Router {
    let files = ServeDir::new(STATIC_DIR);
    Router::new()
        .route("/config.js", get(config_js))
        .nest_service("/static", files.clone())
        .fallback_service(files)
        .with_state(config)
}

/// Exposes `bff_url` to the static login/register pages, so their forms can
/// submit straight to bff's absolute URL (a real cross-origin navigation --
/// not a fetch, so this needs no CORS) without the deployer-replaceable HTML
/// files having to know it themselves.
async fn config_js(State(config): State<Config>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        format!("window.BFF_URL = {:?};\n", config.bff_url),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::Jail;

    #[test]
    fn defaults_when_no_env_set() {
        Jail::expect_with(|_jail| {
            let config = Config::load();
            assert_eq!(config.port, 8081);
            assert_eq!(config.bff_url, "http://localhost:8080");
            Ok(())
        });
    }

    #[test]
    fn env_vars_override_defaults() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_LOGIN_PORT", "9999");
            jail.set_env("WA_BFF_URL", "http://bff.env.test");

            let config = Config::load();
            assert_eq!(config.port, 9999);
            assert_eq!(config.bff_url, "http://bff.env.test");
            Ok(())
        });
    }

    #[test]
    fn invalid_port_falls_back_to_default() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_LOGIN_PORT", "not-a-port");

            assert_eq!(Config::load().port, 8081);
            Ok(())
        });
    }
}
