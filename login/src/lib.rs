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
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

use std::env;
use axum::extract::{OriginalUri, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use figment::providers::{Env, Serialized};
use figment::Figment;
use serde::{Deserialize, Serialize};
use tera::{Context, Tera};
use tower_http::services::ServeDir;

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");

/// Deployer-replaceable page templates -- see `AGENTS.md` in this crate for
/// the rule these must follow (plain HTML/CSS, no `<script>`, no client-side
/// logic at all). Re-globbed on every request rather than loaded once, so a
/// deployer can drop in a new file without restarting the process, matching
/// how the static assets in `STATIC_DIR` already behave.
const TEMPLATES_GLOB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/templates/*.html");

/// The login shell -- compiled into the binary rather than served from
/// `STATIC_DIR`, so a deployer replacing the static dir's contents (to
/// reskin `login.html`/`register.html`) can't affect this routing shell.
const INDEX_HTML: &str = include_str!("index.html");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub bff_url: String,
    pub own_origin: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8081,
            bff_url: "http://localhost:8080".to_string(),
            own_origin: "http://localhost:8081".to_string(),
        }
    }
}

impl Config {
    /// Loads config from `WA_LOGIN_PORT` / `WA_BFF_URL` / `WA_LOGIN_PUBLIC_URL` env
    /// vars, falling back to defaults for anything unset.
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
                        "WA_LOGIN_PUBLIC_URL" => "own_origin".into(),
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
        .route("/", get(index_page))
        .route("/index.html", get(index_page))
        .route("/login.html", get(login_page))
        .route("/register.html", get(register_page))
        .nest_service("/static", files.clone())
        .fallback_service(files)
        .with_state(config)
}

/// Serves the compiled-in shell at `/` (and `/index.html`, for anyone linking
/// there directly) ahead of the static-dir fallback, so it always wins over
/// anything a deployer drops into the static dir.
async fn index_page() -> impl IntoResponse {
    Html(INDEX_HTML)
}

/// Query params a deployer's page template can be rendered with. All
/// optional -- the templates handle every field being absent (a plain first
/// visit).
#[derive(Debug, Default, Deserialize)]
struct PageQuery {
    redirect_uri: Option<String>,
    error: Option<String>,
    email: Option<String>,
}

async fn login_page(
    State(config): State<Config>,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<PageQuery>,
) -> Result<Html<String>, StatusCode> {
    render_page("login.html", &config, uri.path(), &query)
}

async fn register_page(
    State(config): State<Config>,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<PageQuery>,
) -> Result<Html<String>, StatusCode> {
    render_page("register.html", &config, uri.path(), &query)
}

/// Renders one of the deployer-replaceable page templates, computing the
/// same values their inline scripts used to compute client-side:
/// `redirect_uri` (falling back to this service's own origin), and
/// `own_url`/`next` (this page's own URL with that `redirect_uri` echoed
/// back, so a form failure or an OIDC round-trip can bounce back here).
fn render_page(
    template: &str,
    config: &Config,
    path: &str,
    query: &PageQuery,
) -> Result<Html<String>, StatusCode> {
    let origin = &config.own_origin;
    let redirect_uri = query
        .redirect_uri
        .clone()
        .unwrap_or_else(|| format!("{origin}/"));
    let own_url = format!(
        "{origin}{path}?redirect_uri={}",
        url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>(),
    );

    let mut ctx = Context::new();
    ctx.insert("bff_url", &config.bff_url);
    ctx.insert("redirect_uri", &redirect_uri);
    ctx.insert("own_url", &own_url);
    ctx.insert("error", &query.error);
    ctx.insert("email", &query.email);

    let mut tera = Tera::new();
    tera.register_filter("urlencode", urlencode_filter);
    tera.load_from_glob(TEMPLATES_GLOB)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tera.render(template, &ctx)
        .map(Html)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Tera 2 dropped its built-in `urlencode` filter, so templates that rely on
/// it (to safely embed `redirect_uri`/`next` in query strings) need it
/// registered by hand.
/// RFC 3986 unreserved characters, left unescaped like every other
/// percent-encoding scheme (`-`, `_`, `.`, `~` alongside alphanumerics).
const URLENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn urlencode_filter(value: String, _kwargs: tera::Kwargs, _state: &tera::State) -> String {
    percent_encoding::utf8_percent_encode(&value, URLENCODE_SET).collect()
}

#[cfg(test)]
// figment::Jail::expect_with's closure signature is fixed by the crate; its
// Result<(), figment::Error> can't be shrunk from call sites.
#[allow(clippy::result_large_err)]
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
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");

            let config = Config::load();
            assert_eq!(config.port, 9999);
            assert_eq!(config.bff_url, "http://bff.env.test");
            assert_eq!(config.own_origin, "https://login.env.test");
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
