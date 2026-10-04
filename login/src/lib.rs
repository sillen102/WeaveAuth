#![forbid(unsafe_code)]
#![deny(
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
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{OriginalUri, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use common::config::PublicUrl;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tera::{Context, Tera};
use tower_http::services::ServeDir;

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");

/// Deployer-replaceable page templates -- see `AGENTS.md` in this crate for
/// the rule these must follow (plain HTML/CSS, no `<script>`, no client-side
/// logic at all). Re-globbed on every request rather than loaded once, so a
/// deployer can drop in a new file without restarting the process, matching
/// how the static assets in `STATIC_DIR` already behave.
const TEMPLATES_GLOB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../templates/pages/*.html");

/// The login shell -- compiled into the binary rather than served from
/// `STATIC_DIR`, so a deployer replacing the static dir's contents (to
/// reskin `login.html`/`register.html`) can't affect this routing shell.
const INDEX_HTML: &str = include_str!("index.html");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub bff_url: String,
    pub own_origin: String,
    /// Where the user goes after any login page opened without a
    /// `redirect_uri`. Must be on backend's redirect allowlist. Unset: login's
    /// own origin.
    pub default_redirect_uri: Option<String>,
    /// Like `default_redirect_uri`, for the pages reached from an email link
    /// (they never carry a `redirect_uri`): the verification page once the
    /// code is right, the login page after a password reset, and the
    /// forgot-password page (bff's dead-link redirect carries none either).
    /// Must be on backend's redirect allowlist. Unset: `default_redirect_uri`.
    pub email_link_default_redirect_uri: Option<String>,
    /// Where login itself reaches bff (for `/oidc/providers`), when
    /// `bff_url` -- the browser-facing address -- doesn't resolve from
    /// login's network. Unset: `bff_url`.
    pub bff_internal_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8081,
            bff_url: "http://localhost:8080".to_string(),
            own_origin: "http://localhost:8081".to_string(),
            default_redirect_uri: None,
            email_link_default_redirect_uri: None,
            bff_internal_url: None,
        }
    }
}

const ENV: common::config::EnvTable = &[
    ("WA_PROFILE", "profile"),
    ("WA_BFF_URL", "bff_url"),
    ("WA_LOGIN_PUBLIC_URL", "own_origin"),
    ("WA_DEFAULT_REDIRECT_URI", "default_redirect_uri"),
    (
        "WA_EMAIL_LINK_DEFAULT_REDIRECT_URI",
        "email_link_default_redirect_uri",
    ),
    ("WA_BFF_INTERNAL_URL", "bff_internal_url"),
];

impl Config {
    /// Loads config from the env vars in [`ENV`] plus `WA_LOGIN_PORT`, falling
    /// back to defaults for anything unset (an empty `WA_DEFAULT_REDIRECT_URI`,
    /// `WA_EMAIL_LINK_DEFAULT_REDIRECT_URI` or `WA_BFF_INTERNAL_URL` counts as
    /// unset). A value that is set but invalid is an error: silently using the
    /// defaults would point the login page at localhost. Under the prod
    /// profile (`WA_PROFILE`, the default) `WA_BFF_URL`,
    /// `WA_DEFAULT_REDIRECT_URI` and `WA_EMAIL_LINK_DEFAULT_REDIRECT_URI` must
    /// be https and `WA_LOGIN_PUBLIC_URL` an https origin. `own_origin` is
    /// stored without a trailing `/`.
    pub fn load() -> anyhow::Result<Self> {
        // `WA_LOGIN_PORT` is applied by hand below, so its error names the variable.
        let user = common::config::user_settings(false, ENV, &[])?;
        let mut config: Config = common::config::extract(Config::default(), &user)
            .map_err(|error| anyhow::anyhow!("invalid login configuration: {error}"))?;
        let profile = common::config::profile(&user)?;
        common::config::require_https_in_prod(
            profile,
            &[
                ("WA_BFF_URL", &config.bff_url, PublicUrl::Base),
                ("WA_LOGIN_PUBLIC_URL", &config.own_origin, PublicUrl::Origin),
            ],
        )?;
        // Every URL derived from it appends a path.
        config.own_origin = config.own_origin.trim_end_matches('/').to_string();

        if let Ok(raw) = env::var("WA_LOGIN_PORT") {
            config.port = raw
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid WA_LOGIN_PORT {raw:?}: {error}"))?;
        }

        config.bff_internal_url = config.bff_internal_url.filter(|raw| !raw.is_empty());
        for (var, value) in [
            ("WA_DEFAULT_REDIRECT_URI", &mut config.default_redirect_uri),
            (
                "WA_EMAIL_LINK_DEFAULT_REDIRECT_URI",
                &mut config.email_link_default_redirect_uri,
            ),
        ] {
            *value = value.take().filter(|raw| !raw.is_empty());
            if let Some(raw) = value {
                let url = url::Url::parse(raw)
                    .map_err(|error| anyhow::anyhow!("invalid {var} {raw:?}: {error}"))?;
                if !matches!(url.scheme(), "http" | "https") {
                    anyhow::bail!("invalid {var} {raw:?}: not an http(s) URL");
                }
                common::config::require_https_in_prod(profile, &[(var, raw, PublicUrl::Base)])?;
            }
        }

        Ok(config)
    }
}

pub fn app(config: Config) -> Router {
    let files = ServeDir::new(STATIC_DIR);
    Router::new()
        .route("/", get(index_page))
        .route("/index.html", get(index_page))
        .route("/login.html", get(login_page))
        .route("/register.html", get(register_page))
        .route("/verify-email.html", get(verify_email_page))
        .route("/forgot-password.html", get(forgot_password_page))
        .route("/reset-password.html", get(reset_password_page))
        .nest_service("/static", files.clone())
        .fallback_service(files)
        .with_state(AppState {
            provider_names: Arc::new(ProviderNamesCache::new(&config)),
            config,
        })
}

#[derive(Clone)]
struct AppState {
    config: Config,
    provider_names: Arc<ProviderNamesCache>,
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
    /// With `email`: whether the account can confirm the link with a
    /// password. Absent counts as `true`.
    has_password: Option<bool>,
    /// With `email`: comma-separated keys of the providers already linked to
    /// the account, any of which can confirm the link. Keys bff's
    /// `/oidc/providers` doesn't list are dropped.
    linked_providers: Option<String>,
    /// With `email`: key of the provider whose sign-in is waiting to be linked.
    provider: Option<String>,
    /// What bff bounced back with on the verification page: `invalid`, `sent`,
    /// `cooling_down`, `code_used_up`, `locked`, `locked_until_reset` or
    /// `session_expired`.
    status: Option<String>,
    /// Seconds until a new code can be requested, with `cooling_down` or `locked`.
    retry_after: Option<u64>,
    /// Seconds the new code stays valid, with `sent`.
    expires_in: Option<u64>,
}

/// A malformed query string (a repeated key, say) renders the page as a plain
/// first visit rather than failing it.
fn page_query(query: Result<Query<PageQuery>, QueryRejection>) -> PageQuery {
    match query {
        Ok(Query(query)) => query,
        Err(err) => {
            tracing::info!(status = %err.status(), "ignoring a malformed query string");
            PageQuery::default()
        }
    }
}

async fn login_page(
    State(AppState {
        config,
        provider_names,
    }): State<AppState>,
    OriginalUri(uri): OriginalUri,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Html<String>, StatusCode> {
    let mut query = page_query(query);
    // The reset link carries no redirect_uri, so the page reached after a
    // reset falls back like the verification page does.
    if query.redirect_uri.is_none() && query.status.as_deref() == Some("password_reset") {
        query.redirect_uri = config.email_link_default_redirect_uri.clone();
    }
    // Only the confirm-link view (`email` set) names providers.
    let provider_names = match query.email {
        Some(_) => provider_names.get().await,
        None => ProviderNames::Unavailable,
    };
    render_page("login.html", &config, uri.path(), &query, &provider_names)
}

/// Display names by provider key, from bff's `/oidc/providers`.
#[derive(Clone)]
enum ProviderNames {
    Fetched(HashMap<String, String>),
    /// The lookup failed: keys are shown as themselves, limited to
    /// `[A-Za-z0-9_-]` since they become a bff path segment.
    Unavailable,
}

impl ProviderNames {
    fn get(&self, key: &str) -> Option<String> {
        match self {
            ProviderNames::Fetched(names) => names.get(key).cloned(),
            ProviderNames::Unavailable => {
                let plain = !key.is_empty()
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
                plain.then(|| key.to_string())
            }
        }
    }
}

#[derive(Deserialize)]
struct ProvidersResponse {
    providers: Vec<ProviderEntry>,
}

#[derive(Deserialize)]
struct ProviderEntry {
    key: String,
    display_name: String,
}

/// bff's provider list, fetched on first use and kept for `FETCHED_TTL`
/// (it only changes when backend restarts), or `FAILED_TTL` after a failed
/// lookup -- so rendering the page, which anyone can do, doesn't turn into a
/// bff and backend round trip each time.
struct ProviderNamesCache {
    client: reqwest::Client,
    url: String,
    /// Held across the fetch, so concurrent renders share one request.
    cached: tokio::sync::Mutex<Option<(Instant, ProviderNames)>>,
}

const FETCHED_TTL: Duration = Duration::from_secs(300);
const FAILED_TTL: Duration = Duration::from_secs(30);

impl ProviderNamesCache {
    fn new(config: &Config) -> Self {
        let bff = config.bff_internal_url.as_ref().unwrap_or(&config.bff_url);
        Self {
            client: reqwest::Client::new(),
            url: format!("{bff}/oidc/providers"),
            cached: tokio::sync::Mutex::new(None),
        }
    }

    async fn get(&self) -> ProviderNames {
        let mut cached = self.cached.lock().await;
        if let Some((expires_at, names)) = cached.as_ref()
            && Instant::now() < *expires_at
        {
            return names.clone();
        }
        let names = self.fetch().await;
        let ttl = match names {
            ProviderNames::Fetched(_) => FETCHED_TTL,
            ProviderNames::Unavailable => FAILED_TTL,
        };
        *cached = Some((Instant::now() + ttl, names.clone()));
        names
    }

    async fn fetch(&self) -> ProviderNames {
        let response = async {
            self.client
                .get(&self.url)
                .timeout(Duration::from_secs(2))
                .send()
                .await?
                .error_for_status()?
                .json::<ProvidersResponse>()
                .await
        }
        .await;
        match response {
            Ok(response) => ProviderNames::Fetched(
                response
                    .providers
                    .into_iter()
                    .map(|entry| (entry.key, entry.display_name))
                    .collect(),
            ),
            Err(error) => {
                tracing::warn!(
                    error = %common::error::cause_chain(&error.without_url()),
                    url = %self.url,
                    "could not fetch oidc provider names from bff, showing keys"
                );
                ProviderNames::Unavailable
            }
        }
    }
}

async fn register_page(
    State(AppState { config, .. }): State<AppState>,
    OriginalUri(uri): OriginalUri,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Html<String>, StatusCode> {
    render_page(
        "register.html",
        &config,
        uri.path(),
        &page_query(query),
        &ProviderNames::Unavailable,
    )
}

async fn verify_email_page(
    State(AppState { config, .. }): State<AppState>,
    OriginalUri(uri): OriginalUri,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Html<String>, StatusCode> {
    let mut query = page_query(query);
    if query.redirect_uri.is_none() {
        query.redirect_uri = config.email_link_default_redirect_uri.clone();
    }
    render_page(
        "verify-email.html",
        &config,
        uri.path(),
        &query,
        &ProviderNames::Unavailable,
    )
}

async fn forgot_password_page(
    State(AppState { config, .. }): State<AppState>,
    OriginalUri(uri): OriginalUri,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Html<String>, StatusCode> {
    let mut query = page_query(query);
    // bff's dead-link redirect carries no redirect_uri, like the email links.
    if query.redirect_uri.is_none() {
        query.redirect_uri = config.email_link_default_redirect_uri.clone();
    }
    render_page(
        "forgot-password.html",
        &config,
        uri.path(),
        &query,
        &ProviderNames::Unavailable,
    )
}

/// Opened from the reset email with the token in the fragment. The page
/// script keeps it out of the address bar; these headers keep the page out of
/// caches and its path out of any Referer. Not `no-referrer`: under it the
/// browser sends `Origin: null` on the form's POST to bff, which refuses it.
/// The fragment never goes into a Referer under any policy.
async fn reset_password_page(
    State(AppState { config, .. }): State<AppState>,
    OriginalUri(uri): OriginalUri,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<impl IntoResponse, StatusCode> {
    let page = render_page(
        "reset-password.html",
        &config,
        uri.path(),
        &page_query(query),
        &ProviderNames::Unavailable,
    )?;
    Ok((
        [
            (header::REFERRER_POLICY, "strict-origin"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        page,
    ))
}

/// Waits shorter than this are spelled out in seconds, and the page counts
/// them down; longer ones are rounded up to minutes and stay static.
const SHORT_WAIT_SECS: u64 = 120;

/// "1 second", "42 seconds", "2 minutes": minutes (rounded up) from two on.
fn human_duration(secs: u64) -> String {
    let (n, unit) = if secs < SHORT_WAIT_SECS {
        (secs, "second")
    } else {
        (secs.div_ceil(60), "minute")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// Renders one of the deployer-replaceable page templates, computing the
/// same values their inline scripts used to compute client-side:
/// `redirect_uri` (falling back to `default_redirect_uri`, then this service's
/// own origin), and `own_url`/`next` (this page's own URL with that
/// `redirect_uri` echoed back, so a form failure or an OIDC round-trip can
/// bounce back here).
fn render_page(
    template: &str,
    config: &Config,
    path: &str,
    query: &PageQuery,
    provider_names: &ProviderNames,
) -> Result<Html<String>, StatusCode> {
    let origin = &config.own_origin;
    let redirect_uri = query
        .redirect_uri
        .clone()
        .or_else(|| config.default_redirect_uri.clone())
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
    ctx.insert("has_password", &query.has_password.unwrap_or(true));
    // Names come from bff, never from the URL, so a crafted link can't put its own text on the page.
    let display_name = |key: &str| provider_names.get(key);
    let linked_providers: Vec<LinkedProvider> = query
        .linked_providers
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .filter_map(|key| {
            Some(LinkedProvider {
                key,
                name: display_name(key)?,
            })
        })
        .collect();
    ctx.insert("linked_providers", &linked_providers);
    ctx.insert(
        "provider",
        &query.provider.as_deref().and_then(display_name),
    );
    ctx.insert("status", &query.status);
    ctx.insert("retry_after", &query.retry_after.map(human_duration));
    ctx.insert(
        "countdown_secs",
        &query.retry_after.filter(|secs| *secs < SHORT_WAIT_SECS),
    );
    ctx.insert("expires_in", &query.expires_in.map(human_duration));

    let mut tera = Tera::new();
    tera.register_filter("urlencode", urlencode_filter);
    tera.load_from_glob(TEMPLATES_GLOB).map_err(|error| {
        tracing::error!(%error, "could not load login page templates");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    tera.render(template, &ctx).map(Html).map_err(|error| {
        tracing::error!(%error, template, "could not render login page");
        StatusCode::INTERNAL_SERVER_ERROR
    })
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

#[derive(Serialize)]
struct LinkedProvider<'a> {
    key: &'a str,
    name: String,
}

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
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            let config = Config::load().unwrap();
            assert_eq!(config.port, 8081);
            assert_eq!(config.bff_url, "http://localhost:8080");
            assert_eq!(config.email_link_default_redirect_uri, None);
            Ok(())
        });
    }

    #[test]
    fn the_internal_bff_url_is_read_from_its_env_var() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            assert_eq!(Config::load().unwrap().bff_internal_url, None);
            jail.set_env("WA_BFF_INTERNAL_URL", "http://bff.internal:8080");

            let config = Config::load().unwrap();
            assert_eq!(
                config.bff_internal_url.as_deref(),
                Some("http://bff.internal:8080")
            );
            Ok(())
        });
    }

    #[test]
    fn env_vars_override_defaults() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_LOGIN_PORT", "9999");
            jail.set_env("WA_BFF_URL", "http://bff.env.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");
            jail.set_env(
                "WA_EMAIL_LINK_DEFAULT_REDIRECT_URI",
                "https://app.env.test/home",
            );

            let config = Config::load().unwrap();
            assert_eq!(
                config.email_link_default_redirect_uri.as_deref(),
                Some("https://app.env.test/home")
            );
            assert_eq!(config.port, 9999);
            assert_eq!(config.bff_url, "http://bff.env.test");
            assert_eq!(config.own_origin, "https://login.env.test");
            Ok(())
        });
    }

    #[test]
    fn the_default_redirect_uri_is_read_validated_and_empty_counts_as_unset() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_DEFAULT_REDIRECT_URI", "http://app.test/home");
            let config = Config::load().unwrap();
            assert_eq!(
                config.default_redirect_uri.as_deref(),
                Some("http://app.test/home")
            );
            assert_eq!(config.email_link_default_redirect_uri, None);

            jail.set_env("WA_DEFAULT_REDIRECT_URI", "");
            assert_eq!(Config::load().unwrap().default_redirect_uri, None);

            jail.set_env("WA_DEFAULT_REDIRECT_URI", "/downstream");
            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_DEFAULT_REDIRECT_URI"), "{error}");

            jail.set_env("WA_PROFILE", "prod");
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
            jail.set_env("WA_DEFAULT_REDIRECT_URI", "http://app.test/home");
            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_DEFAULT_REDIRECT_URI"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn an_empty_email_link_default_redirect_uri_counts_as_unset() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_EMAIL_LINK_DEFAULT_REDIRECT_URI", "");

            let config = Config::load().unwrap();
            assert_eq!(config.email_link_default_redirect_uri, None);
            Ok(())
        });
    }

    #[test]
    fn an_unparseable_email_link_default_redirect_uri_is_an_error() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_EMAIL_LINK_DEFAULT_REDIRECT_URI", "/downstream");

            let error = Config::load()
                .expect_err("a relative URL can't be redirected to once the code is spent");
            assert!(
                error
                    .to_string()
                    .contains("WA_EMAIL_LINK_DEFAULT_REDIRECT_URI"),
                "unhelpful error: {error}"
            );
            Ok(())
        });
    }

    #[test]
    fn a_email_link_default_redirect_uri_must_be_http_or_https() {
        for value in ["javascript:alert(1)", "mailto:a@example.com"] {
            Jail::expect_with(|jail| {
                jail.set_env("WA_PROFILE", "dev");
                jail.set_env("WA_EMAIL_LINK_DEFAULT_REDIRECT_URI", value);

                let error = Config::load().expect_err("only web URLs can be redirected to");
                assert!(
                    error
                        .to_string()
                        .contains("WA_EMAIL_LINK_DEFAULT_REDIRECT_URI"),
                    "{value}: unhelpful error: {error}"
                );
                Ok(())
            });
        }
    }

    #[test]
    fn invalid_port_is_an_error() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_LOGIN_PORT", "not-a-port");

            let error =
                Config::load().expect_err("an unparseable port must not fall back to the default");
            assert!(
                error.to_string().contains("WA_LOGIN_PORT"),
                "unhelpful error: {error}"
            );
            Ok(())
        });
    }

    #[test]
    fn a_trailing_slash_on_the_login_public_url_is_dropped() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test/");

            assert_eq!(Config::load().unwrap().own_origin, "https://login.env.test");
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_to_start_on_localhost_defaults() {
        for (bff_url, login_url, missing) in [
            (None, Some("https://login.test"), "WA_BFF_URL"),
            (Some("https://bff.test"), None, "WA_LOGIN_PUBLIC_URL"),
        ] {
            Jail::expect_with(|jail| {
                if let Some(url) = bff_url {
                    jail.set_env("WA_BFF_URL", url);
                }
                if let Some(url) = login_url {
                    jail.set_env("WA_LOGIN_PUBLIC_URL", url);
                }

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains(missing), "{error}");
                Ok(())
            });
        }
    }

    #[test]
    fn prod_refuses_an_http_email_link_default_redirect_uri() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
            jail.set_env("WA_EMAIL_LINK_DEFAULT_REDIRECT_URI", "http://app.test/home");

            let error = Config::load().unwrap_err().to_string();
            assert!(
                error.contains("WA_EMAIL_LINK_DEFAULT_REDIRECT_URI"),
                "{error}"
            );

            jail.set_env(
                "WA_EMAIL_LINK_DEFAULT_REDIRECT_URI",
                "https://app.test/home",
            );
            Config::load().unwrap();
            Ok(())
        });
    }

    #[test]
    fn prod_starts_once_its_public_urls_are_set() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");

            Config::load().unwrap();
            Ok(())
        });
    }
}
