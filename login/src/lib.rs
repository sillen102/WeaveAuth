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
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, header};
use axum::response::IntoResponse;
use axum::routing::get;
use common::rate_limit::{Governor, build_governor};
use config::RATE_LIMIT_WINDOW_SECS;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_governor::GovernorLayer;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

mod challenges;
mod config;
mod hydra;
mod i18n;
mod kratos;
mod pages;
mod proxy;
mod render;
mod throttle;
mod upstream;

pub use config::Config;

/// The `context` names each message or label text may use as `{name}`. For the system tests,
/// which check that Kratos still sends them.
#[doc(hidden)]
pub fn context_names() -> &'static [(&'static str, &'static [&'static str])] {
    i18n::context_names()
}

/// Every (`message` or `label`, Kratos id, key) login translates. For the system tests, which
/// fail when a Kratos upgrade renumbers an id.
#[doc(hidden)]
pub fn translated_ids() -> Vec<(&'static str, u64, &'static str)> {
    i18n::translated_ids()
}

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");

/// Deployer-replaceable page templates. Each extends the compiled-in `layout.html` and fills
/// its `page` block; see `AGENTS.md` in this crate for what they may contain.
const PAGES_GLOB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../templates/pages/*.html");

/// Deployer-replaceable provider logos, one image per provider id (`google.webp`), served at
/// `/providers`.
const PROVIDERS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../templates/providers");

/// Deployer-replaceable translations of what Kratos says, one `<language>.json` each.
const LOCALES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../templates/locales");

/// Opened directly, a deployer's SVG or HTML must not run as this origin.
const PROVIDER_LOGO_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

/// A day: a deployer's replaced logo shows up for returning visitors within it.
const PROVIDER_LOGO_CACHE_CONTROL: &str = "public, max-age=86400";

/// The script that binds Kratos' passkey triggers; compiled in so no deployer file can replace it.
const UI_JS: &str = include_str!("ui.js");

/// Forms are small; a passkey response is a few kilobytes.
const MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) own_origin: url::Url,
    pub(crate) kratos: kratos::Kratos,
    pub(crate) hydra: hydra::Hydra,
    /// The proxy's client: no redirects (the browser follows them), bounded in time.
    pub(crate) http: reqwest::Client,
    pub(crate) renderer: Arc<render::Renderer>,
    pub(crate) catalog: Arc<i18n::Catalog>,
    providers_dir: PathBuf,
    pub(crate) throttle: Arc<throttle::LoginThrottle>,
    limits: Limits,
}

/// Per-client buckets: submissions to Kratos, and everything else.
#[derive(Clone)]
struct Limits {
    submit: Governor,
    general: Governor,
}

impl AppState {
    fn new(
        config: Config,
        pages_glob: &str,
        providers_dir: PathBuf,
        locales_dir: &Path,
    ) -> anyhow::Result<Self> {
        let catalog = Arc::new(i18n::Catalog::load(locales_dir, &config.default_locale)?);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(15))
            .build()?;
        let kratos = kratos::Kratos::new(http.clone(), &config.kratos_public_url)?;
        let limits = Limits {
            submit: build_governor(
                config.rate_limit_max_attempts,
                RATE_LIMIT_WINDOW_SECS,
                &config.trusted_proxies,
            )?,
            general: build_governor(
                config.rate_limit_proxy_max_attempts,
                RATE_LIMIT_WINDOW_SECS,
                &config.trusted_proxies,
            )?,
        };
        Ok(Self {
            own_origin: url::Url::parse(&config.own_origin).map_err(|error| {
                anyhow::anyhow!(
                    "invalid WA_LOGIN_PUBLIC_URL {:?}: {error}",
                    config.own_origin
                )
            })?,
            hydra: hydra::Hydra::new(http.clone(), &config.hydra_admin_url)?,
            renderer: Arc::new(render::Renderer::new(
                pages_glob,
                &config.own_origin,
                &kratos.origin(),
                &providers_dir,
                catalog.clone(),
            )?),
            catalog,
            providers_dir,
            throttle: Arc::default(),
            kratos,
            http,
            limits,
            config: Arc::new(config),
        })
    }

    /// Forgets what has expired: clients whose bucket refilled, identifiers nobody tried lately.
    fn sweep(&self) {
        for governor in [&self.limits.submit, &self.limits.general] {
            governor.limiter().retain_recent();
            governor.limiter().shrink_to_fit();
        }
        self.throttle.sweep(Instant::now());
    }
}

/// The router with the deployer's page templates from `templates/pages`.
pub fn app(config: Config) -> anyhow::Result<Router> {
    app_with_templates(config, PAGES_GLOB, PROVIDERS_DIR)
}

/// Like [`app`], loading page templates from `pages_glob` and provider logos from
/// `providers_dir` instead.
pub fn app_with_templates(
    config: Config,
    pages_glob: &str,
    providers_dir: impl Into<PathBuf>,
) -> anyhow::Result<Router> {
    app_with_locales(config, pages_glob, providers_dir, LOCALES_DIR)
}

/// Like [`app_with_templates`], loading translations from `locales_dir` as well.
pub fn app_with_locales(
    config: Config,
    pages_glob: &str,
    providers_dir: impl Into<PathBuf>,
    locales_dir: impl AsRef<Path>,
) -> anyhow::Result<Router> {
    Ok(router(AppState::new(
        config,
        pages_glob,
        providers_dir.into(),
        locales_dir.as_ref(),
    )?))
}

/// Like [`app`], loading page templates from `pages_glob` instead.
pub fn app_with_pages(config: Config, pages_glob: &str) -> anyhow::Result<Router> {
    app_with_templates(config, pages_glob, PROVIDERS_DIR)
}

/// Binds `config.port` and serves until the process ends.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let addr = ("0.0.0.0", config.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on 0.0.0.0:{}", config.port);

    let state = AppState::new(
        config,
        PAGES_GLOB,
        PathBuf::from(PROVIDERS_DIR),
        Path::new(LOCALES_DIR),
    )?;
    let sweeper = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(
            common::config::EXPIRY_SWEEP_INTERVAL_SECS,
        ));
        loop {
            interval.tick().await;
            sweeper.sweep();
        }
    });

    // with_connect_info: the rate limiter keys on the peer address.
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    let general = || GovernorLayer::new(state.limits.general.clone());

    let pages = Router::new()
        .route("/login", get(pages::login_page))
        .route("/registration", get(pages::registration_page))
        .route("/recovery", get(pages::recovery_page))
        .route("/verification", get(pages::verification_page))
        .route("/settings", get(pages::settings_page))
        .route("/error", get(pages::error_page))
        .route("/logout", get(challenges::logout))
        .route("/consent", get(challenges::consent))
        .layer(general());

    // Browser flows only ever use GET and POST. Submissions have the smaller bucket.
    let submissions =
        axum::routing::post(proxy::proxy).layer(GovernorLayer::new(state.limits.submit.clone()));
    let to_kratos = Router::new()
        .route(
            "/self-service/{*rest}",
            get(proxy::proxy).layer(general()).merge(submissions),
        )
        .route(
            "/.well-known/ory/{*rest}",
            get(proxy::proxy).layer(general()),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    Router::new()
        .merge(pages)
        .merge(to_kratos)
        .route("/health", get(|| async { "ok" }))
        .route("/ui.js", get(ui_js))
        .nest(
            "/static",
            Router::new()
                .fallback_service(ServeDir::new(STATIC_DIR))
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                // Revalidate (it has `Last-Modified`), so a changed stylesheet isn't served stale.
                .layer(SetResponseHeaderLayer::overriding(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("no-cache"),
                )),
        )
        .nest(
            "/providers",
            Router::new()
                .fallback_service(
                    ServeDir::new(&state.providers_dir).append_index_html_on_directories(false),
                )
                .layer(SetResponseHeaderLayer::overriding(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static(PROVIDER_LOGO_CSP),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                // Not on a 404, which would keep a logo that is added later hidden for a day.
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CACHE_CONTROL,
                    |response: &axum::response::Response| {
                        response
                            .status()
                            .is_success()
                            .then(|| HeaderValue::from_static(PROVIDER_LOGO_CACHE_CONTROL))
                    },
                )),
        )
        .with_state(state)
}

async fn ui_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        UI_JS,
    )
}
