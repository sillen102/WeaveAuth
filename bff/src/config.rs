use crate::server::login_cookie::LOGIN_COOKIE;
use common::config::{EnvTable, Profile, PublicUrl};
use ipnet::{IpNet, Ipv4Net};
use secrecy::{ExposeSecret, SecretString};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteConfig {
    pub path_prefix: String,
    pub upstream_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The public listener: `/login`, `/callback`, `/logout`, `/logged-out`, `/health` and the
    /// proxied routes.
    pub port: u16,
    /// The internal listener: `/backchannel-logout` and `/internal/revoke`. Must never be
    /// reachable from the internet.
    pub internal_port: u16,
    /// Bff's own public origin; Hydra sends the browser back to `{bff_url}/callback`.
    pub bff_url: String,
    /// Hydra's issuer, as the browser and the tokens' `iss` see it (on the login host).
    /// The browser is sent to `{hydra_public_url}/oauth2/auth` and `/oauth2/sessions/logout`.
    /// Stored without a trailing `/`.
    pub hydra_public_url: String,
    /// Where bff itself reaches Hydra: the token and revocation endpoints and the JWKS.
    /// Stored without a trailing `/`.
    pub hydra_internal_url: String,
    /// The `audience` bff asks for in the authorize request, so the access tokens' `aud` names
    /// it (Hydra only puts a requested audience there). Empty: none is asked for.
    pub hydra_audience: String,
    /// The Hydra OAuth2 client bff is: confidential, authenticating with `client_secret_basic`.
    pub bff_client_id: String,
    /// Never serialized: see [`Config::load`] for where it comes from.
    #[serde(default, skip_serializing)]
    pub bff_client_secret: SecretString,
    /// How long Hydra's refresh tokens live (its `ttl.refresh_token`); a session ends for good
    /// that long after its last refresh. Hydra's default is 30 days.
    pub hydra_refresh_token_ttl_secs: i64,
    /// The `redirect_uri` values `/login` and `/logout` accept, compared as exact strings: where
    /// the browser may be sent once logged in or out. Empty stops startup under `prod`.
    pub redirect_uri_allowlist: Vec<String>,
    /// Where `/logged-out` sends the browser when the logout named no (allowed) destination.
    /// Unset: such a request is refused. Held to the same rules as an allowlist entry.
    pub default_redirect_uri: Option<String>,
    /// The key hooks sends as `Authorization: Bearer <key>` to `/internal/revoke`.
    #[serde(default, skip_serializing)]
    pub internal_api_key: SecretString,
    /// The session cookie's name, an RFC 6265 token. Under https the browser sees it with a
    /// `__Host-` prefix (see [`Config::session_cookie`]).
    pub session_cookie_name: String,
    /// Proxy routes: incoming requests whose path is `path_prefix` or under it are
    /// forwarded to `upstream_url` (prefix stripped) with the session's access
    /// token swapped in as `Authorization: Bearer <token>`, replacing the cookie.
    /// A `path_prefix` of `/` takes every request no other route or endpoint does.
    /// Under `prod` an `upstream_url` must be https or loopback. Only configurable via
    /// the YAML file -- there's no sane env-var shape for a list.
    pub routes: Vec<RouteConfig>,
    /// Origins trusted by the browser-facing routes: allowed to `POST /logout` and to send
    /// state-changing proxied requests (checked against the request's `Origin` header,
    /// falling back to `Referer`) -- without the check any site could submit one on the
    /// victim's behalf -- and allowed to read proxied responses cross-origin, with
    /// credentials (CORS). Bare origins, https under `prod`, same-site as `bff_url`: the `SameSite=Lax`
    /// session cookie is not sent from another site. Bff's own origin is always
    /// trusted on top of these. Unset: none.
    pub trusted_origins: Vec<String>,
    /// Burst size of the auth rate-limit bucket (see `RateLimits`), per client and
    /// replenished over [`RATE_LIMIT_WINDOW_SECS`]. `0` stops startup; above 60000 it
    /// refills like 60000 (the refill interval bottoms out at 1ms). Unset: 10 for prod,
    /// 100 for dev.
    pub rate_limit_max_attempts: u32,
    /// Burst size of the proxy rate-limit bucket, per client, replenished over
    /// [`RATE_LIMIT_WINDOW_SECS`]; every proxied call draws from it. `0` stops
    /// startup. Unset: 600 for prod, 6000 for dev.
    pub rate_limit_proxy_max_attempts: u32,
    /// Reverse proxies (addresses or CIDR ranges) whose `X-Forwarded-For` the
    /// rate limiter believes. Empty: every client is keyed on its peer (IPv6:
    /// its /64), so behind a proxy all of them share the proxy's budget.
    #[serde(deserialize_with = "ip_nets")]
    pub trusted_proxies: Vec<IpNet>,
}

/// The window [`Config::rate_limit_max_attempts`] applies over; the bucket
/// replenishes at `max_attempts / window` per second.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Hydra's default `ttl.refresh_token` (30 days).
const DEFAULT_REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// The longest refresh TTL accepted: ten years, past which it is a typo.
const MAX_REFRESH_TOKEN_TTL_SECS: i64 = 10 * 365 * 24 * 60 * 60;

/// The shortest `internal_api_key` `prod` accepts.
const MIN_PROD_API_KEY_LEN: usize = 16;

/// Prefix that makes a browser refuse a cookie set by a sibling subdomain, or with a `Domain`
/// or a `Path` other than `/` (RFC 6265bis 4.1.3.2).
const HOST_COOKIE_PREFIX: &str = "__Host-";

/// Prefix that makes a browser drop a cookie set without `Secure`.
const SECURE_COOKIE_PREFIX: &str = "__Secure-";

/// Browsers match cookie prefixes case-insensitively.
fn has_prefix(name: &str, prefix: &str) -> bool {
    name.get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

/// The credentials in the committed dev configs (`bff/config.yaml`, `hooks/mise.toml`), which
/// `prod` refuses.
const COMMITTED_DEV_SECRETS: [&str; 2] = ["dev-bff-client-secret", "dev-bff-internal-api-key"];

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8080,
            internal_port: 8082,
            bff_url: "http://localhost:8080".to_string(),
            hydra_public_url: "http://localhost:4444".to_string(),
            hydra_internal_url: "http://localhost:4444".to_string(),
            bff_client_id: "bff".to_string(),
            hydra_audience: "weaveauth".to_string(),
            default_redirect_uri: None,
            bff_client_secret: SecretString::from(String::new()),
            hydra_refresh_token_ttl_secs: DEFAULT_REFRESH_TOKEN_TTL_SECS,
            redirect_uri_allowlist: Vec::new(),
            internal_api_key: SecretString::from(String::new()),
            session_cookie_name: "wa_session".to_string(),
            routes: Vec::new(),
            trusted_origins: Vec::new(),
            rate_limit_max_attempts: 10,
            rate_limit_proxy_max_attempts: 600,
            trusted_proxies: Vec::new(),
        }
    }
}

/// The scalar settings that have an env var; the ones in [`ENV_LISTS`] are lists.
const ENV: EnvTable = &[
    ("WA_PROFILE", "profile"),
    ("WA_BFF_PORT", "port"),
    ("WA_BFF_INTERNAL_PORT", "internal_port"),
    ("WA_BFF_URL", "bff_url"),
    ("WA_HYDRA_PUBLIC_URL", "hydra_public_url"),
    ("WA_HYDRA_INTERNAL_URL", "hydra_internal_url"),
    ("WA_BFF_CLIENT_ID", "bff_client_id"),
    ("WA_HYDRA_AUDIENCE", "hydra_audience"),
    ("WA_DEFAULT_REDIRECT_URI", "default_redirect_uri"),
    ("WA_BFF_CLIENT_SECRET", "bff_client_secret"),
    (
        "WA_HYDRA_REFRESH_TOKEN_TTL_SECS",
        "hydra_refresh_token_ttl_secs",
    ),
    ("WA_BFF_INTERNAL_API_KEY", "internal_api_key"),
    ("WA_SESSION_COOKIE_NAME", "session_cookie_name"),
    ("WA_RATE_LIMIT_MAX_ATTEMPTS", "rate_limit_max_attempts"),
];

const ENV_LISTS: EnvTable = &[
    ("WA_REDIRECT_URI_ALLOWLIST", "redirect_uri_allowlist"),
    ("WA_TRUSTED_ORIGINS", "trusted_origins"),
    ("WA_TRUSTED_PROXIES", "trusted_proxies"),
];

impl Config {
    /// Whether cookies should carry the `Secure` flag -- derived from `bff_url`'s scheme
    /// so plain HTTP local dev keeps working without a separate setting.
    pub(crate) fn secure_cookies(&self) -> bool {
        url::Url::parse(&self.bff_url).is_ok_and(|url| url.scheme() == "https")
    }

    /// The session cookie's name as the browser sees it.
    pub(crate) fn session_cookie(&self) -> String {
        self.cookie_name(&self.session_cookie_name)
    }

    /// The name of the cookie that carries a login from `/login` to `/callback`.
    pub(crate) fn login_cookie(&self) -> String {
        self.cookie_name(LOGIN_COOKIE)
    }

    /// `name`, `__Host-` prefixed under https: `build_cookie` already sends `Secure`, `Path=/`
    /// and no `Domain`, so a sibling subdomain can't plant a cookie of this name.
    fn cookie_name(&self, name: &str) -> String {
        if self.secure_cookies() && !has_prefix(name, HOST_COOKIE_PREFIX) {
            format!("{HOST_COOKIE_PREFIX}{name}")
        } else {
            name.to_string()
        }
    }

    /// Whether `redirect_uri` is one of `redirect_uri_allowlist`, compared as an exact
    /// string: no URL parsing, so no parser difference can read a look-alike host or a
    /// `user@host` trick as an allowed one.
    pub(crate) fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uri_allowlist
            .iter()
            .any(|allowed| allowed == redirect_uri)
    }

    /// Where Hydra sends the browser once it has logged it out.
    pub(crate) fn logged_out_url(&self) -> String {
        format!("{}/logged-out", self.bff_url.trim_end_matches('/'))
    }

    /// Where Hydra sends the browser back to once it has logged in.
    pub(crate) fn callback_url(&self) -> String {
        format!("{}/callback", self.bff_url.trim_end_matches('/'))
    }

    /// Loads config, layering (highest precedence last): built-in defaults,
    /// then the YAML file at `WA_CONFIG_FILE` (default `config.yaml`; a
    /// missing file is not an error, one that exists but can't be read is),
    /// then the `WA_*` env vars in [`ENV`]. Prod refuses to start unless the
    /// browser-facing URLs are https, both Hydra URLs are set (their defaults
    /// are localhost addresses), the allowlist is not empty and the internal
    /// API key is long enough. The client secret and API key are required
    /// under every profile. The rate limits default by profile.
    pub fn load() -> Result<Self, anyhow::Error> {
        common::config::load_dotenv()?;
        let user = common::config::user_settings(true, ENV, ENV_LISTS)?;
        let profile = common::config::profile(&user)?;
        if profile == Profile::Prod {
            for (var, key) in [
                ("WA_HYDRA_PUBLIC_URL", "hydra_public_url"),
                ("WA_HYDRA_INTERNAL_URL", "hydra_internal_url"),
            ] {
                anyhow::ensure!(
                    user.contains(key),
                    "{var} (or `{key}` in the config file) must be set for the prod profile; \
                     its default is a localhost address. Set WA_PROFILE=dev for local development"
                );
            }
        }
        let mut config: Config = common::config::extract(Config::default(), &user)?;
        common::config::require_https_in_prod(
            profile,
            &[
                ("WA_BFF_URL", &config.bff_url, PublicUrl::Base),
                (
                    "WA_HYDRA_PUBLIC_URL",
                    &config.hydra_public_url,
                    PublicUrl::Base,
                ),
            ],
        )?;
        // Every endpoint derived from them appends a path.
        for url in [&mut config.hydra_public_url, &mut config.hydra_internal_url] {
            *url = url.trim_end_matches('/').to_string();
        }
        anyhow::ensure!(
            url::Url::parse(&config.hydra_internal_url)
                .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.has_host()),
            "WA_HYDRA_INTERNAL_URL must be an http(s) URL"
        );
        anyhow::ensure!(
            !config.bff_client_id.is_empty(),
            "WA_BFF_CLIENT_ID must not be empty"
        );
        anyhow::ensure!(
            !config.bff_client_secret.expose_secret().is_empty(),
            "WA_BFF_CLIENT_SECRET (bff_client_secret) must be set"
        );
        let api_key_len = config.internal_api_key.expose_secret().len();
        anyhow::ensure!(
            api_key_len > 0,
            "WA_BFF_INTERNAL_API_KEY (internal_api_key) must be set"
        );
        anyhow::ensure!(
            profile != Profile::Prod || api_key_len >= MIN_PROD_API_KEY_LEN,
            "WA_BFF_INTERNAL_API_KEY must be at least {MIN_PROD_API_KEY_LEN} characters for the \
             prod profile"
        );
        anyhow::ensure!(
            profile != Profile::Prod
                || ![
                    config.bff_client_secret.expose_secret(),
                    config.internal_api_key.expose_secret(),
                ]
                .iter()
                .any(|secret| COMMITTED_DEV_SECRETS.contains(secret)),
            "WA_BFF_CLIENT_SECRET and WA_BFF_INTERNAL_API_KEY must not be the committed dev \
             credentials for the prod profile"
        );
        anyhow::ensure!(
            is_cookie_token(&config.session_cookie_name),
            "WA_SESSION_COOKIE_NAME (session_cookie_name) must be a cookie name: letters, digits \
             and !#$%&'*+-.^_`|~"
        );
        anyhow::ensure!(
            config.session_cookie() != config.login_cookie(),
            "WA_SESSION_COOKIE_NAME (session_cookie_name) must differ from the login cookie \
             {LOGIN_COOKIE:?}"
        );
        anyhow::ensure!(
            config.secure_cookies()
                || !(has_prefix(&config.session_cookie_name, HOST_COOKIE_PREFIX)
                    || has_prefix(&config.session_cookie_name, SECURE_COOKIE_PREFIX)),
            "WA_SESSION_COOKIE_NAME (session_cookie_name) must not start with {HOST_COOKIE_PREFIX:?} \
             or {SECURE_COOKIE_PREFIX:?} while WA_BFF_URL is not https: browsers drop such a cookie"
        );
        check_routes(&config.routes, profile)?;
        anyhow::ensure!(
            (1..=MAX_REFRESH_TOKEN_TTL_SECS).contains(&config.hydra_refresh_token_ttl_secs),
            "WA_HYDRA_REFRESH_TOKEN_TTL_SECS must be between 1 and {MAX_REFRESH_TOKEN_TTL_SECS} seconds"
        );
        anyhow::ensure!(
            config.port != config.internal_port,
            "WA_BFF_PORT and WA_BFF_INTERNAL_PORT must differ"
        );
        check_redirect_uri_allowlist(&config.redirect_uri_allowlist, profile)?;
        if let Some(default) = &config.default_redirect_uri {
            check_redirect_uri_allowlist(std::slice::from_ref(default), profile)?;
        }
        if config.rate_limit_max_attempts == 0 {
            anyhow::bail!(
                "WA_RATE_LIMIT_MAX_ATTEMPTS (rate_limit_max_attempts) must be at least 1"
            );
        }
        if config.rate_limit_proxy_max_attempts == 0 {
            anyhow::bail!("rate_limit_proxy_max_attempts must be at least 1");
        }
        if profile == Profile::Prod
            && let Some(too_wide) = config
                .trusted_proxies
                .iter()
                .find(|net| too_wide_to_trust(net))
        {
            anyhow::bail!(
                "WA_TRUSTED_PROXIES (trusted_proxies) contains {too_wide}, wider than IPv4 /8 or IPv6 /32, which \
                 would let clients in it pick their own rate-limit key; list the proxies' own \
                 addresses"
            );
        }

        // Each one may read credentialed proxy responses (CORS), so https in prod.
        for origin in &mut config.trusted_origins {
            *origin = origin.trim_end_matches('/').to_string();
            // Compared verbatim with the browser's `Origin`, so it must be in its serialized form.
            let is_origin = url::Url::parse(origin)
                .is_ok_and(|url| url.origin().ascii_serialization() == *origin);
            anyhow::ensure!(
                is_origin,
                "WA_TRUSTED_ORIGINS (trusted_origins) entry {origin:?} must be an origin such as \
                 https://app.example.com (scheme and host, lowercase, no path, no default port, no *)"
            );
            anyhow::ensure!(
                profile != Profile::Prod || origin.starts_with("https://"),
                "WA_TRUSTED_ORIGINS (trusted_origins) entry {origin:?} must be https for the prod \
                 profile. Set WA_PROFILE=dev for local development"
            );
        }
        if !user.contains("rate_limit_max_attempts") && profile == Profile::Dev {
            config.rate_limit_max_attempts = 100;
        }
        if !user.contains("rate_limit_proxy_max_attempts") && profile == Profile::Dev {
            config.rate_limit_proxy_max_attempts = 6000;
        }

        Ok(config)
    }
}

/// An RFC 6265 cookie name: an RFC 9110 token.
fn is_cookie_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// The paths bff serves itself; a route on one would clash with it.
const RESERVED_PREFIXES: [&str; 5] = ["/login", "/callback", "/logout", "/logged-out", "/health"];

/// Refuses routes the proxy could not mount (a prefix axum would read as a pattern, or that
/// climbs with `..`, or one of bff's own paths; an upstream that isn't a plain http(s) base URL), two routes on one prefix,
/// and under `prod` an upstream the bearer token would cross in the clear.
fn check_routes(routes: &[RouteConfig], profile: Profile) -> anyhow::Result<()> {
    for (index, route) in routes.iter().enumerate() {
        let prefix = &route.path_prefix;
        anyhow::ensure!(
            is_route_prefix(prefix),
            "`routes` entry {prefix:?}: path_prefix must be `/` or start with `/`, without a \
             trailing `/`, empty or `.`/`..` segments, or any of `{{}}*?#%\\`"
        );
        anyhow::ensure!(
            !RESERVED_PREFIXES.contains(&prefix.as_str()),
            "`routes` entry {prefix:?}: path_prefix is one of bff's own paths ({RESERVED_PREFIXES:?})"
        );
        anyhow::ensure!(
            !routes
                .iter()
                .take(index)
                .any(|other| other.path_prefix == *prefix),
            "`routes` has two entries for path_prefix {prefix:?}"
        );
        let upstream = url::Url::parse(&route.upstream_url).ok().filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.has_host()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        });
        let Some(upstream) = upstream else {
            anyhow::bail!(
                "`routes` entry {prefix:?}: upstream_url must be an http(s) URL with a host and \
                 no user info, query or fragment"
            );
        };
        anyhow::ensure!(
            profile != Profile::Prod || upstream.scheme() == "https" || is_loopback(&upstream),
            "`routes` entry {prefix:?}: upstream_url must be https for the prod profile (or \
             loopback), since the session's bearer token is sent to it. Set WA_PROFILE=dev for \
             local development"
        );
    }
    Ok(())
}

fn is_route_prefix(prefix: &str) -> bool {
    prefix == "/"
        || prefix.strip_prefix('/').is_some_and(|path| {
            path.split('/').all(|segment| {
                !matches!(segment, "" | "." | "..")
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && !b"{}*?#%\\".contains(&byte))
            })
        })
}

fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Refuses an empty allowlist under `prod`, and entries that are not absolute http(s) URLs
/// (https under `prod`) without user info or a fragment: a browser may be redirected to any of
/// them, and `https://trusted.example@evil.example` reads differently to different parsers.
fn check_redirect_uri_allowlist(allowlist: &[String], profile: Profile) -> anyhow::Result<()> {
    anyhow::ensure!(
        profile != Profile::Prod || !allowlist.is_empty(),
        "WA_REDIRECT_URI_ALLOWLIST (redirect_uri_allowlist) must list at least one URL for the \
         prod profile. Set WA_PROFILE=dev for local development"
    );
    for entry in allowlist {
        // The entry goes verbatim into a `Location` header.
        let header_safe = entry.bytes().all(|byte| (0x21..0x7f).contains(&byte));
        let valid = header_safe
            && url::Url::parse(entry).is_ok_and(|url| {
                let scheme_ok = match profile {
                    Profile::Prod => url.scheme() == "https",
                    Profile::Dev => matches!(url.scheme(), "http" | "https"),
                };
                scheme_ok
                    && url.has_host()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none()
            });
        anyhow::ensure!(
            valid,
            "WA_REDIRECT_URI_ALLOWLIST (redirect_uri_allowlist) entry {entry:?} must be an \
             absolute {} URL without user info or a fragment",
            if profile == Profile::Prod {
                "https"
            } else {
                "http(s)"
            }
        );
    }
    Ok(())
}

/// Accepts a bare address as a single-host network, which `IpNet` alone refuses.
fn ip_nets<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<IpNet>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map(v4_mapped_as_v4)
                .map_err(|_| D::Error::custom(format!("not an IP address or CIDR: {entry:?}")))
        })
        .collect()
}

/// The rate limiter compares canonical (IPv4) client addresses, which an
/// `::ffff:a.b.c.d` network would never contain.
fn v4_mapped_as_v4(net: IpNet) -> IpNet {
    match net {
        IpNet::V6(v6) if v6.prefix_len() >= 96 => v6
            .addr()
            .to_ipv4_mapped()
            .and_then(|v4| Ipv4Net::new(v4, v6.prefix_len() - 96).ok())
            .map_or(net, IpNet::V4),
        _ => net,
    }
}

/// Whether `prod` refuses this `trusted_proxies` entry: wider than IPv4 /8 or
/// IPv6 /32. A typo guard against ranges like `0.0.0.0/1`; it doesn't check
/// that a range is private (IPv6's ULA range, `fc00::/7`, is refused too).
fn too_wide_to_trust(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.prefix_len() < 8,
        IpNet::V6(v6) => v6.prefix_len() < 32,
    }
}

#[cfg(test)]
// figment::Jail::expect_with's closure signature is fixed by the crate; its
// Result<(), figment::Error> can't be shrunk from call sites.
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use figment::Jail;

    /// The settings that have no default, set to values `Config::load` accepts under `prod`.
    fn set_required(jail: &mut Jail) {
        set_required_except(jail, "");
    }

    fn set_required_except(jail: &mut Jail, skipped: &str) {
        jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
        for (var, value) in [
            ("WA_BFF_URL", "https://bff.test"),
            ("WA_HYDRA_PUBLIC_URL", "https://login.test"),
            ("WA_HYDRA_INTERNAL_URL", "http://hydra:4444"),
            ("WA_BFF_CLIENT_SECRET", "client-secret"),
            ("WA_BFF_INTERNAL_API_KEY", "an-internal-api-key"),
            ("WA_REDIRECT_URI_ALLOWLIST", "https://app.test/"),
        ] {
            if var != skipped {
                jail.set_env(var, value);
            }
        }
    }

    #[test]
    fn defaults_when_only_the_required_settings_are_set() {
        Jail::expect_with(|jail| {
            set_required(jail);

            let config = Config::load().unwrap();
            assert_eq!(config.port, 8080);
            assert_eq!(config.internal_port, 8082);
            assert_eq!(config.bff_client_id, "bff");
            assert_eq!(config.hydra_audience, "weaveauth");
            assert_eq!(config.default_redirect_uri, None);
            assert_eq!(config.session_cookie_name, "wa_session");
            assert_eq!(config.hydra_refresh_token_ttl_secs, 30 * 24 * 60 * 60);
            assert!(config.routes.is_empty());
            assert!(
                config.trusted_origins.is_empty(),
                "no origin is trusted unless listed"
            );
            assert_eq!(config.rate_limit_max_attempts, 10);
            assert_eq!(config.hydra_internal_url, "http://hydra:4444");
            assert_eq!(config.callback_url(), "https://bff.test/callback");
            assert!(config.secure_cookies());
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
internal_port: 9998
bff_url: "http://file.test:9999"
hydra_public_url: "http://hydra-public.file.test/"
hydra_internal_url: "http://hydra.file.test:4444/"
bff_client_id: file-client
bff_client_secret: file-secret
internal_api_key: file-api-key
hydra_refresh_token_ttl_secs: 3600
redirect_uri_allowlist:
  - "http://app.file.test/"
session_cookie_name: "file_cookie"
routes:
  - path_prefix: /api
    upstream_url: http://upstream.file.test
trusted_origins:
  - "http://file-login.test"
rate_limit_max_attempts: 5
"#,
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 9999);
            assert_eq!(config.internal_port, 9998);
            assert_eq!(config.bff_url, "http://file.test:9999");
            assert_eq!(config.hydra_public_url, "http://hydra-public.file.test");
            assert_eq!(config.hydra_internal_url, "http://hydra.file.test:4444");
            assert_eq!(config.bff_client_id, "file-client");
            assert_eq!(config.bff_client_secret.expose_secret(), "file-secret");
            assert_eq!(config.internal_api_key.expose_secret(), "file-api-key");
            assert_eq!(config.hydra_refresh_token_ttl_secs, 3600);
            assert_eq!(config.redirect_uri_allowlist, ["http://app.file.test/"]);
            assert_eq!(config.session_cookie_name, "file_cookie");
            assert_eq!(
                config.routes,
                vec![RouteConfig {
                    path_prefix: "/api".to_string(),
                    upstream_url: "http://upstream.file.test".to_string(),
                }]
            );
            assert_eq!(config.trusted_origins, ["http://file-login.test"]);
            assert_eq!(config.rate_limit_max_attempts, 5);
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
bff_client_secret: file-secret
internal_api_key: file-api-key
routes:
  - path_prefix: /api
    upstream_url: http://upstream.file.test
"#,
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_BFF_PORT", "7000");
            jail.set_env("WA_BFF_CLIENT_SECRET", "env-secret");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 7000);
            assert_eq!(config.bff_client_secret.expose_secret(), "env-secret");
            // No env var shape for routes -- the file's list always wins.
            assert_eq!(config.routes.len(), 1);
            Ok(())
        });
    }

    #[test]
    fn the_client_secret_and_api_key_are_required_under_every_profile() {
        for (missing, var) in [
            ("WA_BFF_CLIENT_SECRET", "WA_BFF_CLIENT_SECRET"),
            ("WA_BFF_INTERNAL_API_KEY", "WA_BFF_INTERNAL_API_KEY"),
        ] {
            for profile in ["dev", "prod"] {
                Jail::expect_with(|jail| {
                    set_required(jail);
                    jail.set_env("WA_PROFILE", profile);
                    jail.set_env(missing, "");

                    let error = Config::load().unwrap_err().to_string();
                    assert!(error.contains(var), "{profile}: {error}");
                    Ok(())
                });
            }
        }
    }

    #[test]
    fn prod_refuses_a_short_internal_api_key_but_dev_allows_it() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_BFF_INTERNAL_API_KEY", "short");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_BFF_INTERNAL_API_KEY"), "{error}");

            jail.set_env("WA_PROFILE", "dev");
            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn prod_requires_both_hydra_urls_to_be_set() {
        for var in ["WA_HYDRA_PUBLIC_URL", "WA_HYDRA_INTERNAL_URL"] {
            Jail::expect_with(|jail| {
                set_required_except(jail, var);

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains(var), "{error}");

                jail.set_env("WA_PROFILE", "dev");
                assert!(Config::load().is_ok(), "dev falls back to localhost");
                Ok(())
            });
        }
    }

    #[test]
    fn prod_refuses_a_hydra_public_url_that_is_not_https_but_not_an_internal_one() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_HYDRA_PUBLIC_URL", "http://login.test");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_HYDRA_PUBLIC_URL"), "{error}");

            jail.set_env("WA_HYDRA_PUBLIC_URL", "https://login.test");
            jail.set_env("WA_HYDRA_INTERNAL_URL", "http://hydra:4444");
            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn a_hydra_internal_url_that_is_not_http_stops_startup() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_HYDRA_INTERNAL_URL", "hydra:4444");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_HYDRA_INTERNAL_URL"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn trailing_slashes_are_dropped_from_the_hydra_urls() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_HYDRA_PUBLIC_URL", "https://login.test/");
            jail.set_env("WA_HYDRA_INTERNAL_URL", "http://hydra:4444/");

            let config = Config::load().unwrap();
            assert_eq!(config.hydra_public_url, "https://login.test");
            assert_eq!(config.hydra_internal_url, "http://hydra:4444");
            Ok(())
        });
    }

    #[test]
    fn a_refresh_ttl_out_of_range_stops_startup() {
        for ttl in ["0", "-5", "999999999999"] {
            Jail::expect_with(|jail| {
                set_required(jail);
                jail.set_env("WA_HYDRA_REFRESH_TOKEN_TTL_SECS", ttl);

                let error = Config::load().unwrap_err().to_string();
                assert!(
                    error.contains("WA_HYDRA_REFRESH_TOKEN_TTL_SECS"),
                    "{ttl}: {error}"
                );
                Ok(())
            });
        }
    }

    #[test]
    fn both_listeners_cannot_share_a_port() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_BFF_PORT", "9000");
            jail.set_env("WA_BFF_INTERNAL_PORT", "9000");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_BFF_INTERNAL_PORT"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn the_default_redirect_uri_is_held_to_the_allowlist_rules() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_DEFAULT_REDIRECT_URI", "https://app.test/home");
            assert_eq!(
                Config::load().unwrap().default_redirect_uri.as_deref(),
                Some("https://app.test/home")
            );

            for bad in ["http://app.test/", "https://x@evil.test/", "/home"] {
                jail.set_env("WA_DEFAULT_REDIRECT_URI", bad);
                let error = Config::load().unwrap_err().to_string();
                assert!(
                    error.contains("WA_REDIRECT_URI_ALLOWLIST"),
                    "{bad}: {error}"
                );
            }
            Ok(())
        });
    }

    #[test]
    fn the_audience_is_set_by_env() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_HYDRA_AUDIENCE", "api");
            assert_eq!(Config::load().unwrap().hydra_audience, "api");
            Ok(())
        });
    }

    #[test]
    fn the_redirect_uri_allowlist_env_splits_trims_and_drops_empties() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env(
                "WA_REDIRECT_URI_ALLOWLIST",
                "https://a.test/ , https://b.test/x,,",
            );

            assert_eq!(
                Config::load().unwrap().redirect_uri_allowlist,
                ["https://a.test/", "https://b.test/x"]
            );
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_an_empty_allowlist_but_dev_allows_it() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_REDIRECT_URI_ALLOWLIST", "");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_REDIRECT_URI_ALLOWLIST"), "{error}");

            jail.set_env("WA_PROFILE", "dev");
            assert!(Config::load().unwrap().redirect_uri_allowlist.is_empty());
            Ok(())
        });
    }

    #[test]
    fn an_allowlist_entry_that_could_redirect_somewhere_else_stops_startup() {
        for bad in [
            "app.test/",
            "/relative",
            "https://",
            "javascript:alert(1)",
            "https://trusted.test@evil.test/",
            "https://user:pw@app.test/",
            "https://app.test/#frag",
            "ftp://app.test/",
            "https://app.test/caf\u{e9}",
            "https://app.test/a b",
        ] {
            Jail::expect_with(|jail| {
                set_required(jail);
                jail.set_env("WA_PROFILE", "dev");
                jail.set_env(
                    "WA_REDIRECT_URI_ALLOWLIST",
                    format!("https://ok.test/,{bad}"),
                );

                let error = Config::load().unwrap_err().to_string();
                assert!(
                    error.contains("WA_REDIRECT_URI_ALLOWLIST")
                        && error.contains(&format!("{bad:?}")),
                    "{bad}: {error}"
                );
                Ok(())
            });
        }
    }

    #[test]
    fn prod_refuses_an_http_allowlist_entry_but_dev_allows_it() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_REDIRECT_URI_ALLOWLIST", "http://app.test/");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("\"http://app.test/\""), "{error}");

            jail.set_env("WA_PROFILE", "dev");
            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn the_redirect_uri_allowlist_is_matched_as_exact_strings() {
        let config = Config {
            redirect_uri_allowlist: vec!["https://app.test/".into()],
            ..Config::default()
        };

        assert!(config.allows_redirect_uri("https://app.test/"));
        for rejected in [
            "https://app.test",
            "https://app.test/x",
            "https://app.test.evil.test/",
            "https://app.test@evil.test/",
            "https://evil.test/https://app.test/",
            "https://app.test/ ",
            "HTTPS://app.test/",
            "",
        ] {
            assert!(!config.allows_redirect_uri(rejected), "{rejected}");
        }
    }

    #[test]
    fn trusted_origins_are_not_derived_from_anything() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");

            assert!(Config::load().unwrap().trusted_origins.is_empty());
            Ok(())
        });
    }

    #[test]
    fn trusted_origins_env_overrides_file_and_splits_trims_and_drops_empties() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.create_file(
                "config.yaml",
                "trusted_origins:\n  - \"http://file-login.test\"\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_TRUSTED_ORIGINS", "http://a.test , http://b.test,,");

            assert_eq!(
                Config::load().unwrap().trusted_origins,
                ["http://a.test", "http://b.test"]
            );
            Ok(())
        });
    }

    #[test]
    fn a_trusted_origin_that_is_not_a_bare_origin_stops_startup_naming_it() {
        for profile in ["dev", "prod"] {
            for bad in [
                "*",
                "https://app.test/path",
                "app.test",
                "https://app.test?x=1",
                "https://App.test",
                "https://app.test:443",
            ] {
                Jail::expect_with(|jail| {
                    set_required(jail);
                    jail.set_env("WA_PROFILE", profile);
                    jail.set_env("WA_TRUSTED_ORIGINS", format!("https://ok.test,{bad}"));

                    let error = Config::load().unwrap_err().to_string();
                    assert!(
                        error.contains("WA_TRUSTED_ORIGINS") && error.contains(&format!("{bad:?}")),
                        "{profile} {bad}: {error}"
                    );
                    Ok(())
                });
            }
        }
    }

    #[test]
    fn prod_refuses_an_http_trusted_origin_naming_it_but_dev_allows_it() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_TRUSTED_ORIGINS", "https://ok.test,http://app.test");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("\"http://app.test\""), "{error}");

            jail.set_env("WA_PROFILE", "dev");
            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn prod_accepts_https_trusted_origins_and_drops_a_trailing_slash() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env(
                "WA_TRUSTED_ORIGINS",
                "https://app.test/, https://other.test",
            );

            assert_eq!(
                Config::load().unwrap().trusted_origins,
                ["https://app.test", "https://other.test"]
            );
            Ok(())
        });
    }

    #[test]
    fn trusted_proxies_take_cidrs_and_bare_addresses() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_TRUSTED_PROXIES", "10.0.0.0/8, 172.30.0.2, ::1");

            assert_eq!(
                Config::load().unwrap().trusted_proxies,
                vec![
                    "10.0.0.0/8".parse::<IpNet>().unwrap(),
                    "172.30.0.2/32".parse().unwrap(),
                    "::1/128".parse().unwrap(),
                ]
            );
            Ok(())
        });
    }

    #[test]
    fn v4_mapped_trusted_proxies_are_stored_as_v4() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env(
                "WA_TRUSTED_PROXIES",
                "::ffff:172.30.0.2, ::ffff:10.0.0.0/104",
            );

            assert_eq!(
                Config::load().unwrap().trusted_proxies,
                vec![
                    "172.30.0.2/32".parse::<IpNet>().unwrap(),
                    "10.0.0.0/8".parse().unwrap(),
                ]
            );
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_trusted_proxy_ranges_wider_than_v4_8_or_v6_32() {
        Jail::expect_with(|jail| {
            set_required(jail);
            for too_wide in ["10.0.0.0/8, ::/0", "0.0.0.0/1, 128.0.0.0/1", "2001::/31"] {
                jail.set_env("WA_TRUSTED_PROXIES", too_wide);
                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains("WA_TRUSTED_PROXIES"), "{too_wide}: {error}");
            }
            Ok(())
        });
    }

    #[test]
    fn prod_accepts_a_trusted_proxy_range() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_TRUSTED_PROXIES", "10.0.0.0/8, 2001:db8::/32");

            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn dev_allows_trusting_every_address() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_TRUSTED_PROXIES", "0.0.0.0/0");

            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn a_trusted_proxy_that_is_not_an_address_stops_startup() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_TRUSTED_PROXIES", "caddy");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("caddy"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn a_rate_limit_of_zero_stops_startup() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_RATE_LIMIT_MAX_ATTEMPTS", "0");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_RATE_LIMIT_MAX_ATTEMPTS"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn a_proxy_rate_limit_of_zero_stops_startup() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.create_file("config.yaml", "rate_limit_proxy_max_attempts: 0\n")?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("rate_limit_proxy_max_attempts"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn the_proxy_rate_limit_is_set_apart_from_the_auth_one() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.create_file("config.yaml", "rate_limit_proxy_max_attempts: 42\n")?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            assert_eq!(config.rate_limit_proxy_max_attempts, 42);
            assert_eq!(config.rate_limit_max_attempts, 100);
            Ok(())
        });
    }

    #[test]
    fn the_dev_profile_loosens_the_rate_limits() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            assert_eq!(config.rate_limit_max_attempts, 100);
            assert_eq!(config.rate_limit_proxy_max_attempts, 6000);
            Ok(())
        });
    }

    #[test]
    fn explicit_values_win_over_the_dev_profile() {
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_RATE_LIMIT_MAX_ATTEMPTS", "7");

            assert_eq!(Config::load().unwrap().rate_limit_max_attempts, 7);
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_to_start_on_localhost_defaults() {
        for (bff_url, missing) in [
            (None, "WA_BFF_URL"),
            (Some("http://bff.test"), "WA_BFF_URL"),
        ] {
            Jail::expect_with(|jail| {
                set_required(jail);
                match bff_url {
                    Some(url) => jail.set_env("WA_BFF_URL", url),
                    None => jail.set_env("WA_BFF_URL", ""),
                }

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains(missing), "{error}");
                Ok(())
            });
        }
    }

    #[test]
    fn secure_cookies_follow_the_parsed_scheme_of_bff_url() {
        for (bff_url, secure) in [
            ("https://bff.test", true),
            ("HTTPS://bff.test", true),
            (" https://bff.test", true),
            ("http://bff.test", false),
            ("HTTP://bff.test", false),
            ("bff.test", false),
        ] {
            let config = Config {
                bff_url: bff_url.into(),
                ..Config::default()
            };
            assert_eq!(config.secure_cookies(), secure, "{bff_url:?}");
        }
    }

    #[test]
    fn cookie_names_are_host_prefixed_exactly_when_cookies_are_secure() {
        let mut config = Config {
            bff_url: "https://bff.test".into(),
            ..Config::default()
        };
        assert_eq!(config.session_cookie(), "__Host-wa_session");
        assert_eq!(config.login_cookie(), "__Host-wa_login");

        config.session_cookie_name = "__Host-mine".into();
        assert_eq!(config.session_cookie(), "__Host-mine");
        config.session_cookie_name = "__HOST-mine".into();
        assert_eq!(config.session_cookie(), "__HOST-mine");

        config.bff_url = "http://bff.test".into();
        config.session_cookie_name = "wa_session".into();
        assert_eq!(config.session_cookie(), "wa_session");
        assert_eq!(config.login_cookie(), "wa_login");
    }

    #[test]
    fn a_session_cookie_name_that_is_not_an_rfc_6265_token_stops_startup() {
        for name in [
            "",
            "a b",
            "a;b",
            "a=b",
            "a,b",
            "a\"b",
            "caf\u{e9}",
            "a\tb",
            "a(b)",
        ] {
            Jail::expect_with(|jail| {
                set_required(jail);
                jail.set_env("WA_SESSION_COOKIE_NAME", name);

                let error = Config::load().unwrap_err().to_string();
                assert!(
                    error.contains("WA_SESSION_COOKIE_NAME"),
                    "{name:?}: {error}"
                );
                Ok(())
            });
        }
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.set_env("WA_SESSION_COOKIE_NAME", "my-App_session.1");

            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_the_committed_dev_secrets_but_dev_allows_them() {
        for (var, secret) in [
            ("WA_BFF_CLIENT_SECRET", "dev-bff-client-secret"),
            ("WA_BFF_INTERNAL_API_KEY", "dev-bff-internal-api-key"),
        ] {
            Jail::expect_with(|jail| {
                set_required(jail);
                jail.set_env(var, secret);

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains(var), "{error}");
                Ok(())
            });
            Jail::expect_with(|jail| {
                set_required(jail);
                jail.set_env("WA_PROFILE", "dev");
                jail.set_env(var, secret);

                assert!(Config::load().is_ok());
                Ok(())
            });
        }
    }

    /// `Config::load` under `profile` with `routes` (YAML list items) in the config file.
    fn load_with_routes(profile: &str, routes: &str) -> Result<Config, String> {
        let mut loaded = None;
        Jail::expect_with(|jail| {
            set_required(jail);
            jail.create_file("config.yaml", &format!("routes:\n{routes}"))?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", profile);
            loaded = Some(Config::load().map_err(|error| error.to_string()));
            Ok(())
        });
        loaded.unwrap()
    }

    fn route(prefix: &str, upstream: &str) -> String {
        format!("  - path_prefix: \"{prefix}\"\n    upstream_url: \"{upstream}\"\n")
    }

    #[test]
    fn a_route_that_could_not_be_mounted_stops_startup_naming_it() {
        for (prefix, upstream) in [
            ("api", "https://up.test"),
            ("", "https://up.test"),
            ("/api/", "https://up.test"),
            ("/api//v1", "https://up.test"),
            ("/a/{id}", "https://up.test"),
            ("/a/*", "https://up.test"),
            ("/a/../b", "https://up.test"),
            ("/a/./b", "https://up.test"),
            ("/a?x=1", "https://up.test"),
            ("/a b", "https://up.test"),
            ("/api", "up.test"),
            ("/api", "ftp://up.test"),
            ("/api", "https://"),
            ("/api", "https://up.test/?q=1"),
            ("/api", "https://up.test/#frag"),
            ("/api", "https://user:pw@up.test"),
        ] {
            let error = load_with_routes("dev", &route(prefix, upstream)).unwrap_err();
            assert!(error.contains("routes"), "{prefix:?} {upstream:?}: {error}");
        }
    }

    #[test]
    fn a_route_on_one_of_bffs_own_paths_stops_startup() {
        for prefix in RESERVED_PREFIXES {
            let error = load_with_routes("dev", &route(prefix, "https://up.test")).unwrap_err();
            assert!(error.contains("own paths"), "{prefix}: {error}");
        }
        assert!(load_with_routes("dev", &route("/login/x", "https://up.test")).is_ok());
    }

    #[test]
    fn a_session_cookie_name_that_clashes_or_is_dropped_by_browsers_stops_startup() {
        for (name, url) in [
            ("wa_login", "http://bff.test"),
            ("wa_login", "https://bff.test"),
            ("__Host-wa_login", "https://bff.test"),
            ("__Host-mine", "http://bff.test"),
            ("__host-mine", "http://bff.test"),
            ("__Secure-mine", "http://bff.test"),
            ("__SECURE-mine", "http://bff.test"),
        ] {
            Jail::expect_with(|jail| {
                set_required(jail);
                jail.set_env("WA_PROFILE", "dev");
                jail.set_env("WA_BFF_URL", url);
                jail.set_env("WA_SESSION_COOKIE_NAME", name);

                let error = Config::load().unwrap_err().to_string();
                assert!(
                    error.contains("WA_SESSION_COOKIE_NAME"),
                    "{name} {url}: {error}"
                );
                Ok(())
            });
        }
    }

    #[test]
    fn two_routes_cannot_share_a_prefix() {
        let routes = route("/api", "https://a.test") + &route("/api", "https://b.test");

        let error = load_with_routes("dev", &routes).unwrap_err();

        assert!(error.contains("/api"), "{error}");
    }

    #[test]
    fn the_root_and_nested_prefixes_are_valid_routes() {
        let routes = route("/", "https://root.test")
            + &route("/api", "https://api.test/base")
            + &route("/api/v2", "https://v2.test");

        assert_eq!(load_with_routes("dev", &routes).unwrap().routes.len(), 3);
    }

    #[test]
    fn prod_sends_the_bearer_token_only_over_https_or_to_loopback() {
        for upstream in [
            "http://svc.internal:8080",
            "http://10.0.0.5",
            "http://localhost.evil.test",
        ] {
            let error = load_with_routes("prod", &route("/api", upstream)).unwrap_err();
            assert!(error.contains("https"), "{upstream}: {error}");
            assert!(
                load_with_routes("dev", &route("/api", upstream)).is_ok(),
                "{upstream}"
            );
        }
        for upstream in [
            "https://svc.internal",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
        ] {
            assert!(
                load_with_routes("prod", &route("/api", upstream)).is_ok(),
                "{upstream}"
            );
        }
    }

    #[test]
    fn a_secret_is_never_serialized_or_debug_printed() {
        let config = Config {
            bff_client_secret: SecretString::from("super-secret".to_string()),
            internal_api_key: SecretString::from("super-key".to_string()),
            ..Config::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        let debug = format!("{config:?}");

        for text in [json, debug] {
            assert!(!text.contains("super-secret") && !text.contains("super-key"));
        }
    }
}
