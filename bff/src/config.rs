use common::config::{EnvTable, Profile, PublicUrl};
use ipnet::{IpNet, Ipv4Net};
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
    pub port: u16,
    /// Bff's own public origin.
    pub bff_url: String,
    pub backend_url: String,
    /// Login's public origin: the one origin trusted to POST to `/login` and
    /// `/register` unless `trusted_origins` says otherwise.
    pub login_public_url: String,
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
    /// ("login CSRF"). Unset: just `login_public_url`.
    pub trusted_origins: Vec<String>,
    /// Burst size of the auth and docs rate-limit buckets (see `RateLimits`), per
    /// client and replenished over [`RATE_LIMIT_WINDOW_SECS`]. `0` stops startup;
    /// above 60000 it refills like 60000 (the refill interval bottoms out at 1ms).
    /// Argon2 raises the cost of a single guess, but doesn't stop a flood of
    /// guesses or registration spam on its own. Unset: 10 for prod, 100 for dev.
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
    /// Serve the OpenAPI schema (`/openapi.json`) and Scalar UI (`/docs`).
    /// Unset: on for dev only. bff is the internet-facing service, and these
    /// are unauthenticated endpoints describing the auth surface, so a
    /// production deployment has to opt in.
    pub docs_enabled: bool,
}

/// The window [`Config::rate_limit_max_attempts`] applies over; the bucket
/// replenishes at `max_attempts / window` per second.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8080,
            bff_url: "http://localhost:8080".to_string(),
            backend_url: "http://localhost:1983".to_string(),
            login_public_url: "http://localhost:8081".to_string(),
            session_cookie_name: "wa_session".to_string(),
            routes: Vec::new(),
            trusted_origins: vec!["http://localhost:8081".to_string()],
            rate_limit_max_attempts: 10,
            rate_limit_proxy_max_attempts: 600,
            trusted_proxies: Vec::new(),
            docs_enabled: false,
        }
    }
}

/// The scalar settings that have an env var; the ones in [`ENV_LISTS`] are lists.
const ENV: EnvTable = &[
    ("WA_PROFILE", "profile"),
    ("WA_BFF_PORT", "port"),
    ("WA_BFF_URL", "bff_url"),
    ("WA_BACKEND_URL", "backend_url"),
    ("WA_LOGIN_PUBLIC_URL", "login_public_url"),
    ("WA_SESSION_COOKIE_NAME", "session_cookie_name"),
    ("WA_RATE_LIMIT_MAX_ATTEMPTS", "rate_limit_max_attempts"),
    ("WA_DOCS_ENABLED", "docs_enabled"),
];

const ENV_LISTS: EnvTable = &[
    ("WA_TRUSTED_ORIGINS", "trusted_origins"),
    ("WA_TRUSTED_PROXIES", "trusted_proxies"),
];

impl Config {
    /// Whether cookies should carry the `Secure` flag -- derived from `bff_url`
    /// so plain HTTP local dev keeps working without a separate setting.
    pub(crate) fn secure_cookies(&self) -> bool {
        self.bff_url.starts_with("https://")
    }

    /// Loads config, layering (highest precedence last): built-in defaults,
    /// then the YAML file at `WA_CONFIG_FILE` (default `config.yaml`; a
    /// missing file is not an error, one that exists but can't be read is),
    /// then the `WA_*` env vars in [`ENV`]. What the deployer left unset is
    /// then derived: `trusted_origins` from `login_public_url`, and the rate
    /// limit and `docs_enabled` from the profile.
    pub fn load() -> Result<Self, anyhow::Error> {
        common::config::load_dotenv()?;
        let user = common::config::user_settings(true, ENV, ENV_LISTS)?;
        let profile = common::config::profile(&user)?;
        let mut config: Config = common::config::extract(Config::default(), &user)?;
        common::config::require_https_in_prod(
            profile,
            &[
                ("WA_BFF_URL", &config.bff_url, PublicUrl::Base),
                (
                    "WA_LOGIN_PUBLIC_URL",
                    &config.login_public_url,
                    PublicUrl::Origin,
                ),
            ],
        )?;
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
        // Compared verbatim with browsers' `Origin` header, which has no trailing `/`.
        config.login_public_url = config.login_public_url.trim_end_matches('/').to_string();

        if !user.contains("trusted_origins") {
            config.trusted_origins = vec![config.login_public_url.clone()];
        }
        if !user.contains("rate_limit_max_attempts") && profile == Profile::Dev {
            config.rate_limit_max_attempts = 100;
        }
        if !user.contains("rate_limit_proxy_max_attempts") && profile == Profile::Dev {
            config.rate_limit_proxy_max_attempts = 6000;
        }
        if !user.contains("docs_enabled") {
            config.docs_enabled = profile == Profile::Dev;
        }

        Ok(config)
    }
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

    #[test]
    fn defaults_when_no_env_and_no_file() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 8080);
            assert_eq!(config.backend_url, "http://localhost:1983");
            assert_eq!(config.session_cookie_name, "wa_session");
            assert!(config.routes.is_empty());
            assert_eq!(
                config.trusted_origins,
                vec!["https://login.test".to_string()]
            );
            assert_eq!(config.rate_limit_max_attempts, 10);
            assert!(
                !config.docs_enabled,
                "docs must stay off unless explicitly enabled"
            );
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
"#,
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");

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
            jail.set_env("WA_PROFILE", "dev");
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
            jail.set_env("WA_PROFILE", "dev");
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
            jail.set_env("WA_PROFILE", "dev");
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
    fn trusted_proxies_take_cidrs_and_bare_addresses() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_TRUSTED_PROXIES", "10.0.0.0/8, 172.30.0.2, ::1");

            let config = Config::load().unwrap();
            assert_eq!(
                config.trusted_proxies,
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
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env(
                "WA_TRUSTED_PROXIES",
                "::ffff:172.30.0.2, ::ffff:10.0.0.0/104",
            );

            let config = Config::load().unwrap();
            assert_eq!(
                config.trusted_proxies,
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
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
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
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
            jail.set_env("WA_TRUSTED_PROXIES", "10.0.0.0/8, 2001:db8::/32");

            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn dev_allows_trusting_every_address() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_TRUSTED_PROXIES", "0.0.0.0/0");

            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn a_rate_limit_of_zero_stops_startup() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
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
    fn a_trusted_proxy_that_is_not_an_address_stops_startup() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_TRUSTED_PROXIES", "caddy");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("caddy"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn trusted_origins_defaults_to_login_public_url_when_unset() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
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
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");
            jail.set_env("WA_TRUSTED_ORIGINS", "https://other.test");

            let config = Config::load().unwrap();
            assert_eq!(
                config.trusted_origins,
                vec!["https://other.test".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn a_trailing_slash_on_the_login_public_url_is_not_carried_into_trusted_origins() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test/");

            assert_eq!(
                Config::load().unwrap().trusted_origins,
                vec!["https://login.env.test".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_to_start_on_localhost_defaults() {
        for (bff_url, login_url, missing) in [
            (None, Some("https://login.test"), "WA_BFF_URL"),
            (Some("https://bff.test"), None, "WA_LOGIN_PUBLIC_URL"),
            (
                Some("http://bff.test"),
                Some("https://login.test"),
                "WA_BFF_URL",
            ),
        ] {
            Jail::expect_with(|jail| {
                jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
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
    fn prod_starts_once_its_public_urls_are_set() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");

            let config = Config::load().unwrap();
            assert!(config.secure_cookies());
            Ok(())
        });
    }

    #[test]
    fn the_dev_profile_loosens_the_rate_limit_and_turns_docs_on() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            assert_eq!(config.rate_limit_max_attempts, 100);
            assert_eq!(config.rate_limit_proxy_max_attempts, 6000);
            assert!(config.docs_enabled);
            Ok(())
        });
    }

    #[test]
    fn explicit_values_win_over_the_dev_profile() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_RATE_LIMIT_MAX_ATTEMPTS", "7");
            jail.set_env("WA_DOCS_ENABLED", "false");

            let config = Config::load().unwrap();
            assert_eq!(config.rate_limit_max_attempts, 7);
            assert!(!config.docs_enabled);
            Ok(())
        });
    }

    #[test]
    fn trusted_origins_follow_a_login_public_url_set_in_the_file() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "login_public_url: https://login.file.test\n")?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");

            assert_eq!(
                Config::load().unwrap().trusted_origins,
                vec!["https://login.file.test".to_string()]
            );
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
"#,
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_RATE_LIMIT_MAX_ATTEMPTS", "3");

            let config = Config::load().unwrap();
            assert_eq!(config.rate_limit_max_attempts, 3);
            Ok(())
        });
    }
}
