use common::config::{EnvTable, Profile, PublicUrl};
use ipnet::{IpNet, Ipv4Net};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::env;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub bff_url: String,
    /// This service's own browser-facing origin (`WA_LOGIN_PUBLIC_URL`), stored without a
    /// trailing `/`. Kratos and Hydra are on this host too, behind the reverse proxy.
    pub own_origin: String,
    /// Where a page opened without a `login_challenge` or a flow sends the browser back to
    /// (through bff's `/login`), when it carries no `redirect_uri` of its own. Must be on bff's
    /// allowlist. Unset: such a page is an error.
    pub default_redirect_uri: Option<String>,
    /// The language (a file in `templates/locales`) used when the request names none that is
    /// available, and for every text the requested language lacks.
    pub default_locale: String,
    /// Kratos' public API, server to server: where flows are fetched from and what the
    /// `/self-service/*` and `/.well-known/ory/*` proxy forwards to.
    pub kratos_public_url: String,
    /// Hydra's admin API: logout and consent challenges are accepted here. Never browser-facing.
    pub hydra_admin_url: String,
    /// The one Hydra client `/consent` auto-accepts for.
    pub bff_client_id: String,
    /// Name of Kratos' session cookie; must equal `session.cookie.name` in Kratos' config. A
    /// login that doesn't set it isn't a success for the throttle.
    pub kratos_session_cookie: String,
    /// Burst size of the bucket on every submission to Kratos (a `POST` through the proxy), per
    /// client and replenished over [`RATE_LIMIT_WINDOW_SECS`]. `0` stops startup. Unset: 10 for
    /// prod, 100 for dev.
    pub rate_limit_max_attempts: u32,
    /// Burst size of the bucket on everything else (pages, flow starts, `GET`s through the
    /// proxy), per client. `0` stops startup. Code-only; 600 for prod, 6000 for dev.
    pub rate_limit_proxy_max_attempts: u32,
    /// Reverse proxies (addresses or CIDR ranges) whose `X-Forwarded-For` the rate limiter
    /// believes. Empty: every client is keyed on its peer, so behind a proxy all of them share
    /// the proxy's budget.
    #[serde(deserialize_with = "ip_nets")]
    pub trusted_proxies: Vec<IpNet>,
}

/// The window the rate-limit buckets replenish over.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8081,
            bff_url: "http://localhost:8080".to_string(),
            own_origin: "http://localhost:8081".to_string(),
            default_redirect_uri: None,
            default_locale: "en".to_string(),
            kratos_public_url: "http://localhost:4433".to_string(),
            hydra_admin_url: "http://localhost:4445".to_string(),
            bff_client_id: "bff".to_string(),
            kratos_session_cookie: "ory_kratos_session".to_string(),
            rate_limit_max_attempts: 10,
            rate_limit_proxy_max_attempts: 600,
            trusted_proxies: Vec::new(),
        }
    }
}

const ENV: EnvTable = &[
    ("WA_PROFILE", "profile"),
    ("WA_BFF_URL", "bff_url"),
    ("WA_LOGIN_PUBLIC_URL", "own_origin"),
    ("WA_DEFAULT_REDIRECT_URI", "default_redirect_uri"),
    ("WA_DEFAULT_LOCALE", "default_locale"),
    ("WA_KRATOS_PUBLIC_URL", "kratos_public_url"),
    ("WA_HYDRA_ADMIN_URL", "hydra_admin_url"),
    ("WA_BFF_CLIENT_ID", "bff_client_id"),
    ("WA_KRATOS_SESSION_COOKIE", "kratos_session_cookie"),
    ("WA_RATE_LIMIT_MAX_ATTEMPTS", "rate_limit_max_attempts"),
];

const ENV_LISTS: EnvTable = &[("WA_TRUSTED_PROXIES", "trusted_proxies")];

impl Config {
    /// Loads config from the env vars in [`ENV`] and [`ENV_LISTS`] plus `WA_LOGIN_PORT`, falling
    /// back to defaults for anything unset (an empty `WA_DEFAULT_REDIRECT_URI` counts as unset).
    /// A value that is set but invalid is an error: silently using the defaults would point the
    /// login page at localhost. Under the prod profile (`WA_PROFILE`, the default) `WA_BFF_URL`
    /// and `WA_DEFAULT_REDIRECT_URI` must be https, `WA_LOGIN_PUBLIC_URL` an https origin, and
    /// `WA_TRUSTED_PROXIES` no wider than IPv4 /8 or IPv6 /32, and `WA_KRATOS_PUBLIC_URL` and
    /// `WA_HYDRA_ADMIN_URL` (internal, so http is fine) must be set rather than left at their
    /// localhost defaults.
    pub fn load() -> anyhow::Result<Self> {
        // `WA_LOGIN_PORT` is applied by hand below, so its error names the variable.
        let user = common::config::user_settings(false, ENV, ENV_LISTS)?;
        let mut config: Config = common::config::extract(Config::default(), &user)
            .map_err(|error| anyhow::anyhow!("invalid login configuration: {error}"))?;
        let profile = common::config::profile(&user)?;
        if profile == Profile::Prod {
            for (var, key) in [
                ("WA_KRATOS_PUBLIC_URL", "kratos_public_url"),
                ("WA_HYDRA_ADMIN_URL", "hydra_admin_url"),
            ] {
                if !user.contains(key) {
                    anyhow::bail!(
                        "{var} must be set for the prod profile; its default is a localhost address. Set WA_PROFILE=dev for local development"
                    );
                }
            }
        }
        common::config::require_https_in_prod(
            profile,
            &[
                ("WA_BFF_URL", &config.bff_url, PublicUrl::Base),
                ("WA_LOGIN_PUBLIC_URL", &config.own_origin, PublicUrl::Origin),
            ],
        )?;
        // Every URL derived from these appends a path.
        for url in [
            &mut config.own_origin,
            &mut config.bff_url,
            &mut config.kratos_public_url,
            &mut config.hydra_admin_url,
        ] {
            *url = url.trim_end_matches('/').to_string();
        }

        if let Ok(raw) = env::var("WA_LOGIN_PORT") {
            config.port = raw
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid WA_LOGIN_PORT {raw:?}: {error}"))?;
        }

        config.default_redirect_uri = config
            .default_redirect_uri
            .take()
            .filter(|raw| !raw.is_empty());
        if let Some(raw) = &config.default_redirect_uri {
            let url = url::Url::parse(raw).map_err(|error| {
                anyhow::anyhow!("invalid WA_DEFAULT_REDIRECT_URI {raw:?}: {error}")
            })?;
            if !matches!(url.scheme(), "http" | "https") {
                anyhow::bail!("invalid WA_DEFAULT_REDIRECT_URI {raw:?}: not an http(s) URL");
            }
            common::config::require_https_in_prod(
                profile,
                &[("WA_DEFAULT_REDIRECT_URI", raw, PublicUrl::Base)],
            )?;
        }

        let cookie = &config.kratos_session_cookie;
        if cookie.is_empty() || cookie.contains(|c: char| c.is_whitespace() || c == '=' || c == ';')
        {
            anyhow::bail!(
                "WA_KRATOS_SESSION_COOKIE (kratos_session_cookie) must be a cookie name: \
                 not empty, no whitespace, `=` or `;`"
            );
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
                "WA_TRUSTED_PROXIES (trusted_proxies) contains {too_wide}, wider than IPv4 /8 or \
                 IPv6 /32, which would let clients in it pick their own rate-limit key; list the \
                 proxies' own addresses"
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

/// Whether `prod` refuses this `trusted_proxies` entry: wider than IPv4 /8 or IPv6 /32. A typo
/// guard against ranges like `0.0.0.0/1`.
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
    fn defaults_when_no_env_set() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            let config = Config::load().unwrap();
            assert_eq!(config.port, 8081);
            assert_eq!(config.bff_url, "http://localhost:8080");
            assert_eq!(config.kratos_public_url, "http://localhost:4433");
            assert_eq!(config.hydra_admin_url, "http://localhost:4445");
            assert_eq!(config.bff_client_id, "bff");
            assert_eq!(config.default_redirect_uri, None);
            assert_eq!(config.default_locale, "en");
            assert_eq!(config.kratos_session_cookie, "ory_kratos_session");
            Ok(())
        });
    }

    #[test]
    fn env_vars_override_defaults() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_LOGIN_PORT", "9999");
            jail.set_env("WA_BFF_URL", "http://bff.env.test/");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test/");
            jail.set_env("WA_KRATOS_PUBLIC_URL", "http://kratos:4433/");
            jail.set_env("WA_HYDRA_ADMIN_URL", "http://hydra:4445/");
            jail.set_env("WA_BFF_CLIENT_ID", "other-client");
            jail.set_env("WA_RATE_LIMIT_MAX_ATTEMPTS", "7");
            jail.set_env("WA_KRATOS_SESSION_COOKIE", "custom_session");
            jail.set_env("WA_TRUSTED_PROXIES", "10.0.0.0/8, 172.30.0.2");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 9999);
            assert_eq!(config.bff_url, "http://bff.env.test");
            // Every derived URL appends a path.
            assert_eq!(config.own_origin, "https://login.env.test");
            assert_eq!(config.kratos_public_url, "http://kratos:4433");
            assert_eq!(config.hydra_admin_url, "http://hydra:4445");
            assert_eq!(config.bff_client_id, "other-client");
            assert_eq!(config.rate_limit_max_attempts, 7);
            assert_eq!(config.kratos_session_cookie, "custom_session");
            assert_eq!(
                config.trusted_proxies,
                vec![
                    "10.0.0.0/8".parse::<IpNet>().unwrap(),
                    "172.30.0.2/32".parse::<IpNet>().unwrap()
                ]
            );
            Ok(())
        });
    }

    #[test]
    fn a_malformed_kratos_session_cookie_name_is_refused() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            for bad in ["", "a b", "a=b", "a;b"] {
                jail.set_env("WA_KRATOS_SESSION_COOKIE", bad);
                let error = Config::load().unwrap_err().to_string();
                assert!(
                    error.contains("WA_KRATOS_SESSION_COOKIE"),
                    "{bad:?}: {error}"
                );
            }
            jail.set_env("WA_KRATOS_SESSION_COOKIE", "ory_kratos_session");
            Config::load().unwrap();
            Ok(())
        });
    }

    #[test]
    fn the_rate_limits_default_by_profile_unless_set() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            let dev = Config::load().unwrap();
            assert_eq!(
                (
                    dev.rate_limit_max_attempts,
                    dev.rate_limit_proxy_max_attempts
                ),
                (100, 6000)
            );

            jail.set_env("WA_RATE_LIMIT_MAX_ATTEMPTS", "5");
            assert_eq!(Config::load().unwrap().rate_limit_max_attempts, 5);

            jail.set_env("WA_RATE_LIMIT_MAX_ATTEMPTS", "0");
            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_RATE_LIMIT_MAX_ATTEMPTS"), "{error}");

            jail.set_env("WA_PROFILE", "prod");
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
            jail.set_env("WA_RATE_LIMIT_MAX_ATTEMPTS", "10");
            set_internal_urls(jail);
            let prod = Config::load().unwrap();
            assert_eq!(prod.rate_limit_proxy_max_attempts, 600);
            Ok(())
        });
    }

    #[test]
    fn the_default_locale_is_read_from_the_environment() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_DEFAULT_LOCALE", "sv");
            assert_eq!(Config::load().unwrap().default_locale, "sv");
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

            jail.set_env("WA_DEFAULT_REDIRECT_URI", "");
            assert_eq!(Config::load().unwrap().default_redirect_uri, None);

            for bad in ["/downstream", "javascript:alert(1)", "mailto:a@example.com"] {
                jail.set_env("WA_DEFAULT_REDIRECT_URI", bad);
                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains("WA_DEFAULT_REDIRECT_URI"), "{bad}: {error}");
            }

            jail.set_env("WA_PROFILE", "prod");
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
            set_internal_urls(jail);
            jail.set_env("WA_DEFAULT_REDIRECT_URI", "http://app.test/home");
            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_DEFAULT_REDIRECT_URI"), "{error}");

            jail.set_env("WA_DEFAULT_REDIRECT_URI", "https://app.test/home");
            Config::load().unwrap();
            Ok(())
        });
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

    fn set_internal_urls(jail: &mut Jail) {
        jail.set_env("WA_KRATOS_PUBLIC_URL", "http://kratos:4433");
        jail.set_env("WA_HYDRA_ADMIN_URL", "http://hydra:4445");
    }

    #[test]
    fn prod_refuses_to_start_on_localhost_defaults() {
        for (bff_url, login_url, internal, missing) in [
            (None, Some("https://login.test"), true, "WA_BFF_URL"),
            (Some("https://bff.test"), None, true, "WA_LOGIN_PUBLIC_URL"),
        ] {
            Jail::expect_with(|jail| {
                if let Some(url) = bff_url {
                    jail.set_env("WA_BFF_URL", url);
                }
                if let Some(url) = login_url {
                    jail.set_env("WA_LOGIN_PUBLIC_URL", url);
                }
                if internal {
                    set_internal_urls(jail);
                }

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains(missing), "{error}");
                Ok(())
            });
        }
    }

    #[test]
    fn prod_refuses_to_start_without_its_internal_urls() {
        for (var, other_var, other) in [
            (
                "WA_KRATOS_PUBLIC_URL",
                "WA_HYDRA_ADMIN_URL",
                "http://hydra:4445",
            ),
            (
                "WA_HYDRA_ADMIN_URL",
                "WA_KRATOS_PUBLIC_URL",
                "http://kratos:4433",
            ),
        ] {
            Jail::expect_with(|jail| {
                jail.set_env("WA_BFF_URL", "https://bff.test");
                jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
                jail.set_env(other_var, other);

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains(var), "{error}");

                jail.set_env("WA_PROFILE", "dev");
                Config::load().unwrap();
                Ok(())
            });
        }
    }

    #[test]
    fn prod_starts_once_its_urls_are_set() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
            set_internal_urls(jail);

            Config::load().unwrap();
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_trusted_proxy_ranges_wider_than_v4_8_or_v6_32() {
        for wide in ["0.0.0.0/1", "::/0", "2001::/16"] {
            Jail::expect_with(|jail| {
                jail.set_env("WA_BFF_URL", "https://bff.test");
                jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
                jail.set_env("WA_TRUSTED_PROXIES", wide);
                set_internal_urls(jail);

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains("WA_TRUSTED_PROXIES"), "{wide}: {error}");

                jail.set_env("WA_PROFILE", "dev");
                Config::load().unwrap();
                Ok(())
            });
        }
    }

    #[test]
    fn v4_mapped_trusted_proxies_are_stored_as_v4() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_TRUSTED_PROXIES", "::ffff:10.0.0.0/104");

            let config = Config::load().unwrap();
            assert_eq!(
                config.trusted_proxies,
                vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]
            );
            Ok(())
        });
    }

    #[test]
    fn a_trusted_proxy_that_is_not_an_address_is_an_error() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_TRUSTED_PROXIES", "proxy.internal");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("proxy.internal"), "{error}");
            Ok(())
        });
    }
}
