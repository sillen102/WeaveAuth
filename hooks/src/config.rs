use common::config::{EnvTable, Profile};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Deployer-facing settings. Everything is internal: hooks is never reachable
/// from the internet, only from Kratos, Hydra and the deployer's network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    /// Every route except `/health` requires `Authorization: Bearer <this>`.
    /// Kratos and Hydra send it via their web hook `auth: api_key`. Empty is
    /// refused when serving (see [`Config::require_api_keys`]).
    #[serde(default, skip_serializing)]
    pub hooks_api_key: SecretString,
    /// Kratos admin API, e.g. `http://kratos:4434`. No trailing `/`.
    pub kratos_admin_url: String,
    /// Hydra admin API, e.g. `http://hydra:4445`. No trailing `/`.
    pub hydra_admin_url: String,
    /// bff's internal listener, which serves `/internal/revoke`.
    pub bff_internal_url: String,
    /// What hooks presents to bff's internal listener.
    #[serde(default, skip_serializing)]
    pub bff_internal_api_key: SecretString,
    /// Receives `{user_id, email, email_verified, fields}` for every new identity. An error
    /// fails the registration.
    #[serde(default)]
    pub registration_handler: Option<WebhookConfig>,
    /// Asked for extra access token claims on every token mint (code and
    /// refresh grants). `None`: no extra claims.
    #[serde(default)]
    pub login_claims_handler: Option<WebhookConfig>,
    /// Receives `{user_id, email}` when an identity verifies its email address. The deployer
    /// decides what to do (a welcome mail, a queue message). `None`: nobody is told.
    #[serde(default)]
    pub verification_handler: Option<WebhookConfig>,
    /// Per Kratos OIDC provider id (e.g. `google`): extra API calls made with
    /// the provider's access token on a user's first sign-up, for claims the
    /// id_token doesn't carry. Called concurrently; on a field-name clash the
    /// later entry wins.
    #[serde(default)]
    pub profile_apis: HashMap<String, Vec<ProfileApiConfig>>,
    /// The token hook refuses to mint tokens for an identity whose email isn't verified, so the
    /// sign-in path can't be walked around Kratos' verification step. Turn off only when the
    /// deployment lets unverified identities sign in on purpose.
    pub require_verified_email: bool,
    /// Cap on how long any request is served, so a stuck upstream can't pin it.
    pub request_timeout_secs: u64,
    /// Cap on each call to Kratos, Hydra or bff.
    pub upstream_timeout_secs: u64,
}

/// POSTs the hook's JSON to `url`. Must be `https://` unless the host is
/// loopback: the payload carries the user's email, fields or password.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    /// A hung endpoint must not hold the request open indefinitely.
    #[serde(default = "default_webhook_timeout_secs")]
    pub timeout_secs: u64,
    /// Sent as `Authorization: Bearer <this>` when set, so the endpoint can tell hooks from
    /// anything else on the network. Never echoed in errors or logs.
    #[serde(default, skip_serializing)]
    pub bearer_token: Option<SecretString>,
}

fn default_webhook_timeout_secs() -> u64 {
    10
}

/// One profile API call. Its fields reach the registration handler together
/// with the identity's other traits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileApiConfig {
    /// GET with `Authorization: Bearer <access token>`. Must be `https://`
    /// unless the host is loopback.
    pub url: String,
    /// `field name -> JSON pointer` (RFC 6901, e.g. `/phoneNumbers/0/value`)
    /// into the JSON response.
    pub claims: HashMap<String, String>,
    /// OAuth scope the access token needs for this call. Checked against the
    /// scopes the registration request reports as granted: if the user
    /// declined it the call is skipped, or, for a `required` entry, the
    /// registration fails. A request that reports no scopes counts as having
    /// granted everything asked for (RFC 6749 section 5.1). Unset: always called.
    #[serde(default)]
    pub scope: Option<String>,
    /// Whether a failed call (or a pointer that finds nothing) fails the
    /// registration. When false, a failed call is logged and its fields are
    /// left out, and a pointer that finds nothing leaves just that field out.
    #[serde(default)]
    pub required: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 1983,
            hooks_api_key: SecretString::from(String::new()),
            kratos_admin_url: "http://localhost:4434".to_string(),
            hydra_admin_url: "http://localhost:4445".to_string(),
            bff_internal_url: "http://localhost:8082".to_string(),
            bff_internal_api_key: SecretString::from(String::new()),
            registration_handler: None,
            login_claims_handler: None,
            verification_handler: None,
            profile_apis: HashMap::new(),
            require_verified_email: true,
            request_timeout_secs: 30,
            upstream_timeout_secs: 10,
        }
    }
}

const MIN_PROD_API_KEY_LEN: usize = 16;

const ENV: EnvTable = &[
    ("WA_PROFILE", "profile"),
    ("WA_HOOKS_PORT", "port"),
    ("WA_HOOKS_API_KEY", "hooks_api_key"),
    ("WA_KRATOS_ADMIN_URL", "kratos_admin_url"),
    ("WA_HYDRA_ADMIN_URL", "hydra_admin_url"),
    ("WA_BFF_INTERNAL_URL", "bff_internal_url"),
    ("WA_BFF_INTERNAL_API_KEY", "bff_internal_api_key"),
    ("WA_REQUIRE_VERIFIED_EMAIL", "require_verified_email"),
];

impl Config {
    /// Loads config, layering (highest precedence last): built-in defaults,
    /// then the YAML file at `WA_CONFIG_FILE` (default `config.yaml`; a
    /// missing file is not an error, one that exists but can't be read is),
    /// then the `WA_*` env vars in [`ENV`]. The three upstream URLs are
    /// internal, so http is fine, but the prod profile refuses their localhost
    /// defaults: they must be set. Each is stored without a trailing `/`.
    pub fn load() -> Result<Self, anyhow::Error> {
        common::config::load_dotenv()?;
        let user = common::config::user_settings(true, ENV, &[])?;
        let profile = common::config::profile(&user)?;
        if profile == Profile::Prod {
            for (var, key) in [
                ("WA_KRATOS_ADMIN_URL", "kratos_admin_url"),
                ("WA_HYDRA_ADMIN_URL", "hydra_admin_url"),
                ("WA_BFF_INTERNAL_URL", "bff_internal_url"),
            ] {
                if !user.contains(key) {
                    anyhow::bail!(
                        "{var} (or `{key}` in the config file) must be set for the prod profile; its default is a localhost address. Set WA_PROFILE=dev for local development"
                    );
                }
            }
        }
        let mut config: Config = common::config::extract(Config::default(), &user)?;
        // An unset key is left to `require_api_keys`: `import` runs without one.
        let key_len = config.hooks_api_key.expose_secret().len();
        anyhow::ensure!(
            profile != Profile::Prod || key_len == 0 || key_len >= MIN_PROD_API_KEY_LEN,
            "WA_HOOKS_API_KEY must be at least {MIN_PROD_API_KEY_LEN} characters for the prod profile"
        );
        config.validate()?;
        Ok(config)
    }

    fn validate(&mut self) -> anyhow::Result<()> {
        for (var, url) in [
            ("WA_KRATOS_ADMIN_URL", &mut self.kratos_admin_url),
            ("WA_HYDRA_ADMIN_URL", &mut self.hydra_admin_url),
            ("WA_BFF_INTERNAL_URL", &mut self.bff_internal_url),
        ] {
            let parsed = url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid {var}: {e}"))?;
            // The value isn't echoed: it may carry credentials.
            anyhow::ensure!(
                matches!(parsed.scheme(), "http" | "https") && parsed.host().is_some(),
                "{var} must be an http(s) URL"
            );
            *url = url.trim_end_matches('/').to_string();
        }
        for (what, handler) in [
            ("registration_handler", &self.registration_handler),
            ("login_claims_handler", &self.login_claims_handler),
            ("verification_handler", &self.verification_handler),
        ] {
            if let Some(handler) = handler {
                require_https_or_loopback(what, &handler.url)?;
            }
        }
        for api in self.profile_apis.values().flatten() {
            require_https_or_loopback("profile api url", &api.url)?;
        }
        anyhow::ensure!(
            self.request_timeout_secs > 0 && self.upstream_timeout_secs > 0,
            "timeouts must be positive"
        );
        // Revoking takes a Kratos call and then others, each capped at the upstream timeout;
        // a longer one would let the request timeout cancel steps that were still waiting.
        anyhow::ensure!(
            self.upstream_timeout_secs.saturating_mul(2) < self.request_timeout_secs,
            "upstream_timeout_secs must be less than half of request_timeout_secs"
        );
        for (what, handler) in [
            ("registration_handler", &self.registration_handler),
            ("login_claims_handler", &self.login_claims_handler),
            ("verification_handler", &self.verification_handler),
        ] {
            if let Some(handler) = handler {
                // Every hook runs under at most half the request timeout (the registration hook gets
                // exactly half), so its handler must fit.
                anyhow::ensure!(
                    handler.timeout_secs > 0
                        && handler.timeout_secs.saturating_mul(2) <= self.request_timeout_secs,
                    "{what} timeout_secs must be positive and at most half of request_timeout_secs"
                );
            }
        }
        Ok(())
    }

    /// Refuses to serve with an empty API key: an unset key must never mean
    /// an open route. Not part of `load`, so `import` runs without them.
    pub fn require_api_keys(&self) -> anyhow::Result<()> {
        for (var, key) in [
            ("WA_HOOKS_API_KEY", &self.hooks_api_key),
            ("WA_BFF_INTERNAL_API_KEY", &self.bff_internal_api_key),
        ] {
            anyhow::ensure!(!key.expose_secret().is_empty(), "{var} must be set");
        }
        Ok(())
    }
}

/// Rejects a plaintext `http://` URL to a non-local host. The outbound calls
/// configured here carry the user's email, fields, password or access token,
/// which must not cross the network in the clear. `what` names the setting;
/// the URL itself is never echoed, since it may carry credentials.
pub(crate) fn require_https_or_loopback(what: &str, url: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid {what}: {e}"))?;
    let is_loopback = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if parsed.scheme() == "https" || is_loopback {
        Ok(())
    } else {
        anyhow::bail!("{what} must use https (http is only allowed for loopback hosts)")
    }
}

#[cfg(test)]
// figment::Jail::expect_with's closure signature is fixed by the crate; its
// Result<(), figment::Error> can't be shrunk from call sites.
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use figment::Jail;

    fn jail(setup: impl FnOnce(&mut Jail) -> figment::error::Result<()>) {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/config.yaml");
            setup(jail)
        });
    }

    #[test]
    fn defaults_in_dev_when_no_env_and_no_file() {
        jail(|jail| {
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();

            assert_eq!(config.port, 1983);
            assert_eq!(config.kratos_admin_url, "http://localhost:4434");
            assert!(config.registration_handler.is_none());
            assert!(config.profile_apis.is_empty());
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_to_start_on_localhost_defaults() {
        jail(|_| {
            let error = Config::load().expect_err("prod without upstream urls");

            assert!(error.to_string().contains("WA_KRATOS_ADMIN_URL"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn prod_starts_once_the_upstream_urls_are_set() {
        jail(|jail| {
            jail.set_env("WA_KRATOS_ADMIN_URL", "http://kratos:4434/");
            jail.set_env("WA_HYDRA_ADMIN_URL", "http://hydra:4445");
            jail.set_env("WA_BFF_INTERNAL_URL", "http://bff:8082");

            let config = Config::load().unwrap();

            assert_eq!(config.kratos_admin_url, "http://kratos:4434");
            Ok(())
        });
    }

    #[test]
    fn env_overrides_the_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "profile: dev\nport: 2000\nbff_internal_url: http://from-file:1\n",
            )?;
            jail.set_env("WA_HOOKS_PORT", "3000");

            let config = Config::load().unwrap();

            assert_eq!(config.port, 3000);
            assert_eq!(config.bff_internal_url, "http://from-file:1");
            Ok(())
        });
    }

    #[test]
    fn require_verified_email_is_read_from_the_environment() {
        jail(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            assert!(Config::load().unwrap().require_verified_email);
            jail.set_env("WA_REQUIRE_VERIFIED_EMAIL", "false");

            assert!(!Config::load().unwrap().require_verified_email);
            Ok(())
        });
    }

    #[test]
    fn api_keys_are_read_from_the_environment() {
        jail(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_HOOKS_API_KEY", "hooks-key");
            jail.set_env("WA_BFF_INTERNAL_API_KEY", "bff-key");

            let config = Config::load().unwrap();

            assert_eq!(config.hooks_api_key.expose_secret(), "hooks-key");
            assert_eq!(config.bff_internal_api_key.expose_secret(), "bff-key");
            assert!(config.require_api_keys().is_ok());
            Ok(())
        });
    }

    #[test]
    fn serving_requires_both_api_keys() {
        let mut config = Config::default();
        assert!(config.require_api_keys().is_err());
        config.hooks_api_key = "k".to_string().into();
        let error = config.require_api_keys().expect_err("bff key still empty");
        assert!(
            error.to_string().contains("WA_BFF_INTERNAL_API_KEY"),
            "{error}"
        );
        config.bff_internal_api_key = "k".to_string().into();
        assert!(config.require_api_keys().is_ok());
    }

    #[test]
    fn a_non_http_upstream_url_is_refused() {
        jail(|jail| {
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_HYDRA_ADMIN_URL", "ftp://hydra");

            let error = Config::load().expect_err("ftp");

            assert!(error.to_string().contains("WA_HYDRA_ADMIN_URL"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn loads_handlers_and_profile_apis_from_the_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
profile: dev
registration_handler: {url: "http://localhost:10002/users"}
login_claims_handler: {url: "http://localhost:10002/users/claims", timeout_secs: 3}
profile_apis:
  google:
    - url: https://people.googleapis.com/v1/people/me?personFields=phoneNumbers
      required: true
      scope: https://www.googleapis.com/auth/contacts.readonly
      claims: {phone_number: /phoneNumbers/0/canonicalForm}
"#,
            )?;

            let config = Config::load().unwrap();

            assert_eq!(config.registration_handler.unwrap().timeout_secs, 10);
            assert_eq!(config.login_claims_handler.unwrap().timeout_secs, 3);
            let api = &config.profile_apis["google"][0];
            assert!(api.required);
            assert_eq!(api.claims["phone_number"], "/phoneNumbers/0/canonicalForm");
            Ok(())
        });
    }

    #[test]
    fn a_plain_http_webhook_to_a_remote_host_is_refused() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "profile: dev\nregistration_handler: {url: \"http://hook.example.com/check\"}\n",
            )?;

            let error = Config::load().expect_err("plain http, remote host");

            assert!(
                error.to_string().contains("registration_handler"),
                "{error}"
            );
            Ok(())
        });
    }

    #[test]
    fn a_plain_http_profile_api_to_a_remote_host_is_refused() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "profile: dev\nprofile_apis:\n  google:\n    - {url: \"http://api.example.com/me\", claims: {}}\n",
            )?;

            assert!(Config::load().is_err());
            Ok(())
        });
    }

    #[test]
    fn https_and_loopback_http_are_accepted() {
        assert!(require_https_or_loopback("x", "https://example.com/a").is_ok());
        assert!(require_https_or_loopback("x", "http://localhost:1/a").is_ok());
        assert!(require_https_or_loopback("x", "http://127.0.0.1:1/a").is_ok());
        assert!(require_https_or_loopback("x", "http://[::1]:1/a").is_ok());
        assert!(require_https_or_loopback("x", "http://example.com/a").is_err());
        assert!(require_https_or_loopback("x", "not a url").is_err());
    }

    #[test]
    fn a_refused_url_is_not_echoed_in_the_error() {
        let url = "http://user:hunter2@hook.example.com/check?token=abc123";
        let error = require_https_or_loopback("registration_handler", url).expect_err("plain http");
        let invalid = require_https_or_loopback("registration_handler", "http://[bad?token=abc123")
            .expect_err("unparseable");

        for error in [error, invalid] {
            let message = error.to_string();
            assert!(message.contains("registration_handler"), "{message}");
            assert!(
                !message.contains("hunter2") && !message.contains("abc123"),
                "{message}"
            );
        }
    }

    #[test]
    fn a_webhook_bearer_token_is_read_from_the_file_and_stays_out_of_debug_output() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "profile: dev\nregistration_handler: {url: \"https://hook.example.com/check\", bearer_token: s3cret-token}\n",
            )?;

            let config = Config::load().unwrap();

            let handler = config.registration_handler.unwrap();
            assert_eq!(
                handler.bearer_token.as_ref().map(|t| t.expose_secret()),
                Some("s3cret-token")
            );
            assert!(!format!("{handler:?}").contains("s3cret-token"));
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_a_short_hooks_api_key_but_dev_and_an_unset_key_load() {
        jail(|jail| {
            jail.set_env("WA_KRATOS_ADMIN_URL", "http://kratos:4434");
            jail.set_env("WA_HYDRA_ADMIN_URL", "http://hydra:4445");
            jail.set_env("WA_BFF_INTERNAL_URL", "http://bff:8082");
            jail.set_env("WA_HOOKS_API_KEY", "short");

            let error = Config::load().expect_err("short key under prod");
            assert!(error.to_string().contains("WA_HOOKS_API_KEY"), "{error}");

            jail.set_env("WA_HOOKS_API_KEY", "0123456789abcdef");
            assert!(Config::load().is_ok());

            jail.set_env("WA_HOOKS_API_KEY", "");
            assert!(Config::load().is_ok(), "import runs without keys");

            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_HOOKS_API_KEY", "short");
            assert!(Config::load().is_ok());
            Ok(())
        });
    }

    #[test]
    fn zero_timeouts_are_refused() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "profile: dev\nupstream_timeout_secs: 0\n")?;

            assert!(Config::load().is_err());
            Ok(())
        });
    }

    fn load_yaml(yaml: &str) -> anyhow::Result<Config> {
        let mut result = None;
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", yaml)?;
            result = Some(Config::load());
            Ok(())
        });
        result.unwrap()
    }

    #[test]
    fn webhook_timeouts_must_be_positive_and_fit_in_half_the_request_timeout() {
        for handler in [
            "registration_handler",
            "login_claims_handler",
            "verification_handler",
        ] {
            for (timeout, ok) in [(0, false), (16, false), (15, true)] {
                let yaml = format!(
                    "profile: dev\n{handler}: {{url: \"http://localhost:1/x\", timeout_secs: {timeout}}}\n"
                );

                assert_eq!(load_yaml(&yaml).is_ok(), ok, "{handler} {timeout}");
            }
        }
    }

    #[test]
    fn huge_timeouts_are_refused_instead_of_overflowing() {
        let max = u64::MAX;
        assert!(
            load_yaml(&format!(
                "profile: dev\nrequest_timeout_secs: {max}\nupstream_timeout_secs: {max}\n"
            ))
            .is_err()
        );
        assert!(
            load_yaml(&format!(
                "profile: dev\nregistration_handler: {{url: \"http://localhost:1/x\", timeout_secs: {max}}}\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn the_upstream_timeout_must_leave_room_for_two_calls_in_the_request_timeout() {
        assert!(
            load_yaml("profile: dev\nrequest_timeout_secs: 20\nupstream_timeout_secs: 10\n")
                .is_err()
        );
        assert!(
            load_yaml("profile: dev\nrequest_timeout_secs: 21\nupstream_timeout_secs: 10\n")
                .is_ok()
        );
    }

    #[test]
    fn a_misspelled_webhook_or_profile_api_key_is_an_error() {
        assert!(
            load_yaml(
                "profile: dev\nregistration_handler: {url: \"http://localhost:1/x\", timeout_sec: 3}\n"
            )
            .is_err()
        );
        assert!(
            load_yaml(
                "profile: dev\nprofile_apis:\n  google:\n    - {url: \"https://a.example/me\", claims: {}, requried: true}\n"
            )
            .is_err()
        );
    }

    #[test]
    fn an_unreadable_config_file_is_an_error() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "port: 2\n")?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml/nested.yaml");

            assert!(Config::load().is_err());
            Ok(())
        });
    }
}
