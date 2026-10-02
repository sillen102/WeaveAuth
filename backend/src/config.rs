use figment::Figment;
use figment::providers::{Env, Format, Serialized, Yaml};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub redirect_uri_allowlist: Vec<String>,
    pub pkce_code_ttl_secs: i64,
    /// How long a `/oauth/login` session token stays valid for the follow-up
    /// `/oauth/authorize` call -- just a server-to-server hop, so this is
    /// deliberately short-lived.
    pub login_session_ttl_secs: i64,
    /// How long an access token issued by `/oauth/token` stays valid for.
    pub access_token_ttl_secs: i64,
    /// How long a refresh token stays redeemable before it must be re-issued
    /// via a fresh login.
    pub refresh_token_ttl_secs: i64,
    /// How long a state entry for an in-flight `/oauth/oidc/login`
    /// redirect stays valid while the user is off at the provider's consent
    /// screen.
    pub oidc_state_ttl_secs: i64,
    /// How long a pending OIDC-to-password-account link (see
    /// `/oauth/oidc/confirm-link`) stays valid while waiting for the caller
    /// to supply the existing account's password. Deliberately roomier than
    /// `oidc_state_ttl_secs` -- this one waits on a human reading a prompt
    /// and typing a password, not just a redirect round-trip.
    pub pending_oidc_link_ttl_secs: i64,
    /// How long a `/oauth/password-reset/request` token stays redeemable via
    /// `/oauth/password-reset/confirm`. Deliberately roomier than
    /// `oidc_state_ttl_secs` -- this one waits on a human reading an email
    /// and clicking a link, not just a redirect round-trip.
    pub password_reset_token_ttl_secs: i64,
    /// How long an emailed verification code stays valid. Short, since a
    /// 6-digit code is guessable (it also dies after a few wrong attempts).
    pub email_verification_code_ttl_secs: i64,
    /// Minimum time between two verification emails to the same user, so the
    /// resend endpoint can't be used to flood an inbox or to keep replacing
    /// the code the user is about to type.
    pub email_verification_resend_cooldown_secs: i64,
    /// How long the restricted session `/oauth/login` hands an unverified
    /// account (good only for entering the code) stays valid.
    pub email_verification_session_ttl_secs: i64,
    /// How often the background task sweeps expired entries out of the
    /// TTL'd stores (PKCE challenges, OIDC state, login sessions, ...).
    /// Bounds how long an abandoned flow's leftovers linger.
    pub expiry_sweep_interval_secs: u64,
    /// Third-party OIDC login providers, keyed by a short name used in the
    /// `provider` query param (e.g. "google" for `/oauth/oidc/login?provider=google`). Empty by
    /// default -- third-party login is a no-op unless a provider is
    /// configured here.
    ///
    /// `skip_serializing` because `OidcProviderConfig` doesn't derive
    /// `Serialize` (it holds a `SecretString`, and serializing it would
    /// expose the client secret) -- `default` fills it back in from
    /// `Config::default()` on the deserialize side, since `Config::load`'s
    /// defaults layer never sees it.
    #[serde(default, skip_serializing)]
    pub oidc_providers: HashMap<String, OidcProviderConfig>,
    /// Highest bcrypt cost factor accepted when verifying an imported
    /// legacy-user hash (see `crypto::verify_password`) -- caps how long a
    /// single login can tie up a blocking-pool thread.
    pub max_bcrypt_cost: u32,
    /// How extra fields on a register request (anything beyond
    /// `email`/`password`) are handled. `None` means extra fields aren't
    /// supported -- a register request carrying any is rejected.
    #[serde(default)]
    pub extra_data_handler: Option<ExtraDataHandlerConfig>,
    /// Where extra JWT claims are fetched from on every token mint. `None`
    /// means no extra claims are added.
    #[serde(default)]
    pub login_claims_handler: Option<LoginClaimsHandlerConfig>,
    /// The `weaveauth-plugin-exec` binary to start plugins through. It is
    /// the one that holds `CAP_SETUID`/`CAP_SETGID`, so this process needs
    /// none. Unset, backend switches users itself, which needs
    /// `CAP_SETUID`/`CAP_SETGID` (or root), unless a plugin's `uid`/`gid` are
    /// this process's own (local runs).
    #[serde(default)]
    pub setuid_helper: Option<String>,
    /// How a verification email reaches a newly registered user. `None`
    /// means no email is sent (the resend endpoint then does nothing).
    #[serde(default, skip_serializing)]
    pub email_handler: Option<EmailHandlerConfig>,
    /// Login's public origin (`WA_LOGIN_PUBLIC_URL`), where the verification
    /// link points. Required when `email_handler` is set.
    #[serde(default)]
    pub login_public_url: Option<String>,
    /// Refuse `/oauth/login` for accounts whose email isn't verified yet.
    #[serde(default)]
    pub require_verified_email: bool,
}

/// How a verification email is delivered. An error from any kind is logged
/// and never fails registration -- the user can ask for a resend.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EmailHandlerConfig {
    /// Renders the templates in `templates/emails/` and sends them
    /// through this SMTP server.
    Smtp {
        host: String,
        port: u16,
        #[serde(default)]
        tls: SmtpTls,
        #[serde(default)]
        username: Option<String>,
        /// Also settable via `WA_EMAIL_SMTP_PASSWORD`, which wins.
        #[serde(default)]
        password: Option<SecretString>,
        /// The `From` address, e.g. `WeaveAuth <no-reply@example.com>`.
        from: String,
        #[serde(default = "default_smtp_timeout_secs")]
        timeout_secs: u64,
    },
    /// POSTs `{user_id, email, token, verify_url, expires_at}` as JSON to
    /// this URL; the downstream service sends the email. Same https rule as
    /// [`ExtraDataHandlerConfig::Webhook`].
    Webhook {
        url: String,
        #[serde(default = "default_webhook_timeout_secs")]
        timeout_secs: u64,
    },
    /// Calls a plugin process with the `email_verification` hook.
    Plugin {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
        #[serde(default = "default_plugin_timeout_secs")]
        timeout_secs: u64,
        #[serde(default = "default_plugin_startup_timeout_secs")]
        startup_timeout_secs: u64,
        /// The user the plugin runs as, see [`default_email_plugin_id`].
        #[serde(default = "default_email_plugin_id")]
        uid: u32,
        #[serde(default = "default_email_plugin_id")]
        gid: u32,
    },
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    /// Plain connection upgraded with STARTTLS (typically port 587).
    #[default]
    Starttls,
    /// TLS from the first byte (typically port 465).
    Implicit,
    /// No encryption; only for a local relay or tests.
    None,
}

/// Where extra registration fields are forwarded. An error from either kind
/// fails the whole registration; nothing is ever persisted by WeaveAuth
/// itself -- see `extra_data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExtraDataHandlerConfig {
    /// POSTs the extra fields as JSON to this URL. Must be `https://` unless
    /// the host is loopback (`localhost`/127.0.0.1/::1) -- registration
    /// fields include the user's email and whatever the deployer's form
    /// collects, so a plaintext `http://` hop to a non-local host would ship
    /// that over the wire in the clear.
    Webhook {
        url: String,
        /// How long to wait for the webhook before failing the
        /// registration -- a hung endpoint must not hold the request open
        /// indefinitely.
        #[serde(default = "default_webhook_timeout_secs")]
        timeout_secs: u64,
    },
    /// Runs the executable at `command` as a child process and calls it
    /// over gRPC (see `plugin`).
    Plugin {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        /// The plugin's entire environment -- it inherits nothing from
        /// WeaveAuth, so a database URL or an API token the plugin needs
        /// goes here.
        #[serde(default)]
        env: HashMap<String, String>,
        /// How long a single call to the plugin may take before the
        /// registration fails.
        #[serde(default = "default_plugin_timeout_secs")]
        timeout_secs: u64,
        /// How long the plugin has to start listening at startup. A plugin
        /// that misses it stops the server from booting, rather than
        /// surfacing as failed registrations later.
        #[serde(default = "default_plugin_startup_timeout_secs")]
        startup_timeout_secs: u64,
        /// The user the plugin runs as, see [`default_registration_plugin_id`].
        #[serde(default = "default_registration_plugin_id")]
        uid: u32,
        #[serde(default = "default_registration_plugin_id")]
        gid: u32,
    },
}

/// Where extra JWT claims are fetched from on every token mint (both
/// `authorization_code` and `refresh_token` grants). An error from either
/// kind fails the token request -- no token is ever issued without the
/// claims it's configured to carry. See `login_claims`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoginClaimsHandlerConfig {
    /// POSTs `{user_id, email}` as JSON to this URL and expects a JSON
    /// object of claims back. Must be `https://` unless the host is
    /// loopback (`localhost`/127.0.0.1/::1) -- the request carries the
    /// user's email, so a plaintext `http://` hop to a non-local host would
    /// ship that over the wire in the clear.
    Webhook {
        url: String,
        /// How long to wait for the webhook before failing the token
        /// request -- a hung endpoint must not hold the request open
        /// indefinitely.
        #[serde(default = "default_webhook_timeout_secs")]
        timeout_secs: u64,
    },
    /// Runs the executable at `command` as a child process and calls it
    /// over gRPC (see `plugin`).
    Plugin {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        /// The plugin's entire environment -- it inherits nothing from
        /// WeaveAuth, so a database URL or an API token the plugin needs
        /// goes here.
        #[serde(default)]
        env: HashMap<String, String>,
        /// How long a single call to the plugin may take before the token
        /// request fails.
        #[serde(default = "default_plugin_timeout_secs")]
        timeout_secs: u64,
        /// How long the plugin has to start listening at startup. A plugin
        /// that misses it stops the server from booting, rather than
        /// surfacing as failed logins later.
        #[serde(default = "default_plugin_startup_timeout_secs")]
        startup_timeout_secs: u64,
        /// The user the plugin runs as, see [`default_login_claims_plugin_id`].
        #[serde(default = "default_login_claims_plugin_id")]
        uid: u32,
        #[serde(default = "default_login_claims_plugin_id")]
        gid: u32,
    },
}

fn default_webhook_timeout_secs() -> u64 {
    10
}

fn default_smtp_timeout_secs() -> u64 {
    10
}

fn default_plugin_timeout_secs() -> u64 {
    5
}

fn default_plugin_startup_timeout_secs() -> u64 {
    10
}

/// The uid and gid of the image's `wa-registration` user. Every plugin runs
/// as a user of its own -- not WeaveAuth's, and not another plugin's -- so it
/// can't read their memory or environment. Switching to it needs
/// `CAP_SETUID`/`CAP_SETGID` (held by `Config::setuid_helper` in the image),
/// which a local run without them avoids by setting `uid`/`gid` to its own.
fn default_registration_plugin_id() -> u32 {
    1001
}

/// The uid and gid of the image's `wa-login-claims` user; see
/// [`default_registration_plugin_id`].
fn default_login_claims_plugin_id() -> u32 {
    1002
}

/// The uid and gid of the image's `wa-email` user; see
/// [`default_registration_plugin_id`].
fn default_email_plugin_id() -> u32 {
    1003
}

/// Config for a single third-party OIDC login provider. Discovered at
/// startup via `{issuer}/.well-known/openid-configuration`, so only the
/// issuer and this app's own client registration need to be given here.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfig {
    pub client_id: String,
    pub client_secret: SecretString,
    pub issuer: String,
    /// This provider's callback redirect URL, as registered with it --
    /// backend isn't meant to be internet-exposed, so this must be bff's
    /// public URL (e.g. "https://bff.example.com/oidc/google/callback"),
    /// not backend's own address. bff forwards the provider's callback
    /// request to backend's matching route server-to-server.
    pub redirect_uri: String,
    /// Extra profile fields to take from this provider's id_token, as
    /// `field name -> id_token claim name` (e.g. `last_name: family_name`).
    /// Claim names differ per provider, so nothing is forwarded by default.
    /// On a user's first login through this provider the fields are handed to
    /// the extra-data handler, same as a register request's extra fields.
    #[serde(default)]
    pub extra_claims: HashMap<String, String>,
    /// Scopes requested on this provider's consent screen, in addition to
    /// `openid` (always sent). The default covers the email and name claims
    /// WeaveAuth relies on; changing it replaces the list, so keep `email`.
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    /// Extra API calls made with the provider's access token on a user's
    /// first login, for claims the id_token doesn't carry (e.g. Google's
    /// phone number lives in the People API). Called concurrently; on a
    /// field-name clash the later entry wins.
    #[serde(default)]
    pub profile_apis: Vec<ProfileApiConfig>,
}

/// One profile API call. Its fields reach the extra-data handler together
/// with the id_token `extra_claims`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileApiConfig {
    /// GET with `Authorization: Bearer <access token>`. Must be `https://`
    /// unless the host is loopback.
    pub url: String,
    /// `field name -> JSON pointer` (RFC 6901, e.g. `/phoneNumbers/0/value`)
    /// into the JSON response.
    pub claims: HashMap<String, String>,
    /// OAuth scope the access token needs for this call. Checked against the
    /// scopes the provider reports as granted before calling: if the user
    /// declined it the call is skipped, or, for a `required` entry, the login
    /// fails with an error saying the consent is needed. Unset: always called.
    #[serde(default)]
    pub scope: Option<String>,
    /// Whether a failed call (or a pointer that finds nothing) fails the
    /// login. When false, a failed call is logged and its fields are left
    /// out, and a pointer that finds nothing leaves just that field out.
    #[serde(default)]
    pub required: bool,
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["email".to_string(), "profile".to_string()]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 1983,
            redirect_uri_allowlist: vec!["http://localhost:8081/".to_string()],
            pkce_code_ttl_secs: 300,
            login_session_ttl_secs: 60,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 2_592_000,
            oidc_state_ttl_secs: 300,
            pending_oidc_link_ttl_secs: 600,
            password_reset_token_ttl_secs: 1_800,
            email_verification_code_ttl_secs: 900,
            email_verification_resend_cooldown_secs: 60,
            email_verification_session_ttl_secs: 1_800,
            expiry_sweep_interval_secs: 60,
            oidc_providers: HashMap::new(),
            max_bcrypt_cost: bcrypt::DEFAULT_COST,
            extra_data_handler: None,
            login_claims_handler: None,
            setuid_helper: None,
            email_handler: None,
            login_public_url: None,
            require_verified_email: false,
        }
    }
}

impl Config {
    /// Loads config, layering (highest precedence last): built-in defaults,
    /// then the YAML file at `WA_CONFIG_FILE` (default `config.yaml`; a
    /// missing file is not an error, one that exists but can't be read is),
    /// then `WA_*` env vars.
    pub fn load() -> Result<Self, anyhow::Error> {
        // A missing .env is normal; a present but malformed one would otherwise be dropped silently.
        if let Err(error) = dotenvy::dotenv()
            && !error.not_found()
        {
            anyhow::bail!("could not load .env: {error}");
        }

        let path = env::var("WA_CONFIG_FILE").unwrap_or_else(|_| "config.yaml".into());
        // Figment treats a file it can't open like a missing one. Missing is
        // fine (no overlay); present but unreadable is a deployment mistake
        // that would otherwise run on defaults, dropping every setting in it.
        if let Err(error) = std::fs::File::open(&path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            anyhow::bail!("could not read config file {path:?}: {error}");
        }

        // `WA_LOGIN_PUBLIC_URL` is login's own public origin (see
        // `login::Config::own_origin`) -- when the two run side by side, it's
        // also the redirect_uri login sends by default (with a trailing `/`,
        // matching login's own fallback), so seed the built-in default from
        // it before the YAML file/`WA_REDIRECT_URI_ALLOWLIST` env var (below)
        // get a chance to override it. The allowlist check is an exact
        // string match, so the trailing slash isn't optional here.
        let mut defaults = Config::default();
        if let Ok(login_url) = env::var("WA_LOGIN_PUBLIC_URL") {
            defaults.redirect_uri_allowlist = vec![format!("{login_url}/")];
        }

        let mut config: Config = Figment::from(Serialized::defaults(defaults))
            .merge(Yaml::file(&path))
            // `WA_PLUGIN_*` belongs to the plugin process, not to this
            // config -- see `plugin::forwarded_env`. Filtered rather than
            // merely unmatched, so adding a `plugin` field here later can't
            // silently start capturing a deployer's plugin variables.
            .merge(
                Env::prefixed("WA_")
                    .ignore(&["config_file", "redirect_uri_allowlist"])
                    .filter(|key| !key.starts_with("plugin_")),
            )
            .extract()?;

        if let Ok(raw) = env::var("WA_REDIRECT_URI_ALLOWLIST") {
            config.redirect_uri_allowlist = raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        for (name, provider) in config.oidc_providers.iter_mut() {
            let key = name.to_uppercase();
            if let Ok(client_id) = env::var(format!("WA_OIDC_{key}_CLIENT_ID")) {
                provider.client_id = client_id;
            }
            if let Ok(client_secret) = env::var(format!("WA_OIDC_{key}_CLIENT_SECRET")) {
                provider.client_secret = client_secret.into();
            }
        }

        if let Ok(password) = env::var("WA_EMAIL_SMTP_PASSWORD")
            && let Some(EmailHandlerConfig::Smtp { password: slot, .. }) =
                config.email_handler.as_mut()
        {
            *slot = Some(password.into());
        }

        // bcrypt's own hard cap on the cost factor -- not exported by the
        // `bcrypt` crate, so mirrored here. Anything above it would make the
        // configured cap inert (bcrypt would refuse to hash at that cost anyway).
        const BCRYPT_MAX_COST: u32 = 31;
        if config.max_bcrypt_cost > BCRYPT_MAX_COST {
            tracing::warn!(
                configured = config.max_bcrypt_cost,
                clamped_to = BCRYPT_MAX_COST,
                "WA_MAX_BCRYPT_COST exceeds bcrypt's own maximum cost; clamping"
            );
            config.max_bcrypt_cost = BCRYPT_MAX_COST;
        }

        Ok(config)
    }
}

/// Rejects SMTP without TLS to a non-loopback host: the verification code and
/// any SMTP credentials would cross the network in the clear. `tls: none` is
/// only for a local relay (Mailpit, a sidecar).
pub(crate) fn require_tls_or_loopback(host: &str, tls: SmtpTls) -> anyhow::Result<()> {
    let is_loopback = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if tls == SmtpTls::None && !is_loopback {
        anyhow::bail!(
            "smtp host {host:?} needs tls: starttls or implicit (tls: none is only allowed for loopback hosts)"
        );
    }
    Ok(())
}

/// Rejects a plaintext `http://` URL to a non-local host. The outbound calls
/// configured here (webhooks, profile APIs) carry the user's email, fields or
/// access token, which must not cross the network in the clear. `https://` is
/// always accepted; `http://` only for loopback, for local dev/testing against
/// a service on the same machine. `what` names the setting in the error.
pub(crate) fn require_https_or_loopback(what: &str, url: &str) -> anyhow::Result<()> {
    let parsed =
        url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid {what} {url:?}: {e}"))?;
    let is_loopback = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if parsed.scheme() == "https" || is_loopback {
        Ok(())
    } else {
        anyhow::bail!("{what} {url:?} must use https (http is only allowed for loopback hosts)")
    }
}

#[cfg(test)]
// figment::Jail::expect_with's closure signature is fixed by the crate; its
// Result<(), figment::Error> can't be shrunk from call sites.
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use figment::Jail;
    use secrecy::ExposeSecret;

    // A file that exists but can't be read is a deployment mistake, and
    // running on defaults instead would quietly drop every setting in it. A
    // path through a regular file can't be opened even by root, unlike a
    // `chmod 000` file.
    #[test]
    fn refuses_a_config_file_it_cannot_read() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "port: 1984\n")?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml/nested.yaml");

            let error =
                Config::load().expect_err("an unreadable config must not fall back to defaults");

            assert!(
                error.to_string().contains("config.yaml/nested.yaml"),
                "unhelpful error: {error}"
            );
            Ok(())
        });
    }

    #[test]
    fn accepts_https_urls() {
        assert!(require_https_or_loopback("hook url", "https://internal.example.com/hook").is_ok());
    }

    #[test]
    fn accepts_http_for_loopback_hosts() {
        assert!(require_https_or_loopback("hook url", "http://127.0.0.1:9000/hook").is_ok());
        assert!(require_https_or_loopback("hook url", "http://localhost:9000/hook").is_ok());
        assert!(require_https_or_loopback("hook url", "http://[::1]:9000/hook").is_ok());
    }

    #[test]
    fn rejects_plain_http_for_a_non_loopback_host_naming_what_it_checked() {
        let error =
            require_https_or_loopback("hook url", "http://internal.example.com/hook").unwrap_err();

        assert!(error.to_string().contains("hook url"), "{error}");
    }

    #[test]
    fn rejects_an_unparseable_url() {
        assert!(require_https_or_loopback("hook url", "not a url").is_err());
    }

    #[test]
    fn defaults_when_no_env_and_no_file() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 1983);
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://localhost:8081/".to_string()]
            );
            assert_eq!(config.pkce_code_ttl_secs, 300);
            assert_eq!(config.login_session_ttl_secs, 60);
            assert_eq!(config.access_token_ttl_secs, 900);
            assert_eq!(config.refresh_token_ttl_secs, 2_592_000);
            assert_eq!(config.max_bcrypt_cost, bcrypt::DEFAULT_COST);
            Ok(())
        });
    }

    #[test]
    fn max_bcrypt_cost_is_overridable_from_env() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_MAX_BCRYPT_COST", "10");

            let config = Config::load().unwrap();
            assert_eq!(config.max_bcrypt_cost, 10);
            Ok(())
        });
    }

    #[test]
    fn max_bcrypt_cost_above_bcrypts_own_maximum_is_clamped() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_MAX_BCRYPT_COST", "99");

            let config = Config::load().unwrap();
            assert_eq!(config.max_bcrypt_cost, 31);
            Ok(())
        });
    }

    #[test]
    fn file_values_are_used_when_no_env_override() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "port: 9999\nredirect_uri_allowlist:\n  - http://file.test/callback\npkce_code_ttl_secs: 42\nlogin_session_ttl_secs: 30\naccess_token_ttl_secs: 120\nrefresh_token_ttl_secs: 86400\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 9999);
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://file.test/callback".to_string()]
            );
            assert_eq!(config.pkce_code_ttl_secs, 42);
            assert_eq!(config.login_session_ttl_secs, 30);
            assert_eq!(config.access_token_ttl_secs, 120);
            assert_eq!(config.refresh_token_ttl_secs, 86400);
            Ok(())
        });
    }

    #[test]
    fn env_vars_override_file_values() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "port: 9999\nredirect_uri_allowlist:\n  - http://file.test/callback\npkce_code_ttl_secs: 42\nlogin_session_ttl_secs: 30\naccess_token_ttl_secs: 120\nrefresh_token_ttl_secs: 86400\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PORT", "7000");
            jail.set_env("WA_REDIRECT_URI_ALLOWLIST", "http://env.test/callback");
            jail.set_env("WA_PKCE_CODE_TTL_SECS", "11");
            jail.set_env("WA_LOGIN_SESSION_TTL_SECS", "5");
            jail.set_env("WA_ACCESS_TOKEN_TTL_SECS", "3");
            jail.set_env("WA_REFRESH_TOKEN_TTL_SECS", "7");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 7000);
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://env.test/callback".to_string()]
            );
            assert_eq!(config.pkce_code_ttl_secs, 11);
            assert_eq!(config.login_session_ttl_secs, 5);
            assert_eq!(config.access_token_ttl_secs, 3);
            assert_eq!(config.refresh_token_ttl_secs, 7);
            Ok(())
        });
    }

    #[test]
    fn defaults_to_no_oidc_providers() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let config = Config::load().unwrap();
            assert!(config.oidc_providers.is_empty());
            Ok(())
        });
    }

    #[test]
    fn loads_an_oidc_provider_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "oidc_providers:\n  \
                 google:\n    \
                 client_id: my-client-id\n    \
                 client_secret: my-client-secret\n    \
                 issuer: https://accounts.google.com\n    \
                 redirect_uri: http://bff.test/oidc/google/callback\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            let google = config
                .oidc_providers
                .get("google")
                .expect("google provider loaded");
            assert_eq!(google.client_id, "my-client-id");
            assert_eq!(google.client_secret.expose_secret(), "my-client-secret");
            assert_eq!(google.issuer, "https://accounts.google.com");
            assert_eq!(google.redirect_uri, "http://bff.test/oidc/google/callback");
            assert!(google.extra_claims.is_empty());
            assert_eq!(
                google.scopes,
                vec!["email".to_string(), "profile".to_string()]
            );
            assert!(google.profile_apis.is_empty());
            Ok(())
        });
    }

    #[test]
    fn loads_an_oidc_providers_profile_apis_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "oidc_providers:\n  \
                 google:\n    \
                 client_id: my-client-id\n    \
                 client_secret: my-client-secret\n    \
                 issuer: https://accounts.google.com\n    \
                 redirect_uri: http://bff.test/oidc/google/callback\n    \
                 profile_apis:\n      \
                 - url: https://people.test/me\n        \
                 claims:\n          \
                 phone_number: /phoneNumbers/0/value\n      \
                 - url: https://other.test/me\n        \
                 required: true\n        \
                 scope: https://other.test/scope\n        \
                 claims:\n          \
                 nickname: /nick\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            let apis = &config
                .oidc_providers
                .get("google")
                .expect("google provider loaded")
                .profile_apis;
            assert_eq!(apis.len(), 2);
            assert_eq!(apis[0].url, "https://people.test/me");
            assert_eq!(
                apis[0].claims.get("phone_number").map(String::as_str),
                Some("/phoneNumbers/0/value")
            );
            assert!(!apis[0].required, "not required unless asked");
            assert_eq!(apis[0].scope, None);
            assert_eq!(apis[1].scope.as_deref(), Some("https://other.test/scope"));
            assert!(apis[1].required);
            Ok(())
        });
    }

    #[test]
    fn loads_an_oidc_providers_scopes_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "oidc_providers:\n  \
                 google:\n    \
                 client_id: my-client-id\n    \
                 client_secret: my-client-secret\n    \
                 issuer: https://accounts.google.com\n    \
                 redirect_uri: http://bff.test/oidc/google/callback\n    \
                 scopes:\n      \
                 - email\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            let google = config
                .oidc_providers
                .get("google")
                .expect("google provider loaded");
            assert_eq!(google.scopes, vec!["email".to_string()]);
            Ok(())
        });
    }

    #[test]
    fn loads_an_oidc_providers_extra_claims_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "oidc_providers:\n  \
                 google:\n    \
                 client_id: my-client-id\n    \
                 client_secret: my-client-secret\n    \
                 issuer: https://accounts.google.com\n    \
                 redirect_uri: http://bff.test/oidc/google/callback\n    \
                 extra_claims:\n      \
                 last_name: family_name\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            let google = config
                .oidc_providers
                .get("google")
                .expect("google provider loaded");
            assert_eq!(
                google.extra_claims.get("last_name").map(String::as_str),
                Some("family_name")
            );
            Ok(())
        });
    }

    #[test]
    fn oidc_provider_client_id_and_secret_are_overridable_from_env() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "oidc_providers:\n  \
                 google:\n    \
                 client_id: placeholder-id\n    \
                 client_secret: placeholder-secret\n    \
                 issuer: https://accounts.google.com\n    \
                 redirect_uri: http://bff.test/oidc/google/callback\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_OIDC_GOOGLE_CLIENT_ID", "env-client-id");
            jail.set_env("WA_OIDC_GOOGLE_CLIENT_SECRET", "env-client-secret");

            let config = Config::load().unwrap();
            let google = config
                .oidc_providers
                .get("google")
                .expect("google provider loaded");
            assert_eq!(google.client_id, "env-client-id");
            assert_eq!(google.client_secret.expose_secret(), "env-client-secret");
            // Non-secret fields still come from the file, untouched.
            assert_eq!(google.issuer, "https://accounts.google.com");
            Ok(())
        });
    }

    #[test]
    fn defaults_to_no_extra_data_handler() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let config = Config::load().unwrap();
            assert!(config.extra_data_handler.is_none());
            Ok(())
        });
    }

    #[test]
    fn loads_a_webhook_extra_data_handler_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "extra_data_handler:\n  kind: webhook\n  url: https://internal.test/hook\n  timeout_secs: 3\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                ExtraDataHandlerConfig::Webhook { url, timeout_secs } => {
                    assert_eq!(url, "https://internal.test/hook");
                    assert_eq!(timeout_secs, 3);
                }
                other => unreachable!("only a webhook handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn webhook_timeout_secs_defaults_when_omitted() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "extra_data_handler:\n  kind: webhook\n  url: https://internal.test/hook\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                ExtraDataHandlerConfig::Webhook { timeout_secs, .. } => {
                    assert_eq!(timeout_secs, 10)
                }
                other => unreachable!("only a webhook handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn reads_the_setuid_helper_from_the_environment() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_SETUID_HELPER", "/usr/local/bin/weaveauth-plugin-exec");

            let config = Config::load().unwrap();
            assert_eq!(
                config.setuid_helper.as_deref(),
                Some("/usr/local/bin/weaveauth-plugin-exec")
            );
            Ok(())
        });
    }

    #[test]
    fn loads_a_plugin_extra_data_handler_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "extra_data_handler:\n  kind: plugin\n  command: /opt/plugins/register\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                ExtraDataHandlerConfig::Plugin {
                    command,
                    args,
                    env,
                    timeout_secs,
                    startup_timeout_secs,
                    uid,
                    gid,
                } => {
                    assert_eq!(command, "/opt/plugins/register");
                    assert_eq!(
                        (uid, gid),
                        (1001, 1001),
                        "a plugin runs as its own user unless told otherwise"
                    );
                    assert_eq!(timeout_secs, 5);
                    assert_eq!(startup_timeout_secs, 10);
                    assert!(args.is_empty());
                    assert!(
                        env.is_empty(),
                        "a plugin is given no environment unless the deployer sets one"
                    );
                }
                other => unreachable!("only a plugin handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn loads_the_plugin_command_line_and_environment_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "extra_data_handler:\n  kind: plugin\n  command: /opt/plugins/register\n  args:\n    - --verbose\n  env:\n    DATABASE_URL: postgres://plugin@db/appdata\n  timeout_secs: 20\n  uid: 2000\n  gid: 2001\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                ExtraDataHandlerConfig::Plugin {
                    args,
                    env,
                    timeout_secs,
                    uid,
                    gid,
                    ..
                } => {
                    assert_eq!((uid, gid), (2000, 2001));
                    assert_eq!(args, vec!["--verbose".to_string()]);
                    assert_eq!(
                        env.get("DATABASE_URL").map(String::as_str),
                        Some("postgres://plugin@db/appdata")
                    );
                    assert_eq!(timeout_secs, 20);
                }
                other => unreachable!("only a plugin handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn defaults_to_no_login_claims_handler() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let config = Config::load().unwrap();
            assert!(config.login_claims_handler.is_none());
            Ok(())
        });
    }

    #[test]
    fn loads_a_webhook_login_claims_handler_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "login_claims_handler:\n  kind: webhook\n  url: https://internal.test/claims\n  timeout_secs: 3\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.login_claims_handler.expect("handler configured") {
                LoginClaimsHandlerConfig::Webhook { url, timeout_secs } => {
                    assert_eq!(url, "https://internal.test/claims");
                    assert_eq!(timeout_secs, 3);
                }
                other => unreachable!("only a webhook handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn loads_a_plugin_login_claims_handler_from_the_config_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "login_claims_handler:\n  kind: plugin\n  command: /opt/plugins/claims\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.login_claims_handler.expect("handler configured") {
                LoginClaimsHandlerConfig::Plugin {
                    command,
                    args,
                    env,
                    timeout_secs,
                    startup_timeout_secs,
                    uid,
                    gid,
                } => {
                    assert_eq!(command, "/opt/plugins/claims");
                    assert_eq!(
                        (uid, gid),
                        (1002, 1002),
                        "a plugin runs as its own user unless told otherwise"
                    );
                    assert_eq!(timeout_secs, 5);
                    assert_eq!(startup_timeout_secs, 10);
                    assert!(args.is_empty());
                    assert!(
                        env.is_empty(),
                        "a plugin is given no environment unless the deployer sets one"
                    );
                }
                other => unreachable!("only a plugin handler was configured, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn redirect_uri_allowlist_env_splits_trims_and_drops_empties() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env(
                "WA_REDIRECT_URI_ALLOWLIST",
                "http://a.test , http://b.test,,",
            );

            let config = Config::load().unwrap();
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://a.test".to_string(), "http://b.test".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn redirect_uri_allowlist_defaults_to_login_public_url_with_trailing_slash() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");

            let config = Config::load().unwrap();
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["https://login.env.test/".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn explicit_redirect_uri_allowlist_still_wins_over_login_public_url() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");
            jail.set_env("WA_REDIRECT_URI_ALLOWLIST", "https://other.test/callback");

            let config = Config::load().unwrap();
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["https://other.test/callback".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn defaults_to_no_email_handler_and_no_enforcement() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let config = Config::load().unwrap();
            assert!(config.email_handler.is_none());
            assert!(!config.require_verified_email);
            assert_eq!(config.email_verification_code_ttl_secs, 900);
            assert_eq!(config.email_verification_resend_cooldown_secs, 60);
            Ok(())
        });
    }

    #[test]
    fn loads_an_smtp_email_handler_and_lets_the_env_password_win() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "email_handler:\n  kind: smtp\n  host: mail.test\n  port: 465\n  tls: implicit\n  username: u\n  password: from-file\n  from: no-reply@example.com\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_EMAIL_SMTP_PASSWORD", "from-env");

            let config = Config::load().unwrap();
            match config.email_handler.expect("handler configured") {
                EmailHandlerConfig::Smtp {
                    host,
                    port,
                    tls,
                    username,
                    password,
                    from,
                    timeout_secs,
                } => {
                    assert_eq!(host, "mail.test");
                    assert_eq!(port, 465);
                    assert_eq!(tls, SmtpTls::Implicit);
                    assert_eq!(username.as_deref(), Some("u"));
                    assert_eq!(password.unwrap().expose_secret(), "from-env");
                    assert_eq!(from, "no-reply@example.com");
                    assert_eq!(timeout_secs, 10);
                }
                other => unreachable!("expected smtp, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn loads_a_plugin_email_handler_defaulting_to_the_email_plugin_user() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "email_handler:\n  kind: plugin\n  command: /bin/mailer\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");

            let config = Config::load().unwrap();
            match config.email_handler.expect("handler configured") {
                EmailHandlerConfig::Plugin { uid, gid, .. } => {
                    assert_eq!((uid, gid), (1003, 1003));
                }
                other => unreachable!("expected plugin, got {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn login_public_url_and_require_verified_email_load_from_the_environment() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");
            jail.set_env("WA_REQUIRE_VERIFIED_EMAIL", "true");

            let config = Config::load().unwrap();
            assert_eq!(
                config.login_public_url.as_deref(),
                Some("https://login.env.test")
            );
            assert!(config.require_verified_email);
            Ok(())
        });
    }

    #[test]
    fn smtp_without_tls_is_only_allowed_for_loopback_hosts() {
        for host in ["localhost", "127.0.0.1", "::1", "[::1]"] {
            assert!(
                require_tls_or_loopback(host, SmtpTls::None).is_ok(),
                "{host}"
            );
        }
        let error = require_tls_or_loopback("smtp.example.com", SmtpTls::None).unwrap_err();
        assert!(error.to_string().contains("smtp.example.com"), "{error}");
    }

    #[test]
    fn smtp_with_tls_is_allowed_for_any_host() {
        assert!(require_tls_or_loopback("smtp.example.com", SmtpTls::Starttls).is_ok());
        assert!(require_tls_or_loopback("smtp.example.com", SmtpTls::Implicit).is_ok());
    }
}
