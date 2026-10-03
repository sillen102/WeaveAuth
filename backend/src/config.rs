use common::config::{EnvTable, Profile, PublicUrl};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

/// Deployer-facing settings. Everything else a deployment might want to tune
/// is either derived from these (see [`Config::load`]) or fixed in [`Tuning`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    /// Bff's public origin: where an OIDC provider's callback lands, so the
    /// default `redirect_uri` of each provider is built from it.
    pub bff_url: String,
    /// Login's public origin: the default `redirect_uri_allowlist` and where
    /// the verification link in an email points. Stored without a trailing `/`
    /// (see [`Config::load`]); a hand-built `Config` must keep that.
    pub login_public_url: String,
    /// Valid `redirect_uri` values for `/oauth/authorize`. Unset: login's
    /// own origin with a trailing `/` (the check is an exact string match).
    pub redirect_uri_allowlist: Vec<String>,
    /// How long an access token issued by `/oauth/token` stays valid for.
    pub access_token_ttl_secs: i64,
    /// How long a refresh token stays redeemable before it must be re-issued
    /// via a fresh login.
    pub refresh_token_ttl_secs: i64,
    /// How often a new JWT signing key replaces the active one. The
    /// replaced key stays published at `/.well-known/jwks.json` for
    /// [`jwt_key_grace_secs()`] after that, and the next key is published
    /// [`JWT_KEY_PUBLISH_AHEAD_SECS`] before it starts signing. The grace
    /// plus that lead must fit inside this interval, so at most two keys
    /// are published at once. Unset: [`Config::rotation_interval_secs`].
    #[serde(default)]
    pub jwt_key_rotation_interval_secs: Option<i64>,
    /// The `iss` claim on access tokens, and the base URL verifiers fetch
    /// `/.well-known/openid-configuration` from, so it must be backend's
    /// address as they reach it (`WA_BACKEND_URL`, the same value bff uses to
    /// reach it). Unset: `http://localhost:{port}`. Validated at load (http(s),
    /// no user info, path, query or fragment) and stored normalized: scheme
    /// and host lowercased, default port and trailing `/` dropped. That
    /// normalized form is what `iss` carries.
    pub issuer: String,
    /// Third-party OIDC login providers, keyed by a short name used in the
    /// `provider` query param (e.g. "google" for `/oauth/oidc/login?provider=google`). Empty by
    /// default -- third-party login is a no-op unless a provider is
    /// configured here.
    ///
    /// `skip_serializing` because `OidcProviderConfig` doesn't derive
    /// `Serialize` (it holds a `SecretString`, and serializing it would
    /// expose the client secret) -- `default` fills it back in from
    /// `Config::default()` on the deserialize side, since the defaults layer
    /// never sees it.
    #[serde(default, skip_serializing)]
    pub oidc_providers: HashMap<String, OidcProviderConfig>,
    /// How extra fields on a register request (anything beyond
    /// `email`/`password`) are handled. `None` means extra fields aren't
    /// supported -- a register request carrying any is rejected.
    #[serde(default)]
    pub extra_data_handler: Option<HandlerConfig>,
    /// Where extra JWT claims are fetched from on every token mint. `None`
    /// means no extra claims are added.
    #[serde(default)]
    pub login_claims_handler: Option<HandlerConfig>,
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
    /// Refuse `/oauth/login` for accounts whose email isn't verified yet.
    /// Unset: on for the prod profile when an `email_handler` is configured.
    #[serde(default)]
    pub require_verified_email: bool,
    /// Code-only; a `tuning:` key in YAML is ignored.
    #[serde(skip)]
    pub tuning: Tuning,
}

/// Lifetimes and limits nobody needs to tune per deployment: not settable from
/// YAML or the environment, only from code (tests shorten them).
#[derive(Debug, Clone)]
pub struct Tuning {
    /// How long an issued PKCE auth code stays redeemable.
    pub pkce_code_ttl_secs: i64,
    /// How long a `/oauth/login` session token stays valid for the follow-up
    /// `/oauth/authorize` call -- just a server-to-server hop, so deliberately short.
    pub login_session_ttl_secs: i64,
    /// How long a state entry for an in-flight `/oauth/oidc/login` redirect
    /// stays valid while the user is off at the provider's consent screen.
    pub oidc_state_ttl_secs: i64,
    /// How long a pending OIDC-to-password-account link (see
    /// `/oauth/oidc/confirm-link`) waits for the caller to supply the existing
    /// account's password. Roomier than `oidc_state_ttl_secs`: it waits on a
    /// human typing, not a redirect round-trip.
    pub pending_oidc_link_ttl_secs: i64,
    /// How long a `/oauth/password-reset/request` token stays redeemable.
    /// Roomy: it waits on a human reading an email and clicking a link.
    pub password_reset_token_ttl_secs: i64,
    /// How long an emailed verification code stays valid. Short, since a
    /// 9-digit code is guessable (it also dies after a few wrong attempts).
    pub email_verification_code_ttl_secs: i64,
    /// Minimum time between two verification emails to the same user, so the
    /// resend endpoint can't flood an inbox or keep replacing the code the
    /// user is about to type.
    pub email_verification_resend_cooldown_secs: i64,
    /// How long the restricted session `/oauth/login` hands an unverified
    /// account (good only for entering the code) stays valid.
    pub email_verification_session_ttl_secs: i64,
    /// Highest bcrypt cost factor accepted when verifying an imported
    /// legacy-user hash (see `crypto::verify_password`) -- caps how long a
    /// single login can tie up a blocking-pool thread.
    pub max_bcrypt_cost: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            pkce_code_ttl_secs: 300,
            login_session_ttl_secs: 60,
            oidc_state_ttl_secs: 300,
            pending_oidc_link_ttl_secs: 600,
            password_reset_token_ttl_secs: 1_800,
            email_verification_code_ttl_secs: 900,
            email_verification_resend_cooldown_secs: 60,
            email_verification_session_ttl_secs: 1_800,
            max_bcrypt_cost: bcrypt::DEFAULT_COST,
        }
    }
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
    /// this URL; the downstream service sends the email.
    Webhook(WebhookConfig),
    /// Calls a plugin process with the `email_verification` hook.
    Plugin(PluginSettings),
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

/// Where a hook's data goes: the extra registration fields
/// (`extra_data_handler`, an error fails the registration; nothing is ever
/// persisted by WeaveAuth itself, see `extra_data`) or the claims lookup on
/// every token mint (`login_claims_handler`, both `authorization_code` and
/// `refresh_token` grants; an error fails the token request, so no token is
/// issued without the claims it's configured to carry, see `login_claims`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HandlerConfig {
    Webhook(WebhookConfig),
    Plugin(PluginSettings),
}

/// POSTs the hook's JSON to `url`. Must be `https://` unless the host is
/// loopback (`localhost`/127.0.0.1/::1) -- the payload carries the user's
/// email and whatever the deployer's form collects, so a plaintext `http://`
/// hop to a non-local host would ship that over the wire in the clear.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    /// How long to wait before the hook fails -- a hung endpoint must not
    /// hold the request open indefinitely.
    #[serde(default = "default_webhook_timeout_secs")]
    pub timeout_secs: u64,
}

/// Runs the executable at `command` as a child process and calls it over gRPC
/// (see `plugin`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSettings {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// The plugin's entire environment -- it inherits nothing from
    /// WeaveAuth, so a database URL or an API token the plugin needs
    /// goes here.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// How long a single call to the plugin may take before the hook fails.
    #[serde(default = "default_plugin_timeout_secs")]
    pub timeout_secs: u64,
    /// How long the plugin has to start listening at startup. A plugin
    /// that misses it stops the server from booting, rather than
    /// surfacing as failed requests later.
    #[serde(default = "default_plugin_startup_timeout_secs")]
    pub startup_timeout_secs: u64,
    /// The user the plugin runs as. Unset: the hook's own user, see
    /// [`PluginHook::default_id`]. Every plugin runs as a user of its own --
    /// not WeaveAuth's, and not another plugin's -- so it can't read their
    /// memory or environment. Switching needs `CAP_SETUID`/`CAP_SETGID` (held
    /// by `Config::setuid_helper` in the image), which a local run without
    /// them avoids by setting `uid`/`gid` to its own.
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
}

/// The three places a plugin can be plugged in, each with its own user in the image.
#[derive(Debug, Clone, Copy)]
pub enum PluginHook {
    Registration,
    LoginClaims,
    Email,
}

impl PluginHook {
    /// Names this hook in the `WA_PLUGIN_<PLUGIN>_ENV_*` variables a deployer
    /// sets. Upper case because environment variables are.
    pub fn name(self) -> &'static str {
        match self {
            Self::Registration => "REGISTRATION",
            Self::LoginClaims => "LOGIN_CLAIMS",
            Self::Email => "EMAIL",
        }
    }

    /// The uid and gid of the image's `wa-registration`, `wa-login-claims`
    /// and `wa-email` users.
    pub fn default_id(self) -> u32 {
        match self {
            Self::Registration => 1001,
            Self::LoginClaims => 1002,
            Self::Email => 1003,
        }
    }
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

/// Config for a single third-party OIDC login provider. Discovered at
/// startup via `{issuer}/.well-known/openid-configuration`, so only the
/// issuer and this app's own client registration need to be given here.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfig {
    pub client_id: String,
    pub client_secret: SecretString,
    pub issuer: String,
    /// This provider's callback redirect URL, as registered with it.
    /// Backend isn't meant to be internet-exposed, so it must be bff's public
    /// URL, not backend's own address: bff forwards the provider's callback
    /// request to backend's matching route server-to-server. Unset:
    /// `{bff_url}/oidc/{key}/callback`.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// How login pages name this provider ("Continue with LinkedIn"); served
    /// at `/oauth/oidc/providers`. Unset: the key with its first letter capitalized.
    #[serde(default)]
    pub display_name: Option<String>,
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

impl OidcProviderConfig {
    /// `display_name`, or `key` (this provider's name under `oidc_providers`)
    /// with its first letter capitalized.
    pub fn display_name_for(&self, key: &str) -> String {
        self.display_name.clone().unwrap_or_else(|| {
            let mut chars = key.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().chain(chars).collect())
                .unwrap_or_default()
        })
    }

    /// `redirect_uri`, or bff's callback route for `key` under `bff_url`.
    pub fn redirect_uri_for(&self, key: &str, bff_url: &str) -> String {
        self.redirect_uri
            .clone()
            .unwrap_or_else(|| format!("{}/oidc/{key}/callback", bff_url.trim_end_matches('/')))
    }
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["email".to_string(), "profile".to_string()]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 1983,
            bff_url: "http://localhost:8080".to_string(),
            login_public_url: "http://localhost:8081".to_string(),
            redirect_uri_allowlist: vec!["http://localhost:8081/".to_string()],
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 2_592_000,
            jwt_key_rotation_interval_secs: None,
            issuer: "http://localhost:1983".to_string(),
            oidc_providers: HashMap::new(),
            extra_data_handler: None,
            login_claims_handler: None,
            setuid_helper: None,
            email_handler: None,
            require_verified_email: false,
            tuning: Tuning::default(),
        }
    }
}

/// How long a new signing key is published before it signs anything, so a
/// verifier that caches the JWKS for less than this, without re-fetching on
/// an unknown `kid`, has it by then.
pub const JWT_KEY_PUBLISH_AHEAD_SECS: i64 = 86_400;

/// How long a replaced key is kept past the last access token it signed, to
/// cover verifiers' `exp` leeway (jsonwebtoken defaults to 60s) and clock skew.
pub const JWT_KEY_GRACE_MARGIN_SECS: i64 = 3_600;

/// Rotation interval used unless the access token TTL needs a longer one.
const DEFAULT_ROTATION_INTERVAL_SECS: i64 = 2_592_000;

/// Largest accepted TTL or rotation interval (10 years): keeps the time
/// arithmetic on these far from overflow.
const MAX_SECS: i64 = 315_360_000;

/// How long a replaced signing key stays published: the longest-lived access
/// token it can have signed, plus [`JWT_KEY_GRACE_MARGIN_SECS`].
pub fn jwt_key_grace_secs(access_token_ttl_secs: i64) -> i64 {
    access_token_ttl_secs.saturating_add(JWT_KEY_GRACE_MARGIN_SECS)
}

/// The scalar settings that have an env var. Lists are in [`ENV_LISTS`]; the
/// per-provider secrets are read in [`Config::load`], the per-plugin
/// `WA_PLUGIN_*` variables by the plugin start.
const ENV: EnvTable = &[
    ("WA_PROFILE", "profile"),
    ("WA_PORT", "port"),
    ("WA_BFF_URL", "bff_url"),
    ("WA_LOGIN_PUBLIC_URL", "login_public_url"),
    ("WA_BACKEND_URL", "issuer"),
    ("WA_ACCESS_TOKEN_TTL_SECS", "access_token_ttl_secs"),
    ("WA_REFRESH_TOKEN_TTL_SECS", "refresh_token_ttl_secs"),
    (
        "WA_JWT_KEY_ROTATION_INTERVAL_SECS",
        "jwt_key_rotation_interval_secs",
    ),
    ("WA_REQUIRE_VERIFIED_EMAIL", "require_verified_email"),
    ("WA_SETUID_HELPER", "setuid_helper"),
];

const ENV_LISTS: EnvTable = &[("WA_REDIRECT_URI_ALLOWLIST", "redirect_uri_allowlist")];

impl Config {
    /// The rotation interval in effect: the configured one, else 30 days or,
    /// when the access token TTL needs more room than that, the least that
    /// satisfies [`Config::load`]'s check.
    pub fn rotation_interval_secs(&self) -> i64 {
        self.jwt_key_rotation_interval_secs.unwrap_or_else(|| {
            DEFAULT_ROTATION_INTERVAL_SECS.max(
                jwt_key_grace_secs(self.access_token_ttl_secs)
                    .saturating_add(JWT_KEY_PUBLISH_AHEAD_SECS),
            )
        })
    }

    /// Loads config, layering (highest precedence last): built-in defaults,
    /// then the YAML file at `WA_CONFIG_FILE` (default `config.yaml`; a
    /// missing file is not an error, one that exists but can't be read is),
    /// then the `WA_*` env vars in [`ENV`]. What the deployer left unset is
    /// then derived from what they did set: the allowlist from
    /// `login_public_url` (stored without a trailing `/`), `issuer` from `port`
    /// (dev only; prod requires `WA_BACKEND_URL`), each provider's
    /// `redirect_uri` from `bff_url`, and the profile's defaults. Prod also
    /// requires `bff_url` to be https and `login_public_url` an https origin.
    pub fn load() -> Result<Self, anyhow::Error> {
        common::config::load_dotenv()?;
        let user = common::config::user_settings(true, ENV, ENV_LISTS)?;
        let profile = common::config::profile(&user)?;
        // Backend's own address is internal, so http is fine there; it just can't be localhost.
        if profile == Profile::Prod && !user.contains("issuer") {
            anyhow::bail!(
                "WA_BACKEND_URL (or `issuer` in the config file) must be set for the prod profile; its default is a localhost address. Set WA_PROFILE=dev for local development"
            );
        }
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
        // Every URL derived from it appends a path.
        config.login_public_url = config.login_public_url.trim_end_matches('/').to_string();

        if !user.contains("redirect_uri_allowlist") {
            config.redirect_uri_allowlist = vec![format!("{}/", config.login_public_url)];
        }
        if !user.contains("issuer") {
            config.issuer = format!("http://localhost:{}", config.port);
        }
        if !user.contains("require_verified_email") {
            config.require_verified_email =
                profile == Profile::Prod && config.email_handler.is_some();
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

        for (name, value) in [
            ("WA_ACCESS_TOKEN_TTL_SECS", config.access_token_ttl_secs),
            ("WA_REFRESH_TOKEN_TTL_SECS", config.refresh_token_ttl_secs),
        ] {
            if !(1..=MAX_SECS).contains(&value) {
                anyhow::bail!("{name} must be between 1 and {MAX_SECS} seconds");
            }
        }
        if let Some(interval) = config.jwt_key_rotation_interval_secs
            && !(1..=MAX_SECS).contains(&interval)
        {
            anyhow::bail!(
                "WA_JWT_KEY_ROTATION_INTERVAL_SECS must be between 1 and {MAX_SECS} seconds"
            );
        }
        // The replaced key must be pruned before the next one is staged, so at most two are published.
        if jwt_key_grace_secs(config.access_token_ttl_secs)
            .saturating_add(JWT_KEY_PUBLISH_AHEAD_SECS)
            > config.rotation_interval_secs()
        {
            anyhow::bail!(
                "WA_ACCESS_TOKEN_TTL_SECS ({}) plus {}s (key grace margin and publish-ahead) must not exceed WA_JWT_KEY_ROTATION_INTERVAL_SECS ({})",
                config.access_token_ttl_secs,
                JWT_KEY_GRACE_MARGIN_SECS + JWT_KEY_PUBLISH_AHEAD_SECS,
                config.rotation_interval_secs()
            );
        }

        // The value isn't echoed in these errors: it may carry credentials.
        let issuer = url::Url::parse(&config.issuer)
            .map_err(|e| anyhow::anyhow!("invalid WA_BACKEND_URL: {e}"))?;
        if !matches!(issuer.scheme(), "http" | "https")
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            // Backend serves discovery and the endpoints it lists at its own root.
            || issuer.path() != "/"
            || issuer.query().is_some()
            || issuer.fragment().is_some()
        {
            anyhow::bail!(
                "WA_BACKEND_URL must be an http(s) URL without user info, path, query or fragment"
            );
        }
        config.issuer = issuer.origin().ascii_serialization();

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

    fn provider(display_name: Option<&str>) -> OidcProviderConfig {
        OidcProviderConfig {
            client_id: String::new(),
            client_secret: SecretString::from(String::new()),
            issuer: String::new(),
            redirect_uri: None,
            display_name: display_name.map(str::to_string),
            extra_claims: HashMap::new(),
            scopes: Vec::new(),
            profile_apis: Vec::new(),
        }
    }

    #[test]
    fn a_provider_without_a_display_name_is_shown_by_its_capitalized_key() {
        assert_eq!(provider(None).display_name_for("google"), "Google");
        assert_eq!(
            provider(Some("LinkedIn")).display_name_for("linkedin"),
            "LinkedIn"
        );
    }

    // A file that exists but can't be read is a deployment mistake, and
    // running on defaults instead would quietly drop every setting in it. A
    // path through a regular file can't be opened even by root, unlike a
    // `chmod 000` file.
    #[test]
    fn refuses_a_config_file_it_cannot_read() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "port: 1984\n")?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml/nested.yaml");
            jail.set_env("WA_PROFILE", "dev");

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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 1983);
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://localhost:8081/".to_string()]
            );
            assert_eq!(config.access_token_ttl_secs, 900);
            assert_eq!(config.refresh_token_ttl_secs, 2_592_000);
            assert_eq!(config.rotation_interval_secs(), 2_592_000);
            assert_eq!(config.issuer, "http://localhost:1983");
            assert_eq!(config.tuning.pkce_code_ttl_secs, 300);
            assert_eq!(config.tuning.max_bcrypt_cost, bcrypt::DEFAULT_COST);
            Ok(())
        });
    }

    #[test]
    fn rotation_interval_can_be_set_from_env() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_JWT_KEY_ROTATION_INTERVAL_SECS", "1209600");

            let config = Config::load().unwrap();
            assert_eq!(config.rotation_interval_secs(), 1_209_600);
            Ok(())
        });
    }

    #[test]
    fn access_ttl_plus_grace_margin_and_publish_ahead_longer_than_rotation_interval_is_rejected() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_ACCESS_TOKEN_TTL_SECS", "1001");
            jail.set_env(
                "WA_JWT_KEY_ROTATION_INTERVAL_SECS",
                (1000 + JWT_KEY_GRACE_MARGIN_SECS + JWT_KEY_PUBLISH_AHEAD_SECS).to_string(),
            );

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_ACCESS_TOKEN_TTL_SECS"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn access_ttl_plus_grace_margin_and_publish_ahead_equal_to_rotation_interval_is_accepted() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_ACCESS_TOKEN_TTL_SECS", "1000");
            jail.set_env(
                "WA_JWT_KEY_ROTATION_INTERVAL_SECS",
                (1000 + JWT_KEY_GRACE_MARGIN_SECS + JWT_KEY_PUBLISH_AHEAD_SECS).to_string(),
            );

            Config::load().unwrap();
            Ok(())
        });
    }

    #[test]
    fn refresh_ttl_may_outlast_the_rotation_interval() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_JWT_KEY_ROTATION_INTERVAL_SECS", "172800");
            jail.set_env("WA_REFRESH_TOKEN_TTL_SECS", "864000");

            Config::load().unwrap();
            Ok(())
        });
    }

    #[test]
    fn issuer_is_set_from_env_without_its_trailing_slash() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_BACKEND_URL", "https://auth.internal:1983/");

            let config = Config::load().unwrap();
            assert_eq!(config.issuer, "https://auth.internal:1983");
            Ok(())
        });
    }

    #[test]
    fn issuer_is_stored_in_its_normalized_form() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_BACKEND_URL", "HTTP:Auth.Internal");

            let config = Config::load().unwrap();
            assert_eq!(config.issuer, "http://auth.internal");
            Ok(())
        });
    }

    #[test]
    fn issuer_drops_the_default_port_but_keeps_any_other() {
        for (issuer, stored) in [
            ("https://auth.internal:443", "https://auth.internal"),
            ("https://auth.internal:8443", "https://auth.internal:8443"),
        ] {
            Jail::expect_with(|jail| {
                jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
                jail.set_env("WA_PROFILE", "dev");
                jail.set_env("WA_BACKEND_URL", issuer);

                assert_eq!(Config::load().unwrap().issuer, stored);
                Ok(())
            });
        }
    }

    #[test]
    fn malformed_or_non_http_issuer_is_rejected() {
        for issuer in [
            "not a url",
            "ftp://auth.internal",
            "https://auth.internal?x=1",
            "https://auth.internal#x",
            "https://auth.internal/auth",
            "https://user@auth.internal",
            "https://:secret@auth.internal",
        ] {
            Jail::expect_with(|jail| {
                jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
                jail.set_env("WA_PROFILE", "dev");
                jail.set_env("WA_BACKEND_URL", issuer);

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains("WA_BACKEND_URL"), "{issuer}: {error}");
                Ok(())
            });
        }
    }

    #[test]
    fn out_of_range_ttls_and_rotation_interval_are_rejected() {
        for (name, value) in [
            ("WA_ACCESS_TOKEN_TTL_SECS", "0"),
            ("WA_REFRESH_TOKEN_TTL_SECS", "0"),
            ("WA_JWT_KEY_ROTATION_INTERVAL_SECS", "0"),
            ("WA_ACCESS_TOKEN_TTL_SECS", "315360001"),
            ("WA_REFRESH_TOKEN_TTL_SECS", "9223372036854775807"),
            ("WA_JWT_KEY_ROTATION_INTERVAL_SECS", "9223372036854775807"),
        ] {
            Jail::expect_with(|jail| {
                jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
                jail.set_env("WA_PROFILE", "dev");
                jail.set_env(name, value);

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains(name), "{error}");
                Ok(())
            });
        }
    }

    #[test]
    fn ttls_and_rotation_interval_are_accepted_at_the_upper_bound() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_REFRESH_TOKEN_TTL_SECS", "315360000");
            jail.set_env("WA_JWT_KEY_ROTATION_INTERVAL_SECS", "315360000");

            Config::load().unwrap();
            Ok(())
        });
    }

    #[test]
    fn file_values_are_used_when_no_env_override() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "port: 9999\nredirect_uri_allowlist:\n  - http://file.test/callback\naccess_token_ttl_secs: 120\nrefresh_token_ttl_secs: 86400\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 9999);
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://file.test/callback".to_string()]
            );
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
                "port: 9999\nredirect_uri_allowlist:\n  - http://file.test/callback\naccess_token_ttl_secs: 120\nrefresh_token_ttl_secs: 86400\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_PORT", "7000");
            jail.set_env("WA_REDIRECT_URI_ALLOWLIST", "http://env.test/callback");
            jail.set_env("WA_ACCESS_TOKEN_TTL_SECS", "3");
            jail.set_env("WA_REFRESH_TOKEN_TTL_SECS", "7");

            let config = Config::load().unwrap();
            assert_eq!(config.port, 7000);
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["http://env.test/callback".to_string()]
            );
            assert_eq!(config.access_token_ttl_secs, 3);
            assert_eq!(config.refresh_token_ttl_secs, 7);
            Ok(())
        });
    }

    #[test]
    fn defaults_to_no_oidc_providers() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");

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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            let google = config
                .oidc_providers
                .get("google")
                .expect("google provider loaded");
            assert_eq!(google.client_id, "my-client-id");
            assert_eq!(google.client_secret.expose_secret(), "my-client-secret");
            assert_eq!(google.issuer, "https://accounts.google.com");
            assert_eq!(
                google.redirect_uri.as_deref(),
                Some("http://bff.test/oidc/google/callback")
            );
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
            jail.set_env("WA_PROFILE", "dev");

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
            jail.set_env("WA_PROFILE", "dev");

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
            jail.set_env("WA_PROFILE", "dev");

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
            jail.set_env("WA_PROFILE", "dev");
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
            jail.set_env("WA_PROFILE", "dev");

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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                HandlerConfig::Webhook(WebhookConfig { url, timeout_secs }) => {
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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                HandlerConfig::Webhook(WebhookConfig { timeout_secs, .. }) => {
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
            jail.set_env("WA_PROFILE", "dev");
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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                HandlerConfig::Plugin(PluginSettings {
                    command,
                    args,
                    env,
                    timeout_secs,
                    startup_timeout_secs,
                    uid,
                    gid,
                }) => {
                    assert_eq!(command, "/opt/plugins/register");
                    assert_eq!(
                        (uid, gid),
                        (None, None),
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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            match config.extra_data_handler.expect("handler configured") {
                HandlerConfig::Plugin(PluginSettings {
                    args,
                    env,
                    timeout_secs,
                    uid,
                    gid,
                    ..
                }) => {
                    assert_eq!((uid, gid), (Some(2000), Some(2001)));
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
            jail.set_env("WA_PROFILE", "dev");

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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            match config.login_claims_handler.expect("handler configured") {
                HandlerConfig::Webhook(WebhookConfig { url, timeout_secs }) => {
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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            match config.login_claims_handler.expect("handler configured") {
                HandlerConfig::Plugin(PluginSettings {
                    command,
                    args,
                    env,
                    timeout_secs,
                    startup_timeout_secs,
                    uid,
                    gid,
                }) => {
                    assert_eq!(command, "/opt/plugins/claims");
                    assert_eq!(
                        (uid, gid),
                        (None, None),
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
            jail.set_env("WA_PROFILE", "dev");
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
            jail.set_env("WA_PROFILE", "dev");
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
            jail.set_env("WA_PROFILE", "dev");
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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            assert!(config.email_handler.is_none());
            assert!(!config.require_verified_email);
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
            jail.set_env("WA_PROFILE", "dev");
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
            jail.set_env("WA_PROFILE", "dev");

            let config = Config::load().unwrap();
            match config.email_handler.expect("handler configured") {
                EmailHandlerConfig::Plugin(PluginSettings { uid, gid, .. }) => {
                    assert_eq!((uid, gid), (None, None));
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
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test");
            jail.set_env("WA_REQUIRE_VERIFIED_EMAIL", "true");

            let config = Config::load().unwrap();
            assert_eq!(config.login_public_url, "https://login.env.test");
            assert!(config.require_verified_email);
            Ok(())
        });
    }

    #[test]
    fn issuer_defaults_to_localhost_on_the_configured_port() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_PORT", "2000");

            assert_eq!(Config::load().unwrap().issuer, "http://localhost:2000");
            Ok(())
        });
    }

    #[test]
    fn an_explicit_issuer_beats_the_port_derived_one() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_PORT", "2000");
            jail.set_env("WA_BACKEND_URL", "https://auth.internal");

            assert_eq!(Config::load().unwrap().issuer, "https://auth.internal");
            Ok(())
        });
    }

    #[test]
    fn the_allowlist_follows_a_login_public_url_set_in_the_file() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "login_public_url: https://login.file.test\n")?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");

            assert_eq!(
                Config::load().unwrap().redirect_uri_allowlist,
                vec!["https://login.file.test/".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn a_trailing_slash_on_the_login_public_url_is_not_doubled_in_the_allowlist() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.env.test/");

            let config = Config::load().unwrap();
            assert_eq!(config.login_public_url, "https://login.env.test");
            assert_eq!(
                config.redirect_uri_allowlist,
                vec!["https://login.env.test/".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_to_start_on_localhost_defaults() {
        let all = [
            ("WA_BFF_URL", "https://bff.test"),
            ("WA_LOGIN_PUBLIC_URL", "https://login.test"),
            ("WA_BACKEND_URL", "https://backend.test"),
        ];
        for missing in 0..all.len() {
            Jail::expect_with(|jail| {
                jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
                for (i, (var, value)) in all.iter().enumerate() {
                    if i != missing {
                        jail.set_env(var, value);
                    }
                }

                let error = Config::load().unwrap_err().to_string();
                assert!(error.contains(all[missing].0), "{error}");
                Ok(())
            });
        }
    }

    #[test]
    fn prod_refuses_a_public_url_on_plain_http_but_not_an_internal_backend_url() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_BFF_URL", "https://bff.test");
            jail.set_env("WA_LOGIN_PUBLIC_URL", "http://login.test");
            jail.set_env("WA_BACKEND_URL", "http://backend.internal");

            let error = Config::load().unwrap_err().to_string();
            assert!(error.contains("WA_LOGIN_PUBLIC_URL"), "{error}");

            jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
            Config::load().unwrap();
            Ok(())
        });
    }

    #[test]
    fn prod_starts_once_its_public_urls_are_set() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            for (var, value) in [
                ("WA_BFF_URL", "https://bff.test"),
                ("WA_LOGIN_PUBLIC_URL", "https://login.test"),
                ("WA_BACKEND_URL", "https://backend.test"),
            ] {
                jail.set_env(var, value);
            }

            Config::load().unwrap();
            Ok(())
        });
    }

    #[test]
    fn a_providers_redirect_uri_defaults_to_bffs_callback_route() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                "oidc_providers:\n  google:\n    client_id: id\n    client_secret: secret\n    issuer: https://accounts.google.com\n  other:\n    client_id: id\n    client_secret: secret\n    issuer: https://other.test\n    redirect_uri: https://elsewhere.test/cb\n",
            )?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_BFF_URL", "https://bff.env.test/");

            let config = Config::load().unwrap();
            assert_eq!(
                config.oidc_providers["google"].redirect_uri_for("google", &config.bff_url),
                "https://bff.env.test/oidc/google/callback"
            );
            assert_eq!(
                config.oidc_providers["other"].redirect_uri_for("other", &config.bff_url),
                "https://elsewhere.test/cb"
            );
            Ok(())
        });
    }

    #[test]
    fn a_long_access_ttl_widens_the_default_rotation_interval_instead_of_failing() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_ACCESS_TOKEN_TTL_SECS", "3000000");

            let config = Config::load().unwrap();
            assert_eq!(
                config.rotation_interval_secs(),
                3_000_000 + JWT_KEY_GRACE_MARGIN_SECS + JWT_KEY_PUBLISH_AHEAD_SECS
            );
            Ok(())
        });
    }

    #[test]
    fn verification_is_required_by_default_only_in_prod_with_an_email_handler() {
        let email = "email_handler:\n  kind: webhook\n  url: https://mail.test/hook\n";
        for (profile, yaml, required) in [
            ("prod", email, true),
            ("dev", email, false),
            ("prod", "", false),
            (
                "prod",
                "require_verified_email: false\nemail_handler:\n  kind: webhook\n  url: https://mail.test/hook\n",
                false,
            ),
        ] {
            Jail::expect_with(|jail| {
                jail.create_file("config.yaml", yaml)?;
                jail.set_env("WA_CONFIG_FILE", "config.yaml");
                jail.set_env("WA_PROFILE", profile);
                jail.set_env("WA_BFF_URL", "https://bff.test");
                jail.set_env("WA_LOGIN_PUBLIC_URL", "https://login.test");
                jail.set_env("WA_BACKEND_URL", "https://backend.test");

                assert_eq!(
                    Config::load().unwrap().require_verified_email,
                    required,
                    "{profile}: {yaml}"
                );
                Ok(())
            });
        }
    }

    #[test]
    fn tuning_values_are_not_settable_from_the_environment() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");
            jail.set_env("WA_PKCE_CODE_TTL_SECS", "1");
            jail.set_env("WA_MAX_BCRYPT_COST", "4");

            let config = Config::load().unwrap();
            assert_eq!(config.tuning.pkce_code_ttl_secs, 300);
            assert_eq!(config.tuning.max_bcrypt_cost, bcrypt::DEFAULT_COST);
            Ok(())
        });
    }

    #[test]
    fn each_hook_runs_its_plugin_as_its_own_user_unless_told_otherwise() {
        assert_eq!(PluginHook::Registration.default_id(), 1001);
        assert_eq!(PluginHook::LoginClaims.default_id(), 1002);
        assert_eq!(PluginHook::Email.default_id(), 1003);
    }

    // Deployers name these in `WA_PLUGIN_<PLUGIN>_ENV_*`, so they're a contract.
    #[test]
    fn each_hook_has_its_documented_env_name() {
        assert_eq!(PluginHook::Registration.name(), "REGISTRATION");
        assert_eq!(PluginHook::LoginClaims.name(), "LOGIN_CLAIMS");
        assert_eq!(PluginHook::Email.name(), "EMAIL");
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
