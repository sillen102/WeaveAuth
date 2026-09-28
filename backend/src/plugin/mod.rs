//! The plugin mechanism: a deployer mounts an executable, WeaveAuth runs it
//! as a child process and calls it over gRPC at a point in a flow.
//!
//! This module owns the process -- spawning it, restarting it when it dies,
//! and the unix socket the two talk over. The contract itself lives in
//! `plugin-sdk/proto`, so a new flow is a new rpc on that service rather
//! than a new runtime. Registration is the first caller (see
//! `crate::extra_data`).
//!
//! A plugin is a native binary, so it keeps its own async runtime and its
//! own long-lived resources: a `deadpool`/`sqlx` connection pool, an AMQP
//! channel, a vendor SDK client. WeaveAuth holds none of that on its behalf.
//! The price is that **a plugin is not sandboxed** -- it runs with this
//! process's privileges, and mounting one is equivalent to shipping
//! application code. Isolation, if wanted, is the deployer's (containers,
//! users, seccomp), and the environment is the one thing enforced here:
//! a plugin is given exactly the variables it was configured with.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngExt;
use tokio::process::{Child, Command};
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, Endpoint, Uri};
use weaveauth_plugin_sdk::plugin_client::PluginClient;
use weaveauth_plugin_sdk::{HandleRegistrationRequest, SOCKET_ENV, TOKEN_ENV, TOKEN_METADATA_KEY};

/// How long to wait after the plugin process dies before starting it again.
/// A plugin that fails on startup would otherwise be respawned as fast as
/// the OS can fork.
const RESTART_DELAY: Duration = Duration::from_secs(1);

/// How often to poll for the plugin's socket while it starts up.
const READINESS_POLL: Duration = Duration::from_millis(25);

/// The channel dials a unix socket through a connector, so the URI is never
/// resolved -- but `Endpoint` still requires a syntactically valid one.
const UNUSED_AUTHORITY: &str = "http://plugin.invalid";

/// Variables in WeaveAuth's own environment named
/// `WA_PLUGIN_<PLUGIN>_ENV_<NAME>` are forwarded to that plugin as `<NAME>`,
/// so a plugin reads the names its libraries already look for
/// (`DATABASE_URL`, `AWS_ACCESS_KEY_ID`) while a deployer keeps its secrets
/// wherever they keep every other secret, rather than in `config.yaml`.
///
/// The plugin name is part of the prefix so a second plugin surface gets its
/// own variables rather than inheriting this one's credentials.
fn forwarded_prefix(plugin: &str) -> String {
    format!("WA_PLUGIN_{plugin}_ENV_")
}

/// How a deployer describes the plugin to run.
pub(crate) struct PluginConfig {
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    /// The plugin's entire environment. It inherits nothing, so this is also
    /// where its credentials (a database URL, an API token) come from.
    pub(crate) env: HashMap<String, String>,
    /// Deadline on a single rpc.
    pub(crate) timeout: Duration,
    /// How long the plugin has to start listening before startup fails.
    pub(crate) startup_timeout: Duration,
}

/// A running plugin process and the typed client that talks to it.
///
/// The socket path is fixed for the lifetime of this value, so the channel
/// survives a restart: it reconnects to the same path once the replacement
/// process binds it. Calls made in between fail with `UNAVAILABLE`, which is
/// the same thing a flow does with any other plugin failure.
#[derive(Debug)]
pub(crate) struct PluginProcess {
    client: PluginClient<Channel>,
    timeout: Duration,
    /// Presented on every call; the plugin refuses anything without it.
    token: MetadataValue<Ascii>,
    /// Private directory holding the socket, removed on drop.
    dir: PathBuf,
    supervisor: tokio::task::JoinHandle<()>,
}

impl PluginProcess {
    /// Starts the plugin and waits for it to listen, so a missing or broken
    /// command fails at startup rather than at the first registration.
    pub(crate) async fn start(config: PluginConfig) -> anyhow::Result<Self> {
        let dir = socket_dir()?;
        let socket = dir.join("s");
        let secret = generate_token();
        let token = MetadataValue::try_from(&secret)?;

        let child = spawn(&config, &socket, &secret)
            .map_err(|error| anyhow::anyhow!("could not start plugin {:?}: {error}", config.command))?;
        let child = wait_until_listening(child, &socket, config.startup_timeout).await.inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&dir);
        })?;

        let timeout = config.timeout;
        let client = PluginClient::new(channel(socket.clone()));
        let supervisor = tokio::spawn(supervise(child, config, socket, secret));

        Ok(Self { client, timeout, token, dir, supervisor })
    }

    /// Hands the plugin the fields a register request carried beyond
    /// email/password. `Ok` accepts the registration; any status rejects it
    /// and no user is created.
    pub(crate) async fn handle_registration(&self, request: HandleRegistrationRequest) -> Result<(), tonic::Status> {
        let mut request = tonic::Request::new(request);
        request.set_timeout(self.timeout);
        request.metadata_mut().insert(TOKEN_METADATA_KEY, self.token.clone());

        self.client.clone().handle_registration(request).await.map(|_| ())
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        // Aborting drops the `Child`, which is `kill_on_drop`.
        self.supervisor.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A directory only this user can enter, since anyone who can reach the
/// socket inside it can drive the plugin -- and the plugin holds the
/// credentials the deployer gave it.
///
/// The name is kept short on purpose: a unix socket path is capped at ~104
/// bytes, and macOS already spends half of that on `$TMPDIR`.
fn socket_dir() -> anyhow::Result<PathBuf> {
    let unique = &uuid::Uuid::new_v4().simple().to_string()[..12];
    let dir = std::env::temp_dir().join(format!("wa-{unique}"));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

fn channel(socket: PathBuf) -> Channel {
    // Lazy: the endpoint is already known to be listening, and connecting
    // lazily is also what lets the channel recover on its own after a
    // restart.
    Endpoint::from_static(UNUSED_AUTHORITY).connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
        let socket = socket.clone();
        async move { Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tokio::net::UnixStream::connect(socket).await?)) }
    }))
}

/// Bytes of entropy behind the plugin token -- the same size as a refresh
/// token.
const TOKEN_BYTES: usize = 32;

/// A secret the plugin proves it holds on every call. Generated per
/// `PluginProcess` rather than configured, so there is nothing to rotate and
/// nothing to leave in a config file.
fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The variables WeaveAuth passes on to `plugin` from its own environment,
/// with the prefix stripped. Takes the variables rather than reading the
/// process environment so the rule can be tested without mutating it.
///
/// `plugin` names the surface in upper case (`REGISTRATION`); another
/// plugin's variables are left alone. A name that is only the prefix is
/// dropped: an empty variable name isn't something a plugin could read
/// anyway.
pub(crate) fn forwarded_env<I>(vars: I, plugin: &str) -> Vec<(String, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let prefix = forwarded_prefix(plugin);

    vars.into_iter()
        .filter_map(|(key, value)| {
            let name = key.into_string().ok()?.strip_prefix(&prefix)?.to_string();
            (!name.is_empty()).then_some((name, value))
        })
        .collect()
}

fn spawn(config: &PluginConfig, socket: &Path, token: &str) -> std::io::Result<Child> {
    Command::new(&config.command)
        .args(&config.args)
        // The plugin inherits nothing: this process's environment holds
        // WeaveAuth's own secrets (signing keys, OIDC client secrets,
        // database credentials), and a plugin has no business reading them.
        // Only what the deployer named for the plugin gets through.
        .env_clear()
        .envs(&config.env)
        .env(SOCKET_ENV, socket)
        .env(TOKEN_ENV, token)
        // The plugin's own logs are its operator's, so they go where every
        // other log from this container goes.
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
}

/// Polls until the plugin accepts a connection, or gives up. Returns the
/// child so a caller can't accidentally drop (and kill) it while waiting.
async fn wait_until_listening(mut child: Child, socket: &Path, timeout: Duration) -> anyhow::Result<Child> {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if tokio::net::UnixStream::connect(socket).await.is_ok() {
            return Ok(child);
        }
        // Distinguishes "still starting" from "already gave up", which is
        // the difference between waiting out the timeout and reporting what
        // actually happened.
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("plugin process exited during startup with {status}");
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("plugin did not listen on {} within {timeout:?}", socket.display());
        }
        tokio::time::sleep(READINESS_POLL).await;
    }
}

/// Restarts the plugin for as long as this task lives. A plugin that dies
/// mid-flight fails the request in progress; it must not also take every
/// later one down with it.
async fn supervise(mut child: Child, config: PluginConfig, socket: PathBuf, token: String) {
    loop {
        let status = child.wait().await;
        tracing::error!(?status, command = %config.command, "plugin process exited, restarting");

        child = loop {
            tokio::time::sleep(RESTART_DELAY).await;
            // The same token: the host holds it, so a replacement plugin is
            // handed what its predecessor had and the client needs no update.
            match spawn(&config, &socket, &token) {
                Ok(child) => break child,
                Err(error) => tracing::error!(%error, command = %config.command, "could not restart the plugin process"),
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(command: &str, args: &[&str]) -> PluginConfig {
        PluginConfig {
            command: command.to_string(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
            env: HashMap::new(),
            timeout: Duration::from_secs(5),
            startup_timeout: Duration::from_millis(500),
        }
    }

    #[tokio::test]
    async fn fails_to_start_when_the_command_does_not_exist() {
        assert!(PluginProcess::start(config("/nonexistent/weaveauth-plugin", &[])).await.is_err());
    }

    #[tokio::test]
    async fn fails_to_start_when_the_plugin_exits_immediately() {
        let error = PluginProcess::start(config("/bin/sh", &["-c", "exit 3"])).await.expect_err("must not start");

        assert!(error.to_string().contains("exited during startup"), "unhelpful error: {error}");
    }

    // A plugin that runs but never binds the socket is the case the
    // readiness poll exists for -- without it the failure would surface as a
    // rejected registration much later.
    #[tokio::test]
    async fn fails_to_start_when_the_plugin_never_listens() {
        let error = PluginProcess::start(config("/bin/sh", &["-c", "sleep 30"])).await.expect_err("must not start");

        assert!(error.to_string().contains("did not listen"), "unhelpful error: {error}");
    }

    /// What [`TOKEN_BYTES`] encodes to: unpadded base64 spends 4 characters
    /// on every 3 bytes, with no rounding up to a whole group.
    const TOKEN_LEN: usize = (TOKEN_BYTES * 4).div_ceil(3);

    // `cargo-mutants` found both of these unguarded: a token that is empty or
    // constant still authenticates, because both sides agree on whatever it
    // is, so every end-to-end test stays green while the control is gone.
    #[test]
    fn generates_an_unpredictable_token_every_time() {
        let first = generate_token();

        assert_ne!(first, generate_token(), "the token is the same every time, so it is not a secret");
        assert_eq!(first.len(), TOKEN_LEN, "the token is not the size it claims to be: {first:?}");
    }

    fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs.iter().map(|(key, value)| (OsString::from(key), OsString::from(value))).collect()
    }

    #[test]
    fn forwards_prefixed_variables_with_the_prefix_stripped() {
        let forwarded =
            forwarded_env(vars(&[("WA_PLUGIN_REGISTRATION_ENV_DATABASE_URL", "postgres://db/appdata")]), "REGISTRATION");

        // Stripped, because a plugin's libraries look for the name they
        // always look for, not a WeaveAuth-flavoured one.
        assert_eq!(forwarded, vec![("DATABASE_URL".to_string(), OsString::from("postgres://db/appdata"))]);
    }

    // The reason the plugin name is in the prefix: each surface gets its own
    // credentials, so a registration plugin can't read the claims plugin's
    // database password by being started alongside it.
    #[test]
    fn does_not_forward_another_plugins_variables() {
        let forwarded = forwarded_env(
            vars(&[
                ("WA_PLUGIN_CLAIMS_ENV_DATABASE_URL", "postgres://db/claims"),
                ("WA_PLUGIN_REGISTRATION_ENV_DATABASE_URL", "postgres://db/appdata"),
            ]),
            "REGISTRATION",
        );

        assert_eq!(forwarded, vec![("DATABASE_URL".to_string(), OsString::from("postgres://db/appdata"))]);
    }

    // The whole point of `env_clear`: WeaveAuth's own configuration and
    // secrets sit in variables that look very much like the forwarded ones.
    #[test]
    fn does_not_forward_weaveauths_own_variables() {
        let forwarded = forwarded_env(
            vars(&[
            ("WA_MAX_BCRYPT_COST", "12"),
            ("WA_OIDC_GOOGLE_CLIENT_SECRET", "hunter2"),
            ("WA_PLUGIN_SOCKET", "/tmp/somewhere/s"),
            ("WA_PLUGIN_TOKEN", "a-real-secret"),
            ("WA_PLUGIN_ENV_DATABASE_URL", "postgres://db/unscoped"),
            ("PATH", "/usr/bin"),
            ("DATABASE_URL", "postgres://weaveauth/users"),
        ]),
        "REGISTRATION",
    );

        assert!(forwarded.is_empty(), "a variable WeaveAuth never marked for the plugin was forwarded: {forwarded:?}");
    }

    #[test]
    fn drops_a_variable_that_is_only_the_prefix() {
        assert!(forwarded_env(vars(&[("WA_PLUGIN_REGISTRATION_ENV_", "orphan")]), "REGISTRATION").is_empty());
    }

    #[test]
    fn gives_the_plugin_a_private_socket_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = socket_dir().expect("creates a directory");
        let mode = std::fs::metadata(&dir).expect("readable").permissions().mode();
        let _ = std::fs::remove_dir_all(&dir);

        // Anyone who can open the socket can drive the plugin, and through
        // it whatever credentials the deployer gave it.
        assert_eq!(mode & 0o777, 0o700, "the socket directory is reachable by other users");
    }
}
