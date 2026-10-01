//! The plugin mechanism: a deployer mounts an executable, WeaveAuth runs it
//! as a child process and calls it over gRPC at a point in a flow.
//!
//! This module owns the process -- spawning it, restarting it when it dies,
//! and the connection the two talk over. The contract itself lives in
//! `plugin-sdk/proto`, so a new flow is a new `hook` value on its one
//! generic rpc rather than a new runtime. Registration
//! (`crate::server::api::register`) and login claims
//! (`crate::server::api::token`) are its callers.
//!
//! A plugin is a native binary, so it keeps its own async runtime and its
//! own long-lived resources: a `deadpool`/`sqlx` connection pool, an AMQP
//! channel, a vendor SDK client. WeaveAuth holds none of that on its behalf.
//! The price is that **a plugin is not sandboxed** -- mounting one is
//! equivalent to shipping application code. What is enforced here: it runs
//! as its own user, it is given exactly the variables it was configured
//! with, and the only connection to it is one WeaveAuth created.

use std::collections::HashMap;
use std::error::Error;
use std::ffi::OsString;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngExt;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, Endpoint, Uri};
use weaveauth_plugin_sdk::plugin_client::PluginClient;
use weaveauth_plugin_sdk::{PluginRequest, PluginResponse, TOKEN_METADATA_KEY};

/// How long to wait after the plugin process dies before starting it again.
/// A plugin that fails on startup would otherwise be respawned as fast as
/// the OS can fork.
const RESTART_DELAY: Duration = Duration::from_secs(1);

/// How long a plugin that failed to answer at startup gets to be reaped, so
/// the error can say it exited rather than that it went quiet.
const EXIT_GRACE: Duration = Duration::from_millis(200);

/// The hook WeaveAuth calls once at startup to learn the plugin is serving.
/// Whatever the plugin answers, even a refusal, counts.
pub(crate) const STARTUP_HOOK: &str = "weaveauth.startup";

/// The channel dials through a connector, so the URI is never resolved --
/// but `Endpoint` still requires a syntactically valid one.
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
    /// How long the plugin has to answer its first call before startup fails.
    pub(crate) startup_timeout: Duration,
    /// Who the plugin runs as. Never 0: a root plugin could read everything
    /// this process holds.
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

/// WeaveAuth's end of the connection to the current plugin process, waiting
/// for the channel to take it. Empty once taken, until a restart refills it.
type PendingConnection = Arc<Mutex<Option<UnixStream>>>;

/// A running plugin process and the typed client that talks to it.
///
/// The plugin's stdin is one end of a socket pair and WeaveAuth holds the
/// other, so there is no address for any other process to reach. The channel
/// survives a restart: it reconnects through the end the supervisor hands
/// it for the replacement process. Calls made in between fail with
/// `UNAVAILABLE`, which is the same thing a flow does with any other plugin
/// failure.
#[derive(Debug)]
pub(crate) struct PluginProcess {
    client: PluginClient<Channel>,
    timeout: Duration,
    /// Presented on every call; the plugin refuses anything without it.
    token: MetadataValue<Ascii>,
    supervisor: tokio::task::JoinHandle<()>,
}

impl PluginProcess {
    /// Starts the plugin and waits for it to answer, so a missing or broken
    /// command fails at startup rather than at the first registration.
    pub(crate) async fn start(config: PluginConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(config.uid != 0 && config.gid != 0, "plugin {:?} is configured to run as root", config.command);

        let secret = generate_token();
        let token = MetadataValue::try_from(&secret)?;

        let (child, connection) = spawn(&config, &secret).map_err(|error| {
            anyhow::anyhow!(
                "could not start plugin {:?} as uid {}/gid {}: {error} (running it as another user needs \
                 CAP_SETUID/CAP_SETGID; for a local run, set uid/gid to your own)",
                config.command,
                config.uid,
                config.gid
            )
        })?;
        let pending = Arc::new(Mutex::new(Some(connection)));
        let client = PluginClient::new(channel(pending.clone()));
        let child = wait_until_serving(child, &client, &token, config.startup_timeout).await?;

        let timeout = config.timeout;
        let supervisor = tokio::spawn(supervise(child, config, secret, pending));

        Ok(Self { client, timeout, token, supervisor })
    }

    /// Calls the plugin's one generic rpc for `request.hook`. `Ok` accepts/
    /// succeeds the caller's flow; any status rejects/fails it. What `Ok`'s
    /// `data` means (extra claims, nothing at all, ...) is up to the hook,
    /// not this method.
    pub(crate) async fn invoke(&self, request: PluginRequest) -> Result<PluginResponse, tonic::Status> {
        let mut request = tonic::Request::new(request);
        request.set_timeout(self.timeout);
        request.metadata_mut().insert(TOKEN_METADATA_KEY, self.token.clone());

        self.client.clone().invoke(request).await.map(|response| response.into_inner())
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        // Aborting drops the `Child`, which is `kill_on_drop`.
        self.supervisor.abort();
    }
}

fn channel(pending: PendingConnection) -> Channel {
    // Lazy, so the first call (the startup check) is what connects, and so
    // the channel reconnects on its own after a restart.
    Endpoint::from_static(UNUSED_AUTHORITY).connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
        let connection = pending.lock().ok().and_then(|mut slot| slot.take());
        async move {
            let stream = connection
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "the plugin is restarting"))?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
        }
    }))
}

/// Bytes of entropy behind the plugin token -- the same size as a refresh
/// token.
const TOKEN_BYTES: usize = 32;

/// A secret the plugin proves it was given on every call: a second layer
/// behind the socket pair, in case the connection ever reaches a process it
/// shouldn't. Generated per `PluginProcess` rather than configured, so there
/// is nothing to rotate and nothing to leave in a config file.
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

/// Encodes a JSON object as a `google.protobuf.Struct` for [`PluginRequest::data`]
/// -- the generic contract's payload type, so every hook shares one
/// conversion instead of each inventing its own.
pub(crate) fn json_to_struct(map: serde_json::Map<String, serde_json::Value>) -> prost_types::Struct {
    prost_types::Struct { fields: map.into_iter().map(|(key, value)| (key, json_value_to_prost(value))).collect() }
}

fn json_value_to_prost(value: serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;

    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(bool) => Kind::BoolValue(bool),
        serde_json::Value::Number(number) => Kind::NumberValue(number.as_f64().unwrap_or_default()),
        serde_json::Value::String(string) => Kind::StringValue(string),
        serde_json::Value::Array(values) => {
            Kind::ListValue(prost_types::ListValue { values: values.into_iter().map(json_value_to_prost).collect() })
        }
        serde_json::Value::Object(map) => Kind::StructValue(json_to_struct(map)),
    };
    prost_types::Value { kind: Some(kind) }
}

/// The inverse of [`json_to_struct`], decoding [`PluginResponse::data`] back
/// into ordinary JSON.
pub(crate) fn struct_to_json(value: prost_types::Struct) -> serde_json::Map<String, serde_json::Value> {
    value.fields.into_iter().map(|(key, value)| (key, prost_value_to_json(value))).collect()
}

fn prost_value_to_json(value: prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;

    match value.kind {
        None | Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::NumberValue(number)) => {
            serde_json::Number::from_f64(number).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null)
        }
        Some(Kind::StringValue(string)) => serde_json::Value::String(string),
        Some(Kind::BoolValue(bool)) => serde_json::Value::Bool(bool),
        Some(Kind::StructValue(inner)) => serde_json::Value::Object(struct_to_json(inner)),
        Some(Kind::ListValue(list)) => serde_json::Value::Array(list.values.into_iter().map(prost_value_to_json).collect()),
    }
}

/// Spawns the plugin with one end of a fresh socket pair as its stdin and
/// `token` as the first line on it, returning WeaveAuth's end.
fn spawn(config: &PluginConfig, token: &str) -> std::io::Result<(Child, UnixStream)> {
    let (mut ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    // Never waits on the plugin: the line is far below the socket buffer.
    ours.write_all(format!("{token}\n").as_bytes())?;
    let child = Command::new(&config.command)
        .args(&config.args)
        // The plugin inherits nothing: this process's environment holds
        // WeaveAuth's own secrets (signing keys, OIDC client secrets,
        // database credentials), and a plugin has no business reading them.
        // Only what the deployer named for the plugin gets through.
        .env_clear()
        .envs(&config.env)
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .uid(config.uid)
        .gid(config.gid)
        .kill_on_drop(true)
        .spawn()?;

    ours.set_nonblocking(true)?;
    Ok((child, UnixStream::from_std(ours)?))
}

/// Calls [`STARTUP_HOOK`] and waits for the plugin to answer, or for it to
/// exit, whichever comes first. Returns the child so a caller can't
/// accidentally drop (and kill) it while waiting.
async fn wait_until_serving(
    mut child: Child,
    client: &PluginClient<Channel>,
    token: &MetadataValue<Ascii>,
    timeout: Duration,
) -> anyhow::Result<Child> {
    let mut request = tonic::Request::new(PluginRequest { hook: STARTUP_HOOK.to_string(), ..Default::default() });
    request.set_timeout(timeout);
    request.metadata_mut().insert(TOKEN_METADATA_KEY, token.clone());

    let mut client = client.clone();
    let answer = tokio::select! {
        status = child.wait() => anyhow::bail!("plugin process exited during startup with {}", status?),
        answer = client.invoke(request) => answer,
    };
    match answer {
        Ok(_) => Ok(child),
        // A status the plugin sent itself has no source; one with a source
        // came from this side (transport error, deadline).
        Err(status) if status.source().is_none() => Ok(child),
        Err(status) => {
            // A plugin that died takes the connection with it, so the call
            // can fail a moment before the exit is reaped.
            if let Ok(exit) = tokio::time::timeout(EXIT_GRACE, child.wait()).await {
                anyhow::bail!("plugin process exited during startup with {}", exit?);
            }
            anyhow::bail!("plugin did not answer within {timeout:?}: {status}")
        }
    }
}

/// Restarts the plugin for as long as this task lives. A plugin that dies
/// mid-flight fails the request in progress; it must not also take every
/// later one down with it.
async fn supervise(mut child: Child, config: PluginConfig, token: String, pending: PendingConnection) {
    loop {
        let status = child.wait().await;
        tracing::error!(?status, command = %config.command, "plugin process exited, restarting");

        child = loop {
            tokio::time::sleep(RESTART_DELAY).await;
            // The same token: the host holds it, so a replacement plugin is
            // handed what its predecessor had and the client needs no update.
            match spawn(&config, &token) {
                Ok((child, connection)) => {
                    // Replaces an end the channel never took, which led to the
                    // process that just died.
                    if let Ok(mut slot) = pending.lock() {
                        *slot = Some(connection);
                    }
                    break child;
                }
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
            uid: current_id("-u"),
            gid: current_id("-g"),
        }
    }

    /// This process's own uid (`-u`) or gid (`-g`), the one user a plugin can
    /// be spawned as without privileges.
    fn current_id(flag: &str) -> u32 {
        let output = std::process::Command::new("id").arg(flag).output().expect("id runs");
        String::from_utf8_lossy(&output.stdout).trim().parse().expect("id prints a number")
    }

    #[tokio::test]
    async fn refuses_to_run_a_plugin_as_root() {
        let error = PluginProcess::start(PluginConfig { uid: 0, ..config("/bin/sh", &["-c", "sleep 30"]) })
            .await
            .expect_err("must not start");

        assert!(error.to_string().contains("root"), "unhelpful error: {error}");
    }

    #[tokio::test]
    async fn refuses_to_run_a_plugin_in_the_root_group() {
        let error = PluginProcess::start(PluginConfig { gid: 0, ..config("/bin/sh", &["-c", "sleep 30"]) })
            .await
            .expect_err("must not start");

        assert!(error.to_string().contains("root"), "unhelpful error: {error}");
    }

    // Spawning as a user this unprivileged test process isn't must fail --
    // if it started, the configured uid was never applied.
    #[tokio::test]
    async fn runs_the_plugin_as_the_configured_user() {
        let uid = current_id("-u") + 1;
        let error = PluginProcess::start(PluginConfig { uid, ..config("/bin/sh", &["-c", "sleep 30"]) })
            .await
            .expect_err("started as a user it had no right to become");

        assert!(error.to_string().contains("CAP_SETUID"), "unhelpful error: {error}");
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

    // A plugin that runs but never serves is the case the startup call
    // exists for -- without it the failure would surface as a rejected
    // registration much later.
    #[tokio::test]
    async fn fails_to_start_when_the_plugin_never_answers() {
        let error = PluginProcess::start(config("/bin/sh", &["-c", "sleep 30"])).await.expect_err("must not start");

        assert!(error.to_string().contains("did not answer"), "unhelpful error: {error}");
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

    fn string_value(value: &str) -> prost_types::Value {
        prost_types::Value { kind: Some(prost_types::value::Kind::StringValue(value.to_string())) }
    }

    fn list_value(values: Vec<prost_types::Value>) -> prost_types::Value {
        prost_types::Value { kind: Some(prost_types::value::Kind::ListValue(prost_types::ListValue { values })) }
    }

    // The motivating shape: role -> list of ids, nested inside a struct
    // rather than a flat string.
    #[test]
    fn struct_to_json_converts_a_nested_struct_with_a_list_of_strings() {
        let mut roles = std::collections::BTreeMap::new();
        roles.insert("admin".to_string(), list_value(vec![string_value("user-1"), string_value("user-2")]));
        let data = prost_types::Struct {
            fields: std::collections::BTreeMap::from([(
                "roles".to_string(),
                prost_types::Value { kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct { fields: roles })) },
            )]),
        };

        let map = struct_to_json(data);

        assert_eq!(map.get("roles").and_then(|v| v.get("admin")), Some(&serde_json::json!(["user-1", "user-2"])));
    }

    #[test]
    fn struct_to_json_converts_scalar_kinds() {
        let data = prost_types::Struct {
            fields: std::collections::BTreeMap::from([
                ("name".to_string(), string_value("alice")),
                ("active".to_string(), prost_types::Value { kind: Some(prost_types::value::Kind::BoolValue(true)) }),
                ("level".to_string(), prost_types::Value { kind: Some(prost_types::value::Kind::NumberValue(3.0)) }),
                ("nothing".to_string(), prost_types::Value { kind: None }),
            ]),
        };

        let map = struct_to_json(data);

        assert_eq!(map.get("name"), Some(&serde_json::json!("alice")));
        assert_eq!(map.get("active"), Some(&serde_json::json!(true)));
        assert_eq!(map.get("level"), Some(&serde_json::json!(3.0)));
        assert_eq!(map.get("nothing"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn struct_to_json_on_an_empty_struct_yields_an_empty_map() {
        assert!(struct_to_json(prost_types::Struct::default()).is_empty());
    }

    #[test]
    fn json_to_struct_is_the_inverse_of_struct_to_json() {
        let original = serde_json::json!({
            "roles": {"admin": ["user-1", "user-2"]},
            "name": "alice",
            "active": true,
            "level": 3.0,
            "nothing": null,
        });
        let map = original.as_object().cloned().expect("object");

        let round_tripped = struct_to_json(json_to_struct(map));

        assert_eq!(serde_json::Value::Object(round_tripped), original);
    }
}
