//! The plugin's one connection, driven against the probe plugin started
//! outside WeaveAuth: it serves only the end of the socket pair on its stdin,
//! only calls presenting the token written first on it, and refuses to run on
//! anything else.
//!
//! Every other plugin test goes through `PluginProcess`, which always does
//! all of that right -- so they prove the happy path but would stay green if
//! the plugin stopped checking.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::process::{Child, Command, Stdio};

use tonic::transport::{Channel, Endpoint, Uri};
use weaveauth_plugin_sdk::plugin_client::PluginClient;
use weaveauth_plugin_sdk::{PluginRequest, TOKEN_METADATA_KEY};

/// The probe plugin, built as a bin target of this package -- so it is
/// already compiled by the time a test runs, and always from this source
/// tree rather than a stale artifact. Only a test target sees this variable,
/// which is why it isn't in the library.
const PROBE: &str = env!("CARGO_BIN_EXE_probe-plugin");

const TOKEN: &str = "the-real-token";

/// A probe serving the other end of a socket pair, killed when the test ends.
struct Plugin {
    child: Child,
    client: PluginClient<Channel>,
}

impl Plugin {
    fn start() -> Self {
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        writeln!(ours, "{TOKEN}").expect("hands over the token");
        let child =
            Command::new(PROBE).env_clear().stdin(Stdio::from(OwnedFd::from(theirs))).spawn().expect("the probe starts");

        ours.set_nonblocking(true).expect("nonblocking");
        let mut ours = Some(tokio::net::UnixStream::from_std(ours).expect("tokio stream"));
        let channel = Endpoint::from_static("http://plugin.invalid").connect_with_connector_lazy(tower::service_fn(
            move |_: Uri| {
                let stream = ours.take();
                async move {
                    let stream = stream.ok_or(std::io::ErrorKind::NotConnected)?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            },
        ));
        Self { child, client: PluginClient::new(channel) }
    }

    /// Calls the plugin presenting `token`, or nothing at all.
    async fn call(&self, token: Option<&str>) -> Result<(), tonic::Status> {
        let mut request =
            tonic::Request::new(PluginRequest { hook: "registration".to_string(), ..Default::default() });
        if let Some(token) = token {
            request.metadata_mut().insert(TOKEN_METADATA_KEY, token.parse().expect("ascii"));
        }
        self.client.clone().invoke(request).await.map(|_| ())
    }
}

impl Drop for Plugin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// The positive control: without this the tests below would pass against a
// plugin that refuses everything, including WeaveAuth.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_on_the_socket_pair_presenting_the_token_is_served() {
    let plugin = Plugin::start();

    let result = plugin.call(Some(TOKEN)).await;

    assert!(result.is_ok(), "the probe didn't serve its own connection: {result:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_presenting_no_token_is_refused() {
    let plugin = Plugin::start();

    let status = plugin.call(None).await.expect_err("an unauthenticated caller was served");

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_presenting_the_wrong_token_is_refused() {
    let plugin = Plugin::start();

    let status = plugin.call(Some("not-the-token")).await.expect_err("a caller with a bad token was served");

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

// WeaveAuth usually runs as another user and can't kill its plugins, so a
// plugin whose connection is gone has to end itself -- otherwise every
// dropped or restarted plugin stays behind. The tests above are the control:
// a plugin whose connection is open keeps serving.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_exits_once_its_connection_closes() {
    let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().expect("socket pair");
    writeln!(ours, "{TOKEN}").expect("hands over the token");
    let mut child =
        Command::new(PROBE).env_clear().stdin(Stdio::from(OwnedFd::from(theirs))).spawn().expect("the probe starts");

    drop(ours);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("the probe can be waited on") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("the probe kept running after its connection closed");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert!(status.success(), "the probe failed instead of stopping: {status}");
}

/// Runs the probe with `stdin`, returning what it printed once it gave up.
fn run_with_stdin(stdin: Stdio) -> std::process::Output {
    Command::new(PROBE).env_clear().stdin(stdin).output().expect("the probe runs")
}

// Started by hand (or by anything but WeaveAuth), a plugin has no
// connection to serve, and says so instead of hanging.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_without_a_socket_on_stdin_refuses_to_run() {
    let output = run_with_stdin(Stdio::null());

    assert!(!output.status.success(), "a plugin with /dev/null for stdin started anyway");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stdin is not a unix socket"),
        "the failure doesn't say what's missing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_with_a_pipe_on_stdin_refuses_to_run() {
    let output = run_with_stdin(Stdio::piped());

    assert!(!output.status.success(), "a plugin with a pipe for stdin started anyway");
}

// An empty token is worse than none: it would authenticate every caller that
// sends an empty header, while looking configured.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_given_an_empty_token_refuses_to_run() {
    let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().expect("socket pair");
    writeln!(ours).expect("writes an empty line");

    let output = run_with_stdin(Stdio::from(OwnedFd::from(theirs)));

    assert!(!output.status.success(), "a plugin with an empty token started anyway");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no token"),
        "the failure doesn't say what's missing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
