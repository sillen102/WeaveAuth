//! The plugin token, driven against a plugin started outside WeaveAuth.
//!
//! Every other plugin test goes through `PluginProcess`, which always presents
//! the token -- so they prove the happy path but would stay green if the
//! plugin stopped checking. These start the probe plugin directly and call it
//! as an unauthorised local process would.

#[allow(dead_code)]
mod support;

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use support::plugin::PROBE;
use tonic::transport::{Channel, Endpoint, Uri};
use weaveauth_plugin_sdk::HandleRegistrationRequest;
use weaveauth_plugin_sdk::plugin_client::PluginClient;
use weaveauth_plugin_sdk::{SOCKET_ENV, TOKEN_ENV, TOKEN_METADATA_KEY};

const TOKEN: &str = "the-real-token";

/// A probe plugin listening on its own socket, killed when the test ends.
struct Plugin {
    child: Child,
    socket: PathBuf,
    dir: PathBuf,
}

impl Plugin {
    async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("wa-auth-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&dir).expect("creates a socket directory");
        let socket = dir.join("s");

        let child = Command::new(PROBE)
            .env_clear()
            .env(SOCKET_ENV, &socket)
            .env(TOKEN_ENV, TOKEN)
            .spawn()
            .expect("the probe plugin starts");

        wait_until_listening(&socket).await;
        Self { child, socket, dir }
    }

    fn client(&self) -> PluginClient<Channel> {
        let socket = self.socket.clone();
        let channel = Endpoint::from_static("http://plugin.invalid").connect_with_connector_lazy(tower::service_fn(
            move |_: Uri| {
                let socket = socket.clone();
                async move {
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                        tokio::net::UnixStream::connect(socket).await?,
                    ))
                }
            },
        ));
        PluginClient::new(channel)
    }

    /// Calls the plugin presenting `token`, or nothing at all.
    async fn call(&self, token: Option<&str>) -> Result<(), tonic::Status> {
        let mut request = tonic::Request::new(HandleRegistrationRequest {
            user_id: uuid::Uuid::new_v4().to_string(),
            email: "alice@example.com".to_string(),
            fields: Default::default(),
        });
        if let Some(token) = token {
            request.metadata_mut().insert(TOKEN_METADATA_KEY, token.parse().expect("ascii"));
        }
        self.client().handle_registration(request).await.map(|_| ())
    }
}

impl Drop for Plugin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn wait_until_listening(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while tokio::net::UnixStream::connect(socket).await.is_err() {
        assert!(Instant::now() < deadline, "the probe plugin never listened on {}", socket.display());
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// The positive control: without this the tests below would pass against a
// plugin that refuses everything, including WeaveAuth.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_presenting_the_token_is_served() {
    let plugin = Plugin::start().await;

    assert!(plugin.call(Some(TOKEN)).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_presenting_no_token_is_refused() {
    let plugin = Plugin::start().await;

    let status = plugin.call(None).await.expect_err("an unauthenticated caller was served");

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_presenting_the_wrong_token_is_refused() {
    let plugin = Plugin::start().await;

    let status = plugin.call(Some("not-the-token")).await.expect_err("a caller with a bad token was served");

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// Runs the probe plugin with whatever token it was given, returning what it
/// printed once it gave up.
fn start_with_token(token: Option<&str>) -> std::process::Output {
    let dir = std::env::temp_dir().join(format!("wa-auth-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&dir).expect("creates a socket directory");

    let mut command = Command::new(PROBE);
    command.env_clear().env(SOCKET_ENV, dir.join("s"));
    if let Some(token) = token {
        command.env(TOKEN_ENV, token);
    }
    let output = command.output().expect("the probe plugin runs");

    let _ = std::fs::remove_dir_all(&dir);
    output
}

// A plugin with no token has no way to tell WeaveAuth from anyone else, so it
// must refuse to start rather than serve everyone.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_started_without_a_token_refuses_to_run() {
    let output = start_with_token(None);

    assert!(!output.status.success(), "a plugin with no token started anyway");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(TOKEN_ENV),
        "the failure doesn't say what's missing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// An empty token is worse than a missing one: it would authenticate every
// caller that sends an empty header, while looking configured.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_started_with_an_empty_token_refuses_to_run() {
    let output = start_with_token(Some(""));

    assert!(!output.status.success(), "a plugin with an empty token started anyway");
}
