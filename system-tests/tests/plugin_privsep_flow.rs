//! The shipped image's privilege separation, end to end: backend runs as
//! `weaveauth`, spawns the probe plugin as `wa-registration`, and the plugin can't
//! read backend's environment. Only a real container has the users, the file
//! capabilities and `/proc` this needs, so it runs against the image
//! `system-tests/docker/Dockerfile.plugin-test` builds -- `mise run
//! test-docker` builds it first.

#![cfg(feature = "docker")]

use weaveauth_system_tests::support;

use support::plugin::{register, registration_fields};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

/// Starts the image with the probe told which uid it should find itself
/// running as, returning backend's URL.
async fn start(expected_uid: &str) -> (ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new("weaveauth-plugin-test", "latest")
        .with_exposed_port(1983.tcp())
        .with_wait_for(WaitFor::message_on_stdout("listening on 0.0.0.0:1983"))
        .with_env_var("WA_PLUGIN_REGISTRATION_ENV_PLUGIN_EXPECTED_UID", expected_uid)
        .start()
        .await
        .expect("the image starts, which includes backend starting its plugin");
    let port = container.get_host_port_ipv4(1983.tcp()).await.expect("backend publishes a port");
    (container, format!("http://127.0.0.1:{port}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_plugin_runs_as_its_own_user_and_cannot_read_backends_environment() {
    let (_container, backend_url) = start("1001").await;

    let status = register(&backend_url, "alice@example.com", &registration_fields("privsep")).await;

    assert_eq!(status, reqwest::StatusCode::CREATED, "the plugin ran as the wrong user or could read backend");
}

// Positive control for the test above: the probe really does compare its
// uid, so the test isn't passing on a check that never runs. 1000 is
// backend's own user -- what the plugin would be without separation.
#[tokio::test(flavor = "multi_thread")]
async fn the_privsep_probe_rejects_when_it_runs_as_another_user() {
    let (_container, backend_url) = start("1000").await;

    let status = register(&backend_url, "alice@example.com", &registration_fields("privsep")).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
}
