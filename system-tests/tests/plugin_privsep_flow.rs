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

/// The image's default config: the probe runs as `wa-registration` (1001).
const OWN_USER: &str = "/etc/weaveauth/config.yaml";
/// The probe configured as backend's own user (1000).
const BACKENDS_USER: &str = "/etc/weaveauth/same-user.yaml";

/// Starts the image on `config`, with the probe told which uid it should find
/// itself running as and whose environment to try (`parent` is backend),
/// returning backend's URL.
async fn start(config: &str, expected_uid: &str, environ_of: &str) -> (ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new("weaveauth-plugin-test", "latest")
        .with_exposed_port(1983.tcp())
        .with_wait_for(WaitFor::message_on_stdout("listening on 0.0.0.0:1983"))
        .with_env_var("WA_CONFIG_FILE", config)
        .with_env_var("WA_PLUGIN_REGISTRATION_ENV_PLUGIN_EXPECTED_UID", expected_uid)
        .with_env_var("WA_PLUGIN_REGISTRATION_ENV_PLUGIN_ENVIRON_OF", environ_of)
        .start()
        .await
        .expect("the image starts, which includes backend starting its plugin");
    let port = container.get_host_port_ipv4(1983.tcp()).await.expect("backend publishes a port");
    let url = format!("http://127.0.0.1:{port}");
    wait_until_reachable(&url).await;
    (container, url)
}

/// The log line says backend is listening inside the container; the host's
/// port forward (colima's in particular) can still lag behind it.
async fn wait_until_reachable(url: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while reqwest::get(format!("{url}/health")).await.is_err() {
        assert!(std::time::Instant::now() < deadline, "backend never became reachable at {url}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn probe(config: &str, expected_uid: &str, environ_of: &str, behaviour: &str) -> reqwest::StatusCode {
    let (_container, backend_url) = start(config, expected_uid, environ_of).await;
    register(&backend_url, "alice@example.com", &registration_fields(behaviour)).await
}

#[tokio::test(flavor = "multi_thread")]
async fn the_plugin_runs_as_its_own_user_and_cannot_read_backends_environment() {
    let status = probe(OWN_USER, "1001", "parent", "privsep").await;

    assert_eq!(status, reqwest::StatusCode::CREATED, "the plugin ran as the wrong user or could read backend");
}

// Backend marks itself non-dumpable, so not even a process running as its
// own user can read its environment -- which also covers bff and login.
#[tokio::test(flavor = "multi_thread")]
async fn not_even_backends_own_user_can_read_its_environment() {
    let status = probe(BACKENDS_USER, "1000", "parent", "privsep").await;

    assert_eq!(status, reqwest::StatusCode::CREATED, "backend's environment is readable by its own user");
}

// Controls for the two tests above, one per check the probe makes, so they
// aren't passing on a check that never runs. This one: the probe compares
// its uid.
#[tokio::test(flavor = "multi_thread")]
async fn the_privsep_probe_rejects_when_it_runs_as_another_user() {
    let status = probe(OWN_USER, "1000", "parent", "privsep").await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
}

// And this one: the probe really reads an environment. Its own is always
// readable, so it must reject.
#[tokio::test(flavor = "multi_thread")]
async fn the_privsep_probe_rejects_when_it_can_read_the_environment_it_tries() {
    let status = probe(OWN_USER, "1001", "self", "privsep").await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
}

// The helper holds CAP_SETUID: a plugin able to run it could become backend's
// user or another plugin's. It is `root:weaveauth 0710`, so a plugin can't.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_cannot_run_the_setuid_helper() {
    let status = probe(OWN_USER, "1001", "parent", "helper").await;

    assert_eq!(status, reqwest::StatusCode::CREATED, "a plugin could run weaveauth-plugin-exec");
}

// Control for the test above: backend's own user can run it (that's how
// plugins start), so the probe really sees it when it is allowed.
#[tokio::test(flavor = "multi_thread")]
async fn the_helper_probe_rejects_when_it_can_run_the_helper() {
    let status = probe(BACKENDS_USER, "1000", "parent", "helper").await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
}
