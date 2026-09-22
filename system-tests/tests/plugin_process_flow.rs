//! Drives a real plugin process through backend's real `POST /register`.
//!
//! This is the layer that covers the whole path -- HTTP, the registration
//! flow, the spawned process, the guest SDK in `plugin-sdk/`, the gRPC
//! contract and the supervisor -- with no Docker. The companion
//! `plugin_postgres_flow` runs a plugin that talks to a real database, which
//! is what shows a plugin holding a connection pool across calls.
//!
//! A system test sees only HTTP status codes, so each behaviour is selected
//! by a `probe` field the plugin reads off the registration.

#[allow(dead_code)]
mod support;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use support::config::FINAL_REDIRECT;
use support::plugin::{PROBE, env, plugin_handler, register, registration_fields};
use support::servers::spawn_backend;

fn backend_config(timeout_secs: u64, env: HashMap<String, String>) -> weaveauth::config::Config {
    weaveauth::config::Config {
        extra_data_handler: Some(plugin_handler(PROBE, env, timeout_secs)),
        ..support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_accepting_completes_the_registration() {
    let (backend_url, _handle) = spawn_backend(&backend_config(10, HashMap::new())).await.expect("backend starts");

    let status = register(&backend_url, "alice@example.com", &registration_fields("accept")).await;

    assert_eq!(status, reqwest::StatusCode::CREATED);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_rejecting_fails_the_registration() {
    let (backend_url, _handle) = spawn_backend(&backend_config(10, HashMap::new())).await.expect("backend starts");

    let status = register(&backend_url, "alice@example.com", &registration_fields("reject")).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
}

#[tokio::test(flavor = "multi_thread")]
async fn backend_refuses_to_start_when_the_plugin_command_does_not_exist() {
    let config = backend_config(10, HashMap::new());
    let config = weaveauth::config::Config {
        extra_data_handler: Some(plugin_handler("/nonexistent/weaveauth-plugin", HashMap::new(), 10)),
        ..config
    };

    assert!(spawn_backend(&config).await.is_err(), "a missing plugin must fail at startup, not at the first request");
}

// The plugin's deadline is WeaveAuth's, not the plugin's: the probe sleeps
// far past the configured timeout, so only the host giving up can end this.
#[tokio::test(flavor = "multi_thread")]
async fn a_hung_plugin_fails_the_registration_within_its_timeout() {
    let (backend_url, _handle) = spawn_backend(&backend_config(1, HashMap::new())).await.expect("backend starts");

    let started = Instant::now();
    let status = register(&backend_url, "alice@example.com", &registration_fields("stall")).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert!(started.elapsed() < Duration::from_secs(20), "the call outlived its budget: {:?}", started.elapsed());
}

// One dead process must not end the plugin for the rest of the server's
// life -- the supervisor restarts it and the next registration goes through.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_succeeds_after_the_plugin_crashed() {
    let (backend_url, _handle) = spawn_backend(&backend_config(10, HashMap::new())).await.expect("backend starts");

    let crashed = register(&backend_url, "alice@example.com", &registration_fields("crash")).await;
    assert_eq!(crashed, reqwest::StatusCode::BAD_GATEWAY, "a plugin that died mid-call must fail that registration");

    // The supervisor waits a beat before restarting, so the replacement
    // isn't listening the instant the first call fails.
    let mut last = reqwest::StatusCode::BAD_GATEWAY;
    for attempt in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        last = register(&backend_url, &format!("bob{attempt}@example.com"), &registration_fields("accept")).await;
        if last == reqwest::StatusCode::CREATED {
            return;
        }
    }
    panic!("the plugin was never restarted, last registration got {last}");
}

// Two registrations that each sleep in the plugin have to overlap: one
// process serves both, so serialising them would take twice as long.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_serves_concurrent_registrations_concurrently() {
    let (backend_url, _handle) = spawn_backend(&backend_config(10, HashMap::new())).await.expect("backend starts");
    let mut fields = registration_fields("sleep");
    fields.insert("sleep_ms".to_string(), "1000".to_string());

    let started = Instant::now();
    let (first, second) = tokio::join!(
        register(&backend_url, "alice@example.com", &fields),
        register(&backend_url, "bob@example.com", &fields),
    );

    assert_eq!(first, reqwest::StatusCode::CREATED);
    assert_eq!(second, reqwest::StatusCode::CREATED);
    assert!(started.elapsed() < Duration::from_millis(1800), "the calls were serialised: {:?}", started.elapsed());
}

// WeaveAuth's own environment holds its signing keys, OIDC client secrets
// and database credentials. A plugin gets the variables it was configured
// with and nothing else; the probe rejects if it can see `PATH` or `HOME`,
// which the process running this test certainly has.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_is_given_only_the_environment_it_was_configured_with() {
    let configured = env(&[("PLUGIN_CONFIGURED", "yes")]);
    let (backend_url, _handle) = spawn_backend(&backend_config(10, configured)).await.expect("backend starts");

    let status = register(&backend_url, "alice@example.com", &registration_fields("env")).await;

    assert_eq!(status, reqwest::StatusCode::CREATED, "the plugin inherited WeaveAuth's environment");
}

// Positive control for the test above: the same probe rejects when the
// environment it expects isn't there, so that test isn't passing on a check
// that never runs.
#[tokio::test(flavor = "multi_thread")]
async fn the_environment_probe_rejects_when_its_configured_variable_is_missing() {
    let (backend_url, _handle) = spawn_backend(&backend_config(10, HashMap::new())).await.expect("backend starts");

    let status = register(&backend_url, "alice@example.com", &registration_fields("env")).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
}
