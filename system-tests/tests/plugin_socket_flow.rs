//! Drives a real WASM plugin through backend's real `POST /register`, with
//! the plugin reaching a stand-in Postgres over the socket capability.
//!
//! This is the layer that covers the whole path -- HTTP, the registration
//! flow, the plugin runtime, the guest SDK in `plugin-sdk/`, the host
//! functions and the connection pool -- with no Docker. The companion
//! `plugin_postgres_flow` runs the same plugin against a real Postgres,
//! which is the only thing that proves the wire protocol itself.
//!
//! A system test sees only HTTP status codes, so the assertions about
//! pooling are made at the server: it counts how many times it was
//! *dialled*, which a reused connection doesn't add to.

#[allow(dead_code)]
mod support;

use std::time::{Duration, Instant};

use support::config::FINAL_REDIRECT;
use support::plugin::{Behaviour, StandInPostgres, plugin_handler, register, registration_fields, socket_defaults};
use support::servers::spawn_backend;
use weaveauth::config::PluginSocketsConfig;

fn backend_config(allowed: Vec<String>, timeout_secs: u64, sockets: PluginSocketsConfig) -> weaveauth::config::Config {
    weaveauth::config::Config {
        extra_data_handler: Some(plugin_handler(allowed, timeout_secs, sockets)),
        ..support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
    }
}

fn allow(port: u16) -> Vec<String> {
    vec![format!("127.0.0.1:{port}")]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_completes_a_registration_over_the_socket_capability() {
    let server = StandInPostgres::start(Behaviour::Normal);
    let config = backend_config(allow(server.port), 10, socket_defaults());
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    let status = register(&backend_url, "alice@example.com", &registration_fields(server.port, "insert")).await;

    assert_eq!(status, reqwest::StatusCode::CREATED);
    assert_eq!(server.sessions(), 1);
}

// The property the host-side pool exists for: the second registration runs
// in a brand-new wasm instance, yet it inherits the first one's connection
// and skips the protocol handshake.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_registration_reuses_the_pooled_connection() {
    let server = StandInPostgres::start(Behaviour::Normal);
    let config = backend_config(allow(server.port), 10, socket_defaults());
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    for email in ["alice@example.com", "bob@example.com"] {
        let status = register(&backend_url, email, &registration_fields(server.port, "insert")).await;
        assert_eq!(status, reqwest::StatusCode::CREATED, "{email} was rejected");
    }

    assert_eq!(server.sessions(), 1, "the second registration dialled instead of reusing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_cannot_reach_an_endpoint_outside_the_allowlist() {
    let server = StandInPostgres::start(Behaviour::Normal);
    // Allowlists a different port than the one the plugin is told to use.
    let config = backend_config(allow(server.port + 1), 10, socket_defaults());
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    let status = register(&backend_url, "alice@example.com", &registration_fields(server.port, "insert")).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(server.sessions(), 0, "backend dialled an endpoint it should have refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dial_to_nothing_fails_the_registration() {
    let dead = StandInPostgres::dead_port();
    let config = backend_config(allow(dead), 10, socket_defaults());
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    let status = register(&backend_url, "alice@example.com", &registration_fields(dead, "insert")).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
}

// The plugin timeout is one budget for the whole call, wasm and socket IO
// together -- the per-operation timeout here is far longer than it, so only
// the shared deadline can end this.
#[tokio::test(flavor = "multi_thread")]
async fn a_hung_endpoint_fails_the_registration_within_the_plugin_timeout() {
    let server = StandInPostgres::start(Behaviour::Stall);
    let sockets = PluginSocketsConfig { io_timeout_ms: 30_000, ..socket_defaults() };
    let config = backend_config(allow(server.port), 1, sockets);
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    let started = Instant::now();
    let status = register(&backend_url, "alice@example.com", &registration_fields(server.port, "slow_query")).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert!(started.elapsed() < Duration::from_secs(20), "the call outlived its budget: {:?}", started.elapsed());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_cannot_open_more_connections_than_it_is_allowed() {
    let server = StandInPostgres::start(Behaviour::Normal);
    let sockets = PluginSocketsConfig { max_open_per_call: 3, ..socket_defaults() };
    let config = backend_config(allow(server.port), 10, sockets);
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    let status = register(&backend_url, "alice@example.com", &registration_fields(server.port, "open_limit")).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(server.sessions(), 3, "the host refused at the wrong point");
}

// The failure a host-side pool cannot prevent: the server closes a
// connection while it sits idle in the pool, and the host can't tell,
// because it doesn't know the protocol. The plugin has to retry.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_recovers_from_a_pooled_connection_the_server_closed() {
    let server = StandInPostgres::start(Behaviour::Normal);
    let config = backend_config(allow(server.port), 10, socket_defaults());
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    let first = register(&backend_url, "alice@example.com", &registration_fields(server.port, "insert")).await;
    assert_eq!(first, reqwest::StatusCode::CREATED);
    server.hang_up_on_everything();

    let second = register(&backend_url, "bob@example.com", &registration_fields(server.port, "insert")).await;

    assert_eq!(second, reqwest::StatusCode::CREATED, "the plugin did not retry onto a fresh connection");
    assert_eq!(server.sessions(), 2, "the retry did not dial a new connection");
}

// Positive control for the retry: the same plugin without one fails, so the
// test above isn't just watching a connection that still worked.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_without_a_retry_fails_on_a_closed_pooled_connection() {
    let server = StandInPostgres::start(Behaviour::Normal);
    let config = backend_config(allow(server.port), 10, socket_defaults());
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    let first = register(&backend_url, "alice@example.com", &registration_fields(server.port, "no_retry")).await;
    assert_eq!(first, reqwest::StatusCode::CREATED);
    server.hang_up_on_everything();

    let second = register(&backend_url, "bob@example.com", &registration_fields(server.port, "no_retry")).await;

    assert_eq!(second, reqwest::StatusCode::BAD_GATEWAY, "a dead pooled connection looked healthy");
}
