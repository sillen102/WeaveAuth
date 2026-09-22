//! A plugin that writes to a real Postgres with `deadpool-postgres`.
//!
//! This is the layer that shows what the process model buys: the plugin
//! holds an ordinary connection pool across registrations, and recovers from
//! a terminated backend on its own, because it is a normal binary using a
//! normal database library. It needs a Docker daemon, so it is behind the
//! `docker` feature: `mise run test-docker`.

#![cfg(feature = "docker")]

#[allow(dead_code)]
mod support;

use std::time::Duration;

use support::config::FINAL_REDIRECT;
use support::plugin::{env, plugin_handler, register, registration_fields};
use support::servers::spawn_backend;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

const PG_PROBE: &str = env!("CARGO_BIN_EXE_pg-probe-plugin");

const DB_USER: &str = "weaveauth";
const DB_NAME: &str = "appdata";

/// Kills every client backend except this test's own connection -- what a
/// Postgres restart looks like to a connection idle in the plugin's pool.
const TERMINATE_OTHERS: &str = "select pg_terminate_backend(pid) from pg_stat_activity \
                                where datname = current_database() and pid <> pg_backend_pid() \
                                and backend_type = 'client backend'";

struct Database {
    // Held so the container outlives the test.
    _container: ContainerAsync<GenericImage>,
    port: u16,
    client: tokio_postgres::Client,
}

impl Database {
    async fn start() -> Self {
        // `trust`, because what this proves is the plugin's own pool, not
        // Postgres authentication.
        let container = GenericImage::new("postgres", "17-alpine")
            .with_exposed_port(5432.tcp())
            .with_wait_for(WaitFor::message_on_stderr("database system is ready to accept connections"))
            .with_env_var("POSTGRES_USER", DB_USER)
            .with_env_var("POSTGRES_DB", DB_NAME)
            .with_env_var("POSTGRES_HOST_AUTH_METHOD", "trust")
            .start()
            .await
            .expect("postgres starts");
        let port = container.get_host_port_ipv4(5432.tcp()).await.expect("postgres publishes a port");

        let client = connect(port).await;
        client
            .batch_execute("create table profile (user_id text primary key, email text, company text)")
            .await
            .expect("the profile table is created");

        Self { _container: container, port, client }
    }

    async fn profiles(&self) -> i64 {
        self.client.query_one("select count(*) from profile", &[]).await.expect("counts profiles").get(0)
    }

    /// Connections Postgres currently has open other than this test's own --
    /// i.e. the ones the plugin's pool is holding.
    async fn plugin_backends(&self) -> i64 {
        self.client
            .query_one(
                "select count(*) from pg_stat_activity where datname = current_database() \
                 and pid <> pg_backend_pid() and backend_type = 'client backend'",
                &[],
            )
            .await
            .expect("counts backends")
            .get(0)
    }

    async fn backend_url(&self) -> (String, tokio::task::JoinHandle<()>) {
        let url = format!("postgres://{DB_USER}@127.0.0.1:{}/{DB_NAME}", self.port);
        let config = weaveauth::config::Config {
            extra_data_handler: Some(plugin_handler(PG_PROBE, env(&[("DATABASE_URL", &url)]), 20)),
            ..support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
        };
        spawn_backend(&config).await.expect("backend starts")
    }
}

/// Postgres logs "ready to accept connections" once while initialising and
/// again when it actually is, so the wait strategy alone can race the real
/// start -- retry briefly rather than depending on which line was matched.
async fn connect(port: u16) -> tokio_postgres::Client {
    let settings = format!("host=127.0.0.1 port={port} user={DB_USER} dbname={DB_NAME}");

    for attempt in 0..30 {
        match tokio_postgres::connect(&settings, tokio_postgres::NoTls).await {
            Ok((client, connection)) => {
                tokio::spawn(connection);
                return client;
            }
            Err(error) if attempt == 29 => panic!("postgres never accepted a connection: {error}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    unreachable!("the loop either returns or panics")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_writes_to_a_real_postgres() {
    let database = Database::start().await;
    let (backend_url, _handle) = database.backend_url().await;

    let status = register(&backend_url, "alice@example.com", &registration_fields("insert")).await;

    assert_eq!(status, reqwest::StatusCode::CREATED);
    assert_eq!(database.profiles().await, 1);
}

// What the process model is for: the plugin outlives a single call, so the
// second registration reuses the session the first one opened instead of
// handshaking again.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_registration_reuses_the_plugins_pooled_session() {
    let database = Database::start().await;
    let (backend_url, _handle) = database.backend_url().await;

    for email in ["alice@example.com", "bob@example.com"] {
        let status = register(&backend_url, email, &registration_fields("insert")).await;
        assert_eq!(status, reqwest::StatusCode::CREATED, "{email} was rejected");
    }

    assert_eq!(database.profiles().await, 2);
    assert_eq!(database.plugin_backends().await, 1, "the pool holds more than the one reused session");
}

// A rejection from Postgres itself, rather than a transport failure.
#[tokio::test(flavor = "multi_thread")]
async fn a_statement_postgres_rejects_fails_the_registration() {
    let database = Database::start().await;
    let (backend_url, _handle) = database.backend_url().await;
    database.client.batch_execute("drop table profile").await.expect("drops the table");

    let status = register(&backend_url, "alice@example.com", &registration_fields("insert")).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
}

// Recovery is the pool's job now, not WeaveAuth's: nothing in backend knows
// the connection existed.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_recovers_from_a_terminated_postgres_backend() {
    let database = Database::start().await;
    let (backend_url, _handle) = database.backend_url().await;

    let first = register(&backend_url, "alice@example.com", &registration_fields("insert")).await;
    assert_eq!(first, reqwest::StatusCode::CREATED);
    assert_eq!(database.plugin_backends().await, 1);
    database.client.batch_execute(TERMINATE_OTHERS).await.expect("terminates the pooled backend");

    let second = register(&backend_url, "bob@example.com", &registration_fields("insert")).await;

    assert_eq!(second, reqwest::StatusCode::CREATED, "the pool handed out a dead session");
    assert_eq!(database.profiles().await, 2, "the retry lost the row it was supposed to write");
}
