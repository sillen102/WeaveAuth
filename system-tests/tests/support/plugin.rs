//! Support for the plugin system tests: building the probe plugin, and a
//! stand-in Postgres so the socket capability can be exercised without a
//! Docker daemon.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use weaveauth::config::{ExtraDataHandlerConfig, PluginSocketsConfig};

pub const DB_USER: &str = "weaveauth";
pub const DB_NAME: &str = "appdata";

/// Builds `system-tests/tests/fixtures/plugins/pg-probe` for wasm32 and
/// returns the path to the module. Built once per test binary; the cargo
/// invocation is a no-op after the first, so the cost lands on whichever
/// test runs first.
pub fn pg_probe_path() -> PathBuf {
    static MODULE: OnceLock<PathBuf> = OnceLock::new();

    MODULE
        .get_or_init(|| {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/plugins/pg-probe");
            // An explicit target dir, because `~/.cargo/config.toml` points
            // every build at one shared directory -- which would both hide
            // the artifact and make this nested build contend for the outer
            // cargo's lock.
            let target_dir = root.join("target");

            let built = Command::new(env!("CARGO"))
                // Pinned, not inherited: other tests in this workspace chdir
                // into temp directories and delete them, so a concurrent
                // spawn can otherwise find no current directory at all.
                .current_dir(&root)
                .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
                .arg("--manifest-path")
                .arg(root.join("Cargo.toml"))
                .arg("--target-dir")
                .arg(&target_dir)
                .output()
                .expect("cargo runs");

            assert!(
                built.status.success(),
                "building the pg-probe plugin failed -- `rustup target add wasm32-unknown-unknown` if \
                 the target is missing:\n{}",
                String::from_utf8_lossy(&built.stderr)
            );

            let module = target_dir.join("wasm32-unknown-unknown/release/pg_probe.wasm");
            assert!(module.exists(), "the build reported success but produced no {}", module.display());
            module
        })
        .clone()
}

/// A backend `extra_data_handler` running the probe plugin, allowed to reach
/// exactly `allowed`.
pub fn plugin_handler(
    allowed: Vec<String>,
    timeout_secs: u64,
    sockets: PluginSocketsConfig,
) -> ExtraDataHandlerConfig {
    ExtraDataHandlerConfig::Wasm {
        path: pg_probe_path().display().to_string(),
        timeout_secs,
        memory_max_mb: 32,
        allowed_hosts: vec![],
        sockets: Some(PluginSocketsConfig { allowed, ..sockets }),
    }
}

pub fn socket_defaults() -> PluginSocketsConfig {
    PluginSocketsConfig {
        allowed: vec![],
        max_idle_per_endpoint: 8,
        max_open_per_call: 8,
        idle_timeout_ms: 30_000,
        io_timeout_ms: 2_000,
    }
}

/// The form fields a registration carries: the database target, plus which
/// behaviour the probe plugin should run.
pub fn registration_fields(port: u16, probe: &str) -> HashMap<String, String> {
    HashMap::from([
        ("db_host".to_string(), "127.0.0.1".to_string()),
        ("db_port".to_string(), port.to_string()),
        ("db_user".to_string(), DB_USER.to_string()),
        ("db_name".to_string(), DB_NAME.to_string()),
        ("company".to_string(), "Acme".to_string()),
        ("probe".to_string(), probe.to_string()),
    ])
}

/// Posts a registration to a real backend, returning the status.
pub async fn register(backend_url: &str, email: &str, fields: &HashMap<String, String>) -> reqwest::StatusCode {
    let mut body = serde_json::Map::new();
    body.insert("email".to_string(), serde_json::json!(email));
    body.insert("password".to_string(), serde_json::json!("hunter2-hunter2"));
    for (key, value) in fields {
        body.insert(key.clone(), serde_json::json!(value));
    }

    reqwest::Client::new()
        .post(format!("{backend_url}/register"))
        .json(&serde_json::Value::Object(body))
        .send()
        .await
        .expect("backend answers")
        .status()
}

/// How the stand-in server misbehaves, so a test can pick a failure mode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// Complete startup, answer every query.
    Normal,
    /// Accept a query and never answer it, so the read hits its timeout.
    Stall,
}

/// A stand-in Postgres: enough of the v3 protocol to complete a startup and
/// answer simple queries, so the probe plugin's own client is satisfied
/// without a container.
pub struct StandInPostgres {
    pub port: u16,
    sessions: Arc<AtomicUsize>,
    accepted: Arc<Mutex<Vec<TcpStream>>>,
}

impl StandInPostgres {
    pub fn start(behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("has an address").port();
        let sessions = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(Mutex::new(Vec::new()));

        let counter = sessions.clone();
        let held = accepted.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                counter.fetch_add(1, Ordering::SeqCst);
                if let (Ok(copy), Ok(mut held)) = (stream.try_clone(), held.lock()) {
                    held.push(copy);
                }
                std::thread::spawn(move || serve(stream, behaviour));
            }
        });

        Self { port, sessions, accepted }
    }

    /// An unbound port on the same host, for a dial that can only fail.
    pub fn dead_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("has an address").port();
        drop(listener);
        port
    }

    /// Closes every connection accepted so far -- what a server restart
    /// looks like to a connection sitting idle in the host's pool.
    pub fn hang_up_on_everything(&self) {
        let Ok(held) = self.accepted.lock() else { return };
        for stream in held.iter() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// How many TCP connections the server accepted -- one per *dial*, so a
    /// pooled connection doesn't add to it. This is what a system test has
    /// instead of reaching into the host's pool.
    pub fn sessions(&self) -> usize {
        self.sessions.load(Ordering::SeqCst)
    }
}

fn serve(mut stream: TcpStream, behaviour: Behaviour) {
    // Startup message: no tag byte, just a length and the parameters.
    let Some(header) = read_exact(&mut stream, 4) else { return };
    let length = i32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if read_exact(&mut stream, length - 4).is_none() {
        return;
    }

    // AuthenticationOk, then ReadyForQuery ('I' = idle).
    let mut ready = Vec::new();
    push_message(&mut ready, b'R', &0i32.to_be_bytes());
    push_message(&mut ready, b'Z', b"I");
    if stream.write_all(&ready).is_err() {
        return;
    }

    loop {
        let Some(header) = read_exact(&mut stream, 5) else { return };
        let length = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if read_exact(&mut stream, length - 4).is_none() {
            return;
        }
        if header[0] != b'Q' {
            continue;
        }
        if behaviour == Behaviour::Stall {
            std::thread::sleep(Duration::from_secs(60));
            return;
        }

        let mut reply = Vec::new();
        push_message(&mut reply, b'C', b"INSERT 0 1\0");
        push_message(&mut reply, b'Z', b"I");
        if stream.write_all(&reply).is_err() {
            return;
        }
    }
}

fn push_message(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(body);
}

fn read_exact(stream: &mut TcpStream, len: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).ok()?;
    Some(buffer)
}
