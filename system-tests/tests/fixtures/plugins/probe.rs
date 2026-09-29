//! A plugin that does whatever a request's `probe` field (registration) or
//! email local part (login claims) tells it to, so a system test can drive
//! one failure mode at a time through backend's real endpoints.
//!
//! Built as a bin target of this package, so `cargo test` produces it and
//! the tests find it through `CARGO_BIN_EXE_probe-plugin`.

use std::time::Duration;

use weaveauth_plugin_sdk::{Plugin, PluginRequest, PluginResponse, Request, Response, Status, serve};

struct Probe;

#[weaveauth_plugin_sdk::async_trait]
impl Plugin for Probe {
    async fn invoke(&self, request: Request<PluginRequest>) -> Result<Response<PluginResponse>, Status> {
        let request = request.into_inner();
        match request.hook.as_str() {
            "registration" => handle_registration(&request).await,
            "login_claims" => handle_login_claims(&request).await,
            other => Err(Status::unimplemented(format!("unhandled hook {other:?}"))),
        }
    }
}

async fn handle_registration(request: &PluginRequest) -> Result<Response<PluginResponse>, Status> {
    match string_field(request, "probe") {
        Some("accept") | None => {}
        Some("reject") => return Err(Status::invalid_argument("the probe was told to reject")),
        // Outlives any timeout a test configures, so only WeaveAuth's own
        // deadline can end the call.
        Some("stall") => tokio::time::sleep(Duration::from_secs(600)).await,
        // Dies without answering: the request in flight fails, and the next
        // one only succeeds if WeaveAuth restarted the process.
        Some("crash") => std::process::exit(1),
        Some("sleep") => tokio::time::sleep(Duration::from_millis(sleep_ms(request))).await,
        Some("env") => check_environment()?,
        Some(other) => return Err(Status::invalid_argument(format!("unknown probe {other:?}"))),
    }
    Ok(Response::new(PluginResponse { data: None }))
}

async fn handle_login_claims(request: &PluginRequest) -> Result<Response<PluginResponse>, Status> {
    match request.email.split('@').next() {
        Some("reject") => return Err(Status::invalid_argument("the probe was told to reject")),
        // Same reasoning as `handle_registration`'s "stall".
        Some("stall") => tokio::time::sleep(Duration::from_secs(600)).await,
        Some("reserved") => return Ok(Response::new(PluginResponse { data: Some(reserved_claim()) })),
        _ => {}
    }
    Ok(Response::new(PluginResponse { data: Some(roles_claim()) }))
}

fn sleep_ms(request: &PluginRequest) -> u64 {
    string_field(request, "sleep_ms").and_then(|value| value.parse().ok()).unwrap_or(500)
}

/// Reads a string-valued field out of `request.data`, mirroring how
/// registration's old `map<string, string> fields` was read.
fn string_field<'a>(request: &'a PluginRequest, key: &str) -> Option<&'a str> {
    let value = request.data.as_ref()?.fields.get(key)?;
    match &value.kind {
        Some(prost_types::value::Kind::StringValue(string)) => Some(string.as_str()),
        _ => None,
    }
}

fn roles_claim() -> prost_types::Struct {
    prost_types::Struct {
        fields: [(
            "roles".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::ListValue(prost_types::ListValue {
                    values: vec![prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue("admin".to_string())),
                    }],
                })),
            },
        )]
        .into(),
    }
}

/// A claim name that collides with one of the JWT's own reserved claims --
/// exercises WeaveAuth's rejection of a plugin trying to spoof identity.
fn reserved_claim() -> prost_types::Struct {
    prost_types::Struct {
        fields: [(
            "sub".to_string(),
            prost_types::Value { kind: Some(prost_types::value::Kind::StringValue("attacker-controlled".to_string())) },
        )]
        .into(),
    }
}

/// Accepts only if WeaveAuth handed over exactly the configured environment.
/// `PATH` and `HOME` are always set in the process that spawned WeaveAuth, so
/// seeing either means the plugin inherited the parent's environment --
/// which is where WeaveAuth's own signing keys and client secrets live.
fn check_environment() -> Result<(), Status> {
    for leaked in ["PATH", "HOME"] {
        if std::env::var_os(leaked).is_some() {
            return Err(Status::permission_denied(format!("inherited {leaked} from WeaveAuth")));
        }
    }
    match std::env::var("PLUGIN_CONFIGURED").as_deref() {
        Ok("yes") => Ok(()),
        _ => Err(Status::failed_precondition("the configured environment never arrived")),
    }
}

#[tokio::main]
async fn main() -> Result<(), weaveauth_plugin_sdk::ServeError> {
    serve(Probe).await
}
