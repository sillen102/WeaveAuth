//! A plugin that does whatever the registration's `probe` field tells it to,
//! so a system test can drive one failure mode at a time through backend's
//! real `POST /register`.
//!
//! Built as a bin target of this package, so `cargo test` produces it and
//! the tests find it through `CARGO_BIN_EXE_probe-plugin`.

use std::time::Duration;

use weaveauth_plugin_sdk::{
    HandleRegistrationRequest, HandleRegistrationResponse, Plugin, Request, Response, Status, serve,
};

struct Probe;

#[weaveauth_plugin_sdk::async_trait]
impl Plugin for Probe {
    async fn handle_registration(
        &self,
        request: Request<HandleRegistrationRequest>,
    ) -> Result<Response<HandleRegistrationResponse>, Status> {
        let registration = request.into_inner();

        match registration.fields.get("probe").map(String::as_str) {
            Some("accept") | None => {}
            Some("reject") => return Err(Status::invalid_argument("the probe was told to reject")),
            // Outlives any timeout a test configures, so only WeaveAuth's
            // own deadline can end the call.
            Some("stall") => tokio::time::sleep(Duration::from_secs(600)).await,
            // Dies without answering: the request in flight fails, and the
            // next one only succeeds if WeaveAuth restarted the process.
            Some("crash") => std::process::exit(1),
            Some("sleep") => tokio::time::sleep(Duration::from_millis(sleep_ms(&registration))).await,
            Some("env") => check_environment()?,
            Some(other) => return Err(Status::invalid_argument(format!("unknown probe {other:?}"))),
        }

        Ok(Response::new(HandleRegistrationResponse {}))
    }
}

fn sleep_ms(registration: &HandleRegistrationRequest) -> u64 {
    registration.fields.get("sleep_ms").and_then(|value| value.parse().ok()).unwrap_or(500)
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
