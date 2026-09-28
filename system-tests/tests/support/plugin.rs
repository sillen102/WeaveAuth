//! Support for the plugin system tests: pointing backend at one of the probe
//! plugins, and posting registrations through it.

use std::collections::HashMap;

use weaveauth::config::ExtraDataHandlerConfig;

/// The probe plugin, built as a bin target of this package -- so it is
/// already compiled by the time a test runs, and always from this source
/// tree rather than a stale artifact.
pub const PROBE: &str = env!("CARGO_BIN_EXE_probe-plugin");

/// A backend `extra_data_handler` running `command`.
pub fn plugin_handler(command: &str, env: HashMap<String, String>, timeout_secs: u64) -> ExtraDataHandlerConfig {
    ExtraDataHandlerConfig::Process {
        command: command.to_string(),
        args: vec![],
        env,
        timeout_secs,
        startup_timeout_secs: 10,
    }
}

pub fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
}

/// The form fields a registration carries: `probe` picks which behaviour the
/// probe plugin runs.
pub fn registration_fields(probe: &str) -> HashMap<String, String> {
    HashMap::from([("company".to_string(), "Acme".to_string()), ("probe".to_string(), probe.to_string())])
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
