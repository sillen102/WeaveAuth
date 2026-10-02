//! Support for the plugin system tests: pointing backend at one of the probe
//! plugins, and posting registrations through it.

use std::collections::HashMap;

use weaveauth::config::{ExtraDataHandlerConfig, LoginClaimsHandlerConfig};

/// A backend `extra_data_handler` running `command`.
pub fn plugin_handler(
    command: &str,
    env: HashMap<String, String>,
    timeout_secs: u64,
) -> ExtraDataHandlerConfig {
    ExtraDataHandlerConfig::Plugin {
        command: command.to_string(),
        args: vec![],
        env,
        timeout_secs,
        startup_timeout_secs: 10,
        uid: current_id("-u"),
        gid: current_id("-g"),
    }
}

/// A backend `login_claims_handler` running `command`.
pub fn login_claims_handler(command: &str, timeout_secs: u64) -> LoginClaimsHandlerConfig {
    LoginClaimsHandlerConfig::Plugin {
        command: command.to_string(),
        args: vec![],
        env: HashMap::new(),
        timeout_secs,
        startup_timeout_secs: 10,
        uid: current_id("-u"),
        gid: current_id("-g"),
    }
}

/// This process's own uid (`-u`) or gid (`-g`): a plugin is always spawned
/// as some user, and switching to anyone else needs privileges a test run
/// doesn't have.
pub fn current_id(flag: &str) -> u32 {
    let output = std::process::Command::new("id")
        .arg(flag)
        .output()
        .expect("id runs");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("id prints a number")
}

pub fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

/// The form fields a registration carries: `probe` picks which behaviour the
/// probe plugin runs.
pub fn registration_fields(probe: &str) -> HashMap<String, String> {
    HashMap::from([
        ("company".to_string(), "Acme".to_string()),
        ("probe".to_string(), probe.to_string()),
    ])
}

/// Posts a registration to a real backend, returning the status.
pub async fn register(
    backend_url: &str,
    email: &str,
    fields: &HashMap<String, String>,
) -> reqwest::StatusCode {
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
