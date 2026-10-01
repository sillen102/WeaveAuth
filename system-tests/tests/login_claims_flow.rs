//! Drives a real plugin process through backend's real PKCE flow
//! (`/oauth/login` -> `/oauth/authorize` -> `/oauth/token`) with a
//! `login_claims_handler` configured, so the whole path -- HTTP, the token
//! service, the spawned process, the guest SDK, the gRPC contract -- is
//! exercised end to end, the same way `plugin_process_flow` covers
//! registration.
//!
//! A system test sees only HTTP status codes and JWT payloads, so each
//! behaviour is selected by the email's local part (see
//! `fixtures/plugins/probe.rs::handle_login_claims`).

use weaveauth_system_tests::support;

use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use support::config::FINAL_REDIRECT;
use support::plugin::login_claims_handler;
use support::servers::spawn_backend;

/// The probe plugin, built as a bin target of this package -- so it is
/// already compiled by the time a test runs, and always from this source
/// tree rather than a stale artifact. Only a test target sees this variable,
/// which is why it isn't in the library.
const PROBE: &str = env!("CARGO_BIN_EXE_probe-plugin");

const PASSWORD: &str = "hunter2-hunter2";

fn backend_config(timeout_secs: u64) -> weaveauth::config::Config {
    weaveauth::config::Config {
        login_claims_handler: Some(login_claims_handler(PROBE, timeout_secs)),
        ..support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
    }
}

async fn register(backend_url: &str, email: &str) {
    let status = reqwest::Client::new()
        .post(format!("{backend_url}/register"))
        .json(&serde_json::json!({"email": email, "password": PASSWORD}))
        .send()
        .await
        .expect("backend answers")
        .status();
    assert_eq!(status, reqwest::StatusCode::CREATED, "setup: registration should succeed");
}

async fn login_session(backend_url: &str, email: &str) -> String {
    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{backend_url}/oauth/login"))
        .json(&serde_json::json!({"email": email, "password": PASSWORD}))
        .send()
        .await
        .expect("backend answers")
        .json()
        .await
        .expect("valid JSON");
    body["login_session"].as_str().expect("login_session in response").to_string()
}

/// Runs `/oauth/login` -> `/oauth/authorize` -> `/oauth/token` for `email`
/// and returns the raw HTTP status of the final `/oauth/token` call plus its
/// JSON body -- callers that expect success decode `access_token` out of the
/// body, callers expecting failure just check the status.
async fn exchange_code_for_token(backend_url: &str, email: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let login_session = login_session(backend_url, email).await;
    let verifier = "correct-verifier-0123456789";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client builds");
    let authorize = client
        .get(format!("{backend_url}/oauth/authorize"))
        .query(&[
            ("redirect_uri", FINAL_REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("login_session", &login_session),
        ])
        .send()
        .await
        .expect("backend answers");
    assert_eq!(authorize.status(), reqwest::StatusCode::SEE_OTHER, "setup: authorize should issue a code");
    let location = authorize.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).expect("Location header");
    let code = url::Url::parse(location)
        .expect("valid redirect url")
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("code in redirect");

    let response = reqwest::Client::new()
        .post(format!("{backend_url}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", verifier),
            ("redirect_uri", FINAL_REDIRECT),
        ])
        .send()
        .await
        .expect("backend answers");
    let status = response.status();
    let body = response.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

fn decode_claims(access_token: &str) -> serde_json::Value {
    let payload = access_token.split('.').nth(1).expect("JWT has a payload segment");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("valid base64")).expect("valid JSON")
}

#[tokio::test(flavor = "multi_thread")]
async fn login_issues_a_token_with_the_plugins_claims_merged_in() {
    let (backend_url, _handle) = spawn_backend(&backend_config(10)).await.expect("backend starts");
    register(&backend_url, "alice@example.com").await;

    let (status, body) = exchange_code_for_token(&backend_url, "alice@example.com").await;

    assert_eq!(status, reqwest::StatusCode::OK);
    let claims = decode_claims(body["access_token"].as_str().expect("access_token in response"));
    assert_eq!(claims["roles"], serde_json::json!(["admin"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejecting_login_claims_plugin_fails_the_token_request() {
    let (backend_url, _handle) = spawn_backend(&backend_config(10)).await.expect("backend starts");
    register(&backend_url, "reject@example.com").await;

    let (status, _body) = exchange_code_for_token(&backend_url, "reject@example.com").await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY, "fail-closed: no token without the configured claims");
}

// A plugin spoofing an identity claim (here, `sub`) must not be allowed to
// win -- or silently lose -- a merge; the whole request fails instead.
#[tokio::test(flavor = "multi_thread")]
async fn a_reserved_claim_name_from_the_plugin_fails_the_token_request() {
    let (backend_url, _handle) = spawn_backend(&backend_config(10)).await.expect("backend starts");
    register(&backend_url, "reserved@example.com").await;

    let (status, _body) = exchange_code_for_token(&backend_url, "reserved@example.com").await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
}

// The plugin's deadline is WeaveAuth's, not the plugin's -- same reasoning as
// `plugin_process_flow`'s equivalent test for registration.
#[tokio::test(flavor = "multi_thread")]
async fn a_hung_login_claims_plugin_fails_the_token_request_within_its_timeout() {
    let (backend_url, _handle) = spawn_backend(&backend_config(1)).await.expect("backend starts");
    register(&backend_url, "stall@example.com").await;

    let started = Instant::now();
    let (status, _body) = exchange_code_for_token(&backend_url, "stall@example.com").await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert!(started.elapsed() < Duration::from_secs(20), "the call outlived its budget: {:?}", started.elapsed());
}

// The locked design decision -- "every token mint", not just the initial
// login -- proven end to end rather than only at the unit level.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_grant_also_carries_the_plugins_claims() {
    let (backend_url, _handle) = spawn_backend(&backend_config(10)).await.expect("backend starts");
    register(&backend_url, "alice@example.com").await;
    let (status, body) = exchange_code_for_token(&backend_url, "alice@example.com").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let refresh_token = body["refresh_token"].as_str().expect("refresh_token in response").to_string();

    let response = reqwest::Client::new()
        .post(format!("{backend_url}/oauth/token"))
        .form(&[("grant_type", "refresh_token"), ("refresh_token", &refresh_token)])
        .send()
        .await
        .expect("backend answers");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.expect("valid JSON");
    let claims = decode_claims(body["access_token"].as_str().expect("access_token in response"));
    assert_eq!(claims["roles"], serde_json::json!(["admin"]));
}
