//! Registration sends a verification code through whichever handler the
//! deployer configured -- a plugin or a webhook -- and entering it (with the
//! account's credentials) unlocks login when the deployment requires verified
//! emails. The SMTP handler is covered by backend's own tests against a fake
//! server.

use weaveauth_system_tests::support;

use std::collections::HashMap;

use support::config::FINAL_REDIRECT;
use support::plugin::{env, plugin_settings, register};
use support::servers::spawn_backend;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PLUGIN: &str = env!("CARGO_BIN_EXE_probe-plugin");
const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "hunter2-hunter2";
const LOGIN_URL: &str = "http://login.test";

fn backend_config(handler: weaveauth::config::EmailHandlerConfig) -> weaveauth::config::Config {
    weaveauth::config::Config {
        email_handler: Some(handler),
        login_public_url: LOGIN_URL.to_string(),
        require_verified_email: true,
        ..support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
    }
}

async fn post(
    backend_url: &str,
    path: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let response = reqwest::Client::new()
        .post(format!("{backend_url}{path}"))
        .json(&body)
        .send()
        .await
        .expect("backend answers");
    let status = response.status();
    (status, response.json().await.unwrap_or_default())
}

async fn login(backend_url: &str) -> serde_json::Value {
    let (status, body) = post(
        backend_url,
        "/oauth/login",
        serde_json::json!({"email": EMAIL, "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    body
}

async fn confirm(
    backend_url: &str,
    session: &str,
    code: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    post(
        backend_url,
        "/oauth/email-verification/confirm",
        serde_json::json!({"verification_session": session, "code": code}),
    )
    .await
}

/// Registers, checks login withholds the login session, then enters a wrong
/// code, an unknown session and finally the delivered code, which releases the
/// login session and makes later logins ordinary.
async fn assert_full_flow(backend_url: &str, delivered_code: impl AsyncFnOnce() -> String) {
    assert_eq!(
        register(backend_url, EMAIL, &HashMap::new()).await,
        reqwest::StatusCode::CREATED
    );
    let first = login(backend_url).await;
    assert!(first.get("login_session").is_none(), "{first}");
    let session = first["verification_session"]
        .as_str()
        .expect("a verification session");

    let code = delivered_code().await;
    assert_eq!(code.len(), 9);
    let wrong = if code == "000000000" {
        "000000001"
    } else {
        "000000000"
    };
    assert_eq!(
        confirm(backend_url, session, wrong).await.0,
        reqwest::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        confirm(backend_url, "unknown", &code).await.0,
        reqwest::StatusCode::UNAUTHORIZED
    );

    let (status, released) = confirm(backend_url, session, &code).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(
        released["login_session"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "{released}"
    );
    // The verification session is spent.
    assert_eq!(
        confirm(backend_url, session, &code).await.0,
        reqwest::StatusCode::UNAUTHORIZED
    );

    let later = login(backend_url).await;
    assert!(later["login_session"].as_str().is_some(), "{later}");
    assert!(later.get("verification_session").is_none(), "{later}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_receives_the_code_and_entering_it_unlocks_login() {
    let out = std::env::temp_dir().join(format!("wa-email-{}", uuid::Uuid::new_v4()));
    let config = backend_config(weaveauth::config::EmailHandlerConfig::Plugin(
        plugin_settings(
            PLUGIN,
            env(&[("EMAIL_OUT", out.to_str().expect("utf-8 path"))]),
            10,
        ),
    ));
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    assert_full_flow(&backend_url, async || {
        // The send runs in the background, so wait for the plugin to write it.
        for _ in 0..100 {
            if let Ok(written) = std::fs::read_to_string(&out) {
                let (email, code) = written.split_once(' ').expect("email and code");
                assert_eq!(email, EMAIL);
                return code.to_string();
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the plugin never wrote the code");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_webhook_receives_the_code_and_entering_it_unlocks_login() {
    let hook = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&hook)
        .await;
    let config = backend_config(weaveauth::config::EmailHandlerConfig::Webhook(
        weaveauth::config::WebhookConfig {
            url: format!("{}/hook", hook.uri()),
            timeout_secs: 5,
        },
    ));
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    assert_full_flow(&backend_url, async || {
        for _ in 0..100 {
            let requests = hook.received_requests().await.expect("recording is on");
            if let Some(request) = requests.first() {
                let body: serde_json::Value = request.body_json().expect("json body");
                assert_eq!(body["email"], EMAIL);
                assert_eq!(
                    body["verify_page_url"],
                    format!("{LOGIN_URL}/verify-email.html")
                );
                assert!(
                    body["expires_at"]
                        .as_str()
                        .is_some_and(|s| s.ends_with('Z'))
                );
                return body["code"].as_str().expect("a code").to_string();
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the webhook was never called");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_handler_does_not_fail_registration_and_resend_respects_the_cooldown() {
    let hook = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&hook)
        .await;
    let config = backend_config(weaveauth::config::EmailHandlerConfig::Webhook(
        weaveauth::config::WebhookConfig {
            url: format!("{}/hook", hook.uri()),
            timeout_secs: 5,
        },
    ));
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    assert_eq!(
        register(&backend_url, EMAIL, &HashMap::new()).await,
        reqwest::StatusCode::CREATED
    );
    // Logging in sends a code too, but registration just did: inside the cooldown, so no second mail.
    let session = login(&backend_url).await["verification_session"]
        .as_str()
        .expect("a verification session")
        .to_string();
    let (status, body) = post(
        &backend_url,
        "/oauth/email-verification/request",
        serde_json::json!({"verification_session": session}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::ACCEPTED);
    assert_eq!(body["status"], "cooling_down");
    let retry_after = body["retry_after_secs"].as_i64().expect("seconds to wait");
    assert!((1..=60).contains(&retry_after), "{body}");
    let (status, _) = post(
        &backend_url,
        "/oauth/email-verification/request",
        serde_json::json!({"verification_session": "unknown"}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        hook.received_requests()
            .await
            .expect("recording is on")
            .len(),
        1
    );
}
