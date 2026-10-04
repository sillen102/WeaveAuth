//! Someone registers the owner's address first. The owner asks for a password
//! reset, the link reaches them through the deployer's email plugin, and
//! redeeming it hands them the account: the squatter's password and the login
//! session they already held both stop working, and the address counts as
//! verified.

use weaveauth_system_tests::support;

use std::collections::HashMap;

use support::config::FINAL_REDIRECT;
use support::plugin::{env, plugin_settings, register};
use support::servers::spawn_backend;

const PLUGIN: &str = env!("CARGO_BIN_EXE_probe-plugin");
const EMAIL: &str = "alice@example.com";
const SQUATTER_PASSWORD: &str = "hunter2-hunter2";
const NEW_PASSWORD: &str = "alices-own-password";
const LOGIN_URL: &str = "http://login.test";

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

async fn login(backend_url: &str, password: &str) -> (reqwest::StatusCode, serde_json::Value) {
    post(
        backend_url,
        "/oauth/login",
        serde_json::json!({"email": EMAIL, "password": password}),
    )
    .await
}

async fn authorize(backend_url: &str, login_session: &str) -> reqwest::StatusCode {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client builds")
        .get(format!("{backend_url}/oauth/authorize"))
        .query(&[
            ("redirect_uri", FINAL_REDIRECT),
            ("code_challenge", "challenge"),
            ("code_challenge_method", "S256"),
            ("login_session", login_session),
        ])
        .send()
        .await
        .expect("backend answers")
        .status()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_mailed_through_the_plugin_takes_a_squatted_account_back() {
    let out = std::env::temp_dir().join(format!("wa-reset-{}", uuid::Uuid::new_v4()));
    let config = weaveauth::config::Config {
        email_handler: Some(weaveauth::config::EmailHandlerConfig::Plugin(
            plugin_settings(
                PLUGIN,
                env(&[("EMAIL_OUT", out.to_str().expect("utf-8 path"))]),
                10,
            ),
        )),
        login_public_url: LOGIN_URL.to_string(),
        require_verified_email: false,
        ..support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
    };
    let (backend_url, _handle) = spawn_backend(&config).await.expect("backend starts");

    // The squatter registers the address and holds a login session.
    assert_eq!(
        register(&backend_url, EMAIL, &HashMap::new()).await,
        reqwest::StatusCode::CREATED
    );
    let (status, squatter) = login(&backend_url, SQUATTER_PASSWORD).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let squatter_session = squatter["login_session"].as_str().expect("a login session");
    // Registration's verification mail lands in the same file; clear it.
    for _ in 0..100 {
        if std::fs::remove_file(&out).is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // The owner asks for a reset, typing a tagged variant of the address.
    let (status, _) = post(
        &backend_url,
        "/oauth/password-reset/request",
        serde_json::json!({"email": "Alice+reset@Example.com"}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::ACCEPTED);
    let mut written = None;
    for _ in 0..100 {
        if let Ok(contents) = std::fs::read_to_string(&out) {
            written = Some(contents);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let written = written.expect("the plugin wrote the reset mail");
    let (recipient, reset_url) = written.split_once(' ').expect("recipient and link");
    assert_eq!(recipient, EMAIL);
    let token = reset_url
        .strip_prefix("http://login.test/reset-password.html#token=")
        .expect("the token travels in the fragment");

    let (status, _) = post(
        &backend_url,
        "/oauth/password-reset/confirm",
        serde_json::json!({"token": token, "new_password": NEW_PASSWORD}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    // Everything the squatter had is gone.
    assert!(
        authorize(&backend_url, squatter_session)
            .await
            .is_client_error()
    );
    assert_eq!(
        login(&backend_url, SQUATTER_PASSWORD).await.0,
        reqwest::StatusCode::UNAUTHORIZED
    );
    // The owner signs in, with the address now verified.
    let (status, owner) = login(&backend_url, NEW_PASSWORD).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(owner.get("verification_session").is_none(), "{owner}");
    let owner_session = owner["login_session"].as_str().expect("a login session");
    assert_eq!(
        authorize(&backend_url, owner_session).await,
        reqwest::StatusCode::SEE_OTHER
    );
    // The link was single-use.
    let (status, _) = post(
        &backend_url,
        "/oauth/password-reset/confirm",
        serde_json::json!({"token": token, "new_password": "yet-another-one"}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
}
