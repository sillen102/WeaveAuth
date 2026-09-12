use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use weaveauth::config::Config;
use weaveauth::server::app;

// Endpoint-level logic (allowlist checks, PKCE verification, single-use codes, ...) is
// unit-tested next to each handler in src/server/api/*.rs. This file only covers what
// those unit tests can't: real HTTP wiring -- routing, request parsing, and the
// response actually serialized over the wire.

fn test_config() -> Config {
    Config {
        port: 1983,
        redirect_uri_allowlist: vec!["http://bff.test/callback".to_string()],
        pkce_code_ttl_secs: 300,
        login_session_ttl_secs: 60,
    }
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn location(resp: &axum::response::Response) -> String {
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string()
}

/// Registers (idempotent-ish for test purposes) and logs in a user, returning
/// the `login_session` token `/oauth/authorize` requires.
async fn login_session(app: axum::Router, identifier: &str, password: &str) -> String {
    let _ = app
        .clone()
        .oneshot(
            Request::post("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": identifier, "password": password})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::post("/oauth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": identifier, "password": password})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    body["login_session"].as_str().unwrap().to_string()
}

/// Drives a real authorize -> extracts `code` -> returns it plus the verifier
/// whose SHA256 matches the challenge sent to /oauth/authorize.
async fn issue_code(app: axum::Router, code_challenge: &str) -> String {
    let login_session = login_session(app.clone(), "alice", "hunter2").await;

    let resp = app
        .oneshot(
            Request::get(format!(
                "/oauth/authorize?redirect_uri=http%3A%2F%2Fbff.test%2Fcallback&code_challenge={code_challenge}&code_challenge_method=S256&login_session={login_session}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let loc = location(&resp);
    url::Url::parse(&loc)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

fn challenge_for(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[tokio::test]
async fn token_exchange_full_round_trip() {
    let app = app(&test_config());
    let verifier = "correct-verifier";
    let challenge = challenge_for(verifier);
    let code = issue_code(app.clone(), &challenge).await;

    let resp = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "code={code}&code_verifier={verifier}&redirect_uri=http%3A%2F%2Fbff.test%2Fcallback"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_at"].is_string());
}

#[tokio::test]
async fn token_exchange_rejects_expired_code() {
    let mut config = test_config();
    config.pkce_code_ttl_secs = -1; // already "expired" the instant it's issued
    let app = app(&config);
    let verifier = "correct-verifier";
    let challenge = challenge_for(verifier);
    let code = issue_code(app.clone(), &challenge).await;

    let resp = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "code={code}&code_verifier={verifier}&redirect_uri=http%3A%2F%2Fbff.test%2Fcallback"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
