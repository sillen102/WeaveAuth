use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use weaveauth::config::Config;
use weaveauth::server::app;

fn test_config() -> Config {
    Config {
        port: 1983,
        redirect_uri_allowlist: vec!["http://bff.test/callback".to_string()],
        pkce_code_ttl_secs: 300,
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

#[tokio::test]
async fn health_returns_ok() {
    let resp = app(&test_config())
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn authorize_allows_allowlisted_redirect_uri_and_passes_through_state() {
    let resp = app(&test_config())
        .oneshot(
            Request::get(
                "/oauth/authorize?redirect_uri=http%3A%2F%2Fbff.test%2Fcallback&code_challenge=abc&code_challenge_method=S256&state=xyz",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();

    assert!(resp.status().is_redirection());
    let loc = location(&resp);
    assert!(loc.starts_with("http://bff.test/callback?code="));
    assert!(loc.ends_with("&state=xyz"));
}

#[tokio::test]
async fn authorize_omits_state_when_not_given() {
    let resp = app(&test_config())
        .oneshot(
            Request::get(
                "/oauth/authorize?redirect_uri=http%3A%2F%2Fbff.test%2Fcallback&code_challenge=abc&code_challenge_method=S256",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();

    assert!(resp.status().is_redirection());
    let loc = location(&resp);
    assert!(loc.starts_with("http://bff.test/callback?code="));
    assert!(!loc.contains("state="));
}

#[tokio::test]
async fn authorize_rejects_non_allowlisted_redirect_uri() {
    let resp = app(&test_config())
        .oneshot(
            Request::get(
                "/oauth/authorize?redirect_uri=http%3A%2F%2Fevil.test%2F&code_challenge=abc&code_challenge_method=S256",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Drives a real authorize -> extracts `code` -> returns it plus the verifier
/// whose SHA256 matches the challenge sent to /oauth/authorize.
async fn issue_code(app: axum::Router, code_challenge: &str) -> String {
    let resp = app
        .oneshot(
            Request::get(format!(
                "/oauth/authorize?redirect_uri=http%3A%2F%2Fbff.test%2Fcallback&code_challenge={code_challenge}&code_challenge_method=S256"
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
async fn token_exchange_rejects_wrong_verifier() {
    let app = app(&test_config());
    let challenge = challenge_for("correct-verifier");
    let code = issue_code(app.clone(), &challenge).await;

    let resp = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "code={code}&code_verifier=wrong-verifier&redirect_uri=http%3A%2F%2Fbff.test%2Fcallback"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn token_exchange_rejects_unknown_code() {
    let resp = app(&test_config())
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "code=never-issued&code_verifier=whatever&redirect_uri=http%3A%2F%2Fbff.test%2Fcallback",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn token_exchange_code_is_single_use() {
    let app = app(&test_config());
    let verifier = "correct-verifier";
    let challenge = challenge_for(verifier);
    let code = issue_code(app.clone(), &challenge).await;

    let first = app
        .clone()
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
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
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
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn token_exchange_rejects_mismatched_redirect_uri() {
    // The code was issued for http://bff.test/callback (see issue_code); presenting
    // any other redirect_uri at exchange time must fail even with the right verifier.
    let app = app(&test_config());
    let verifier = "correct-verifier";
    let challenge = challenge_for(verifier);
    let code = issue_code(app.clone(), &challenge).await;

    let resp = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "code={code}&code_verifier={verifier}&redirect_uri=http%3A%2F%2Fother.test%2F"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
