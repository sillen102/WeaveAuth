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
        redirect_uri_allowlist: vec!["http://bff.test/callback".to_string()],
        ..Config::default()
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
async fn login_session(app: axum::Router, email: &str, password: &str) -> String {
    let _ = app
        .clone()
        .oneshot(
            Request::post("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
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
                    serde_json::json!({"email": email, "password": password}).to_string(),
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
    let login_session = login_session(app.clone(), "alice@example.com", "hunter2").await;

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
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[tokio::test]
async fn token_exchange_full_round_trip() {
    let app = app(&test_config()).await.expect("test app builds");
    let verifier = "correct-verifier";
    let challenge = challenge_for(verifier);
    let code = issue_code(app.clone(), &challenge).await;

    let resp = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri=http%3A%2F%2Fbff.test%2Fcallback"
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
async fn password_reset_request_returns_accepted_over_http() {
    let app = app(&test_config()).await.expect("test app builds");

    let resp = app
        .oneshot(
            Request::post("/oauth/password-reset/request")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": "alice@example.com"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn password_reset_confirm_rejects_an_unknown_token_over_http() {
    let app = app(&test_config()).await.expect("test app builds");

    let resp = app
        .oneshot(
            Request::post("/oauth/password-reset/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"token": "no-such-token", "new_password": "new-password"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn token_exchange_rejects_expired_code() {
    let mut config = test_config();
    config.tuning.pkce_code_ttl_secs = -1; // already "expired" the instant it's issued
    let app = app(&config).await.expect("test app builds");
    let verifier = "correct-verifier";
    let challenge = challenge_for(verifier);
    let code = issue_code(app.clone(), &challenge).await;

    let resp = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri=http%3A%2F%2Fbff.test%2Fcallback"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_rejects_extra_fields_over_http_when_no_handler_is_configured() {
    let app = app(&test_config()).await.expect("test app builds");

    let resp = app
        .oneshot(
            Request::post("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": "extra@example.com", "password": "hunter2", "company": "Acme"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["reason"], "ExtraDataNotSupported");
}

#[tokio::test]
async fn oidc_login_takes_the_provider_as_a_query_param() {
    let app = app(&test_config()).await.expect("test app builds");

    let missing = app
        .clone()
        .oneshot(
            Request::get("/oauth/oidc/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let unknown = app
        .oneshot(
            Request::get("/oauth/oidc/login?provider=nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(missing).await["details"], "invalid request");
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(unknown).await["details"], "unknown oidc provider");
}

#[tokio::test]
async fn oidc_callback_takes_the_provider_as_a_query_param() {
    let app = app(&test_config()).await.expect("test app builds");

    let missing = app
        .clone()
        .oneshot(
            Request::get("/oauth/oidc/callback?code=c&state=s")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let unstored_state = app
        .oneshot(
            Request::get("/oauth/oidc/callback?provider=nope&code=c&state=s")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(missing).await["details"], "invalid request");
    assert_eq!(unstored_state.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(unstored_state).await["details"],
        "invalid or expired oidc state"
    );
}

#[tokio::test]
async fn malformed_input_is_rejected_as_json_on_every_extractor_kind() {
    let app = app(&test_config()).await.expect("test app builds");
    let cases = [
        // Json
        Request::post("/oauth/login")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
        // Form
        Request::post("/oauth/token")
            .header("content-type", "text/plain")
            .body(Body::from("grant_type=authorization_code"))
            .unwrap(),
        // Query
        Request::get("/oauth/authorize")
            .body(Body::empty())
            .unwrap(),
    ];

    for req in cases {
        let uri = req.uri().to_string();
        let resp = app.clone().oneshot(req).await.unwrap();

        assert!(resp.status().is_client_error(), "{uri}: {}", resp.status());
        assert_eq!(body_json(resp).await["reason"], "InvalidRequest", "{uri}");
    }
}

#[tokio::test]
async fn openapi_documents_the_invalid_request_rejection_on_json_routes() {
    let app = app(&test_config()).await.expect("test app builds");

    let resp = app
        .oneshot(Request::get("/openapi.json").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let spec = body_json(resp).await;
    let responses = &spec["paths"]["/oauth/login"]["post"]["responses"];
    for status in ["400", "415", "422"] {
        assert_eq!(
            responses[status]["description"], "invalid request",
            "{status}"
        );
    }
}

#[tokio::test]
async fn openapi_keeps_invalid_request_on_endpoints_that_already_document_a_400() {
    let app = app(&test_config()).await.expect("test app builds");

    let resp = app
        .oneshot(Request::get("/openapi.json").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let spec = body_json(resp).await;
    for (path, method) in [
        ("/oauth/authorize", "get"),
        ("/oauth/oidc/callback", "get"),
        ("/register", "post"),
        ("/oauth/token", "post"),
    ] {
        let response = &spec["paths"][path][method]["responses"]["400"];
        let examples = &response["content"]["application/json"]["examples"];
        assert!(
            examples["InvalidRequest"].is_object(),
            "{path}: 400 lacks the InvalidRequest example: {response}"
        );
    }
}

/// aide drops spec problems (such as a conflicting inferred response) unless
/// a handler is registered, so a docs regression would otherwise be silent.
#[tokio::test]
async fn openapi_generation_reports_no_errors() {
    aide::generate::on_error(|err| panic!("openapi generation error: {err}"));

    let _app = app(&test_config()).await.expect("test app builds");
}

#[tokio::test]
async fn discovery_document_is_served_and_its_jwks_uri_resolves() {
    let app = app(&test_config()).await.unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::get("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["issuer"], "http://localhost:1983");
    let jwks_path = body["jwks_uri"]
        .as_str()
        .unwrap()
        .strip_prefix("http://localhost:1983")
        .unwrap()
        .to_string();

    let resp = app
        .oneshot(Request::get(jwks_path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!body_json(resp).await["keys"].as_array().unwrap().is_empty());
}
