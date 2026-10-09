mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{Harness, ID, send};

const PROTECTED: [&str; 5] = [
    "/hydra/token-hook",
    "/kratos/after-registration",
    "/kratos/after-recovery",
    "/kratos/after-password-change",
    "/kratos/after-verification",
];

fn recovery_body() -> serde_json::Value {
    json!({"identity_id": ID})
}

#[tokio::test]
async fn health_needs_no_key() {
    let harness = Harness::new().await;

    let (status, _) = send(harness.app(), "GET", "/health", None, json!(null)).await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn every_route_refuses_a_request_without_the_key_and_calls_nothing() {
    let harness = Harness::new().await;
    let wrong = [
        None,
        Some("wrong-key"),
        Some(""),
        Some("hooks-key-for-tests-and-more"),
    ];

    for path in PROTECTED {
        for key in wrong {
            let (status, body) = send(harness.app(), "POST", path, key, recovery_body()).await;

            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} with {key:?}");
            assert_eq!(body["reason"], "Unauthorized");
        }
    }
    assert!(harness.log.calls().is_empty());
}

#[tokio::test]
async fn a_key_in_another_scheme_is_refused() {
    let harness = Harness::new().await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/kratos/after-recovery")
        .header("content-type", "application/json")
        .header("authorization", format!("Basic {}", support::HOOKS_KEY))
        .body(axum::body::Body::from(recovery_body().to_string()))
        .unwrap();

    let response = tower::ServiceExt::oneshot(harness.app(), request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_right_key_gets_through_to_the_handler() {
    let harness = Harness::new().await;

    let (status, _) = harness
        .post("/kratos/after-recovery", recovery_body())
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!harness.log.calls().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_that_takes_longer_than_the_timeout_is_cut_off() {
    let mut harness = Harness::new().await;
    harness.config.request_timeout_secs = 1;
    let slow = harness
        .webhook("slow", |_| {
            std::thread::sleep(std::time::Duration::from_millis(1800));
            (200, json!({}))
        })
        .await;
    harness.config.upstream_timeout_secs = 5;
    harness.config.login_claims_handler = Some(slow);

    let (status, _) = harness
        .post("/hydra/token-hook", support::token_hook_body(ID))
        .await;

    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
}
