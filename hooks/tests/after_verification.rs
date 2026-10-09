mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{Call, Harness, ID};

fn ok(_: &Call) -> (u16, Value) {
    (200, json!({}))
}

fn body() -> Value {
    json!({"identity_id": ID, "email": "alice@example.com"})
}

#[tokio::test]
async fn a_verified_email_is_forwarded_to_the_handler() {
    let mut harness = Harness::new().await;
    harness.config.verification_handler = Some(harness.webhook("verification", ok).await);

    let (status, _) = harness.post("/kratos/after-verification", body()).await;

    assert_eq!(status, StatusCode::OK);
    let calls = harness.log.of("verification");
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].body,
        json!({"user_id": ID, "email": "alice@example.com"})
    );
}

#[tokio::test]
async fn without_a_handler_the_hook_succeeds_and_calls_nobody() {
    let harness = Harness::new().await;

    let (status, _) = harness.post("/kratos/after-verification", body()).await;

    assert_eq!(status, StatusCode::OK);
    assert!(harness.log.calls().is_empty());
}

#[tokio::test]
async fn a_failing_handler_is_a_retryable_error_and_keeps_the_identity() {
    let mut harness = Harness::new().await;
    harness.config.verification_handler = Some(
        harness
            .webhook("verification", |_| (500, json!({"secret": "cause"})))
            .await,
    );

    let (status, response) = harness.post("/kratos/after-verification", body()).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(!response.to_string().contains("cause"), "{response}");
    assert!(
        harness.log.of("kratos").is_empty(),
        "the address is verified; the identity is left alone"
    );
}

#[tokio::test]
async fn a_refusal_is_swallowed_so_the_users_flow_goes_on() {
    for refusal in [400, 403, 422] {
        let mut harness = Harness::new().await;
        harness.config.verification_handler = Some(
            harness
                .webhook("verification", move |_| (refusal, json!({})))
                .await,
        );

        let (status, _) = harness.post("/kratos/after-verification", body()).await;

        assert_eq!(status, StatusCode::OK, "handler answered {refusal}");
        assert_eq!(harness.log.of("verification").len(), 1);
        assert!(harness.log.of("kratos").is_empty());
    }
}

#[tokio::test]
async fn a_handler_status_that_is_not_a_refusal_is_retryable() {
    for status in [401, 404, 429] {
        let mut harness = Harness::new().await;
        harness.config.verification_handler = Some(
            harness
                .webhook("verification", move |_| (status, json!({})))
                .await,
        );

        let (answer, _) = harness.post("/kratos/after-verification", body()).await;

        assert_eq!(answer, StatusCode::BAD_GATEWAY, "handler answered {status}");
    }
}

#[tokio::test]
async fn an_identity_id_that_is_not_a_uuid_never_reaches_the_handler() {
    let mut harness = Harness::new().await;
    harness.config.verification_handler = Some(harness.webhook("verification", ok).await);

    let (status, _) = harness
        .post(
            "/kratos/after-verification",
            json!({"identity_id": "../x", "email": "alice@example.com"}),
        )
        .await;

    assert!(status.is_client_error(), "{status}");
    assert!(harness.log.of("verification").is_empty());
}
