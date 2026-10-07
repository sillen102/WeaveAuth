use axum::http::StatusCode;
use axum::response::IntoResponse;
use common_macros::ErrorResponses;
use thiserror::Error;

#[derive(Debug, Error, ErrorResponses)]
enum Sample {
    #[error("internal wording: db is down")]
    #[error_response(StatusCode::SERVICE_UNAVAILABLE, details = "Try again later")]
    Unit,
    #[error("plain wording")]
    #[error_response(StatusCode::NOT_FOUND)]
    Plain,
    #[error("cause: {0}")]
    #[error_response(StatusCode::BAD_GATEWAY, details = "Upstream failed")]
    Tuple(String),
    #[error("cause: {cause}")]
    #[error_response(StatusCode::CONFLICT, details = "Conflict")]
    Named { cause: String },
}

async fn answer(error: Sample) -> (StatusCode, String, String) {
    let response = error.into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (
        status,
        body["reason"].as_str().unwrap().to_string(),
        body["details"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn a_unit_variant_answers_its_details_not_its_display() {
    let (status, reason, details) = answer(Sample::Unit).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason, "Unit");
    assert_eq!(details, "Try again later");
}

#[tokio::test]
async fn a_unit_variant_without_details_answers_its_display() {
    let (status, reason, details) = answer(Sample::Plain).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(reason, "Plain");
    assert_eq!(details, "plain wording");
}

#[tokio::test]
async fn a_variant_with_data_never_leaks_its_cause() {
    let (status, reason, details) = answer(Sample::Tuple("secret".into())).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(reason, "Tuple");
    assert_eq!(details, "Upstream failed");

    let (status, reason, details) = answer(Sample::Named {
        cause: "secret".into(),
    })
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason, "Named");
    assert_eq!(details, "Conflict");
}
