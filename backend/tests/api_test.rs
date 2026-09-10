use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn health_check() {
    let app = weaveauth::app();

    let response = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cors_reflects_configured_origin() {
    let app = weaveauth::app_with_cors(&["http://localhost:1984".to_string()]);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("Origin", "http://localhost:1984")
                .header("Access-Control-Request-Method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.headers().get("access-control-allow-origin").unwrap(),
        "http://localhost:1984"
    );
}
