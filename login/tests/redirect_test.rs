use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use weaveauth_login::{app, Config};

fn test_config() -> Config {
    Config {
        port: 8081,
        bff_url: "http://bff.test".into(),
    }
}

#[tokio::test]
async fn config_js_exposes_bff_url() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/config.js").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("window.BFF_URL = \"http://bff.test\";"));
}

#[tokio::test]
async fn serves_static_index_page_at_root() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("id=\"login-form\""));
    assert!(body.contains("id=\"register-link\""));
    assert!(body.contains("id=\"google-login-link\""));
}

#[tokio::test]
async fn serves_static_register_page() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/register.html").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("id=\"register-form\""));
    assert!(body.contains("id=\"google-login-link\""));
}

#[tokio::test]
async fn serves_static_stylesheet() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/style.css").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_path_is_not_found() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
