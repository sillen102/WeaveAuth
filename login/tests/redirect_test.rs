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
async fn login_redirects_to_bff() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/login?redirect_uri=http%3A%2F%2Fadmin.test%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(resp.status().is_redirection());
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(loc.starts_with("http://bff.test/login?"));
    assert!(loc.contains("redirect_uri=http%3A%2F%2Fadmin.test%2F"));
}

#[tokio::test]
async fn login_requires_redirect_uri() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
    assert!(body.contains("Sign in"));
    assert!(body.contains("id=\"sign-in\""));
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
