use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use tower::ServiceExt;
use weaveauth_bff::config::Config;
use weaveauth_bff::server::app;

fn test_config(backend_url: String) -> Config {
    Config {
        port: 8080,
        bff_url: "http://bff.test".into(),
        backend_url,
        session_cookie_name: "wa_session".into(),
        routes: vec![],
    }
}

/// Stands in for backend: a real (in-process) /oauth/authorize + /oauth/token,
/// since bff drives the whole exchange server-to-server and needs a real
/// redirect response to read `code` out of. Mirrors backend's allowlist check
/// (only "http://admin.test" / "http://admin.test/" are allowed).
async fn stub_backend() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .route(
            "/oauth/authorize",
            get(
                |axum::extract::Query(q): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
                    assert!(q.get("code_challenge").is_some());
                    assert_eq!(
                        q.get("code_challenge_method").map(String::as_str),
                        Some("S256")
                    );
                    let redirect_uri = q.get("redirect_uri").unwrap();
                    if redirect_uri != "http://admin.test" && redirect_uri != "http://admin.test/"
                    {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    Ok(axum::response::Redirect::to(&format!(
                        "{redirect_uri}?code=stub-code"
                    )))
                },
            ),
        )
        .route(
            "/oauth/token",
            post(|Form(body): Form<serde_json::Value>| async move {
                assert!(body["code"].is_string());
                assert!(body["code_verifier"].is_string());
                assert_eq!(body["grant_type"], "authorization_code");
                Json(serde_json::json!({
                    "access_token": "test-access-token",
                    "refresh_token": "test-refresh-token",
                    "token_type": "Bearer",
                    "expires_at": chrono::Utc::now() + chrono::Duration::minutes(15),
                }))
            }),
        );
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn login_exchanges_code_sets_session_cookie_and_redirects_without_token_in_url() {
    let (backend, _h) = stub_backend().await;
    let app = app(test_config(backend));

    let resp = app
        .oneshot(
            Request::get("/login?redirect_uri=http%3A%2F%2Fadmin.test%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert_eq!(loc, "http://admin.test/");
    assert!(!loc.contains("access_token"));

    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(set_cookie.starts_with("wa_session="));
    assert!(set_cookie.contains("HttpOnly"));
}

#[tokio::test]
async fn login_requires_redirect_uri() {
    let (backend, _h) = stub_backend().await;
    let app = app(test_config(backend));

    let resp = app
        .oneshot(Request::get("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_forwards_redirect_uri_to_backend_and_rejects_when_backend_does() {
    // A rejected redirect_uri (no code, no token) surfaces as 400, not a generic
    // gateway failure.
    let (backend, _h) = stub_backend().await;
    let app = app(test_config(backend));

    let resp = app
        .oneshot(
            Request::get("/login?redirect_uri=http%3A%2F%2Fevil.test%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_rejects_redirect_uri_backend_does_not_allowlist_even_when_it_points_at_bff_itself() {
    // A redirect_uri pointing at bff's own proxy routes (e.g. /downstream) fails
    // unless backend's allowlist includes it.
    let (backend, _h) = stub_backend().await;
    let app = app(test_config(backend));

    let resp = app
        .oneshot(
            Request::get("/login?redirect_uri=http%3A%2F%2Fbff.test%2Fdownstream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_returns_bad_gateway_when_backend_is_unreachable_or_broken() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route(
        "/oauth/authorize",
        get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
    );
    let _h = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let app = app(test_config(format!("http://{addr}")));

    let resp = app
        .oneshot(
            Request::get("/login?redirect_uri=http%3A%2F%2Fadmin.test%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn login_returns_bad_request_when_backend_token_exchange_fails() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .route(
            "/oauth/authorize",
            get(
                |axum::extract::Query(q): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    let redirect_uri = q.get("redirect_uri").unwrap();
                    axum::response::Redirect::to(&format!("{redirect_uri}?code=stub-code"))
                },
            ),
        )
        .route(
            "/oauth/token",
            post(|| async { StatusCode::BAD_REQUEST }),
        );
    let _h = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let app = app(test_config(format!("http://{addr}")));

    let resp = app
        .oneshot(
            Request::get("/login?redirect_uri=http%3A%2F%2Fadmin.test%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_never_redirects_the_browser_to_backend() {
    let (backend, _h) = stub_backend().await;
    let app = app(test_config(backend.clone()));

    let resp = app
        .oneshot(
            Request::get("/login?redirect_uri=http%3A%2F%2Fadmin.test%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // The only response the browser ever sees is the final redirect straight to
    // the caller's redirect_uri -- never to backend.
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(!loc.starts_with(&backend));
}
