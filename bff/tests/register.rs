use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use std::net::SocketAddr;
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
        trusted_origins: vec!["http://login.test".into()],
        rate_limit_max_attempts: 1000,
        rate_limit_window_secs: 60,
    }
}

/// tower_governor's `PeerIpKeyExtractor` reads `ConnectInfo<SocketAddr>`,
/// which `axum::serve` only populates via `into_make_service_with_connect_info`
/// -- these tests call the router directly via `oneshot`, so it has to be
/// inserted by hand.
fn with_test_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

/// Stub backend accepting only identifier "taken" as already registered.
async fn stub_backend() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route(
        "/register",
        post(|Json(body): Json<serde_json::Value>| async move {
            if body["identifier"] == "taken" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::CREATED
            }
        }),
    );
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

fn register_request(identifier: &str, next: &str) -> Request<Body> {
    with_test_peer(
        Request::post("/register")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", "http://login.test")
            .body(Body::from(format!(
                "identifier={identifier}&password=hunter2&next={}",
                url::form_urlencoded::byte_serialize(next.as_bytes()).collect::<String>()
            )))
            .unwrap(),
    )
}

#[tokio::test]
async fn redirects_to_next_on_success() {
    let (backend, _h) = stub_backend().await;
    let app = app(test_config(backend));

    let resp = app
        .oneshot(register_request("alice", "http://login.test/"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://login.test/"));
}

#[tokio::test]
async fn appends_error_query_param_when_backend_rejects() {
    let (backend, _h) = stub_backend().await;
    let app = app(test_config(backend));

    let resp = app
        .oneshot(register_request("taken", "http://login.test/register.html"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://login.test/register.html?error=1"));
}

#[tokio::test]
async fn rejects_an_untrusted_origin() {
    let app = app(test_config("http://127.0.0.1:1".into()));

    let resp = app
        .oneshot(with_test_peer(
            Request::post("/register")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", "http://evil.test")
                .body(Body::from(
                    "identifier=alice&password=hunter2&next=http%3A%2F%2Flogin.test%2F",
                ))
                .unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rate_limits_repeated_attempts_from_the_same_ip() {
    let (backend, _h) = stub_backend().await;
    let mut config = test_config(backend);
    config.rate_limit_max_attempts = 1;
    config.rate_limit_window_secs = 60;
    let app = app(config);

    let first = app
        .clone()
        .oneshot(register_request("alice", "http://login.test/"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::SEE_OTHER);

    let second = app
        .oneshot(register_request("bob", "http://login.test/"))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn returns_bad_gateway_when_backend_unreachable() {
    let app = app(test_config("http://127.0.0.1:1".into()));

    let resp = app
        .oneshot(register_request("alice", "http://login.test/"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}
