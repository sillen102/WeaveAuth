use axum::body::Body;
use axum::extract::{ConnectInfo, Path};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use std::net::SocketAddr;
use tower::ServiceExt;
use weaveauth_bff::config::{Config, RouteConfig};
use weaveauth_bff::server::app;

/// tower_governor's `PeerIpKeyExtractor` reads `ConnectInfo<SocketAddr>`,
/// which `axum::serve` only populates via `into_make_service_with_connect_info`
/// -- these tests call the router directly via `oneshot`, so it has to be
/// inserted by hand.
fn with_test_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

fn login_request(redirect_uri: &str) -> Request<Body> {
    with_test_peer(
        Request::post("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", "http://login.test")
            .body(Body::from(format!(
                "identifier=alice&password=hunter2&redirect_uri={}&next=http%3A%2F%2Flogin.test%2F",
                url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>()
            )))
            .unwrap(),
    )
}

fn test_config(backend_url: String, routes: Vec<RouteConfig>) -> Config {
    Config {
        port: 8080,
        bff_url: "http://bff.test".into(),
        backend_url,
        session_cookie_name: "wa_session".into(),
        routes,
        trusted_origins: vec!["http://login.test".into()],
        rate_limit_max_attempts: 1000,
        rate_limit_window_secs: 60,
    }
}

async fn stub_backend() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .route(
            "/oauth/login",
            post(|| async { Json(serde_json::json!({"login_session": "stub-session"})) }),
        )
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
            post(|Form(_body): Form<serde_json::Value>| async move {
                Json(serde_json::json!({
                    "access_token": "stub-access-token",
                    "refresh_token": "stub-refresh-token",
                    "token_type": "Bearer",
                    "expires_at": chrono::Utc::now() + chrono::Duration::minutes(15),
                    "user_id": uuid::Uuid::new_v4(),
                }))
            }),
        );
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

async fn stub_upstream() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route(
        "/whoami/{id}",
        get(|Path(id): Path<String>, headers: axum::http::HeaderMap| async move {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let has_cookie = headers.contains_key("cookie");
            format!("id={id} auth={auth} cookie={has_cookie}")
        }),
    );
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

fn extract_session_cookie(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn proxies_authenticated_request_swapping_cookie_for_bearer_token() {
    let (backend, _bh) = stub_backend().await;
    let (upstream, _uh) = stub_upstream().await;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: upstream,
    }];
    let app = app(test_config(backend, routes));

    let login_resp = app
        .clone()
        .oneshot(login_request("http://admin.test/"))
        .await
        .unwrap();
    let set_cookie = login_resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let cookie = extract_session_cookie(&set_cookie);

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(body, "id=42 auth=Bearer stub-access-token cookie=false");
}

#[tokio::test]
async fn missing_session_cookie_is_unauthorized() {
    let (backend, _bh) = stub_backend().await;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: "http://unused.test".into(),
    }];
    let app = app(test_config(backend, routes));

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_session_cookie_is_unauthorized() {
    let (backend, _bh) = stub_backend().await;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: "http://unused.test".into(),
    }];
    let app = app(test_config(backend, routes));

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", "wa_session=does-not-exist")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

async fn seeded_cookie(app: Router, backend: &str) -> String {
    let login_resp = app
        .oneshot(login_request("http://admin.test/"))
        .await
        .unwrap();
    let _ = backend; // kept for call-site clarity
    let set_cookie = login_resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    extract_session_cookie(&set_cookie)
}

#[tokio::test]
async fn longest_matching_prefix_wins() {
    let (backend, _bh) = stub_backend().await;
    let (general_upstream, _gh) = stub_upstream().await;
    let (specific_upstream, _sh) = stub_upstream().await;
    let routes = vec![
        RouteConfig {
            path_prefix: "/api".into(),
            upstream_url: general_upstream,
        },
        RouteConfig {
            path_prefix: "/api/v2".into(),
            upstream_url: specific_upstream.clone(),
        },
    ];
    let app = app(test_config(backend.clone(), routes));
    let cookie = seeded_cookie(app.clone(), &backend).await;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/v2/whoami/1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    // Only reachable if the /api/v2 route (not the shorter /api one) matched --
    // both upstream stub servers use the same handler, so this just confirms we
    // got a valid response through the more specific prefix instead of a 404
    // from the general one having a different path shape once stripped.
    assert!(body.starts_with("id=1 "));
}

#[tokio::test]
async fn query_string_is_forwarded_to_upstream() {
    let (backend, _bh) = stub_backend().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_router = Router::new().route(
        "/echo",
        get(|uri: axum::http::Uri| async move { uri.query().unwrap_or("").to_string() }),
    );
    let _uh = tokio::spawn(async move { axum::serve(listener, upstream_router).await.unwrap() });

    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: format!("http://{addr}"),
    }];
    let app = app(test_config(backend.clone(), routes));
    let cookie = seeded_cookie(app.clone(), &backend).await;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/echo?foo=bar&baz=1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(String::from_utf8(body.to_vec()).unwrap(), "foo=bar&baz=1");
}

#[tokio::test]
async fn request_body_is_forwarded_to_upstream() {
    let (backend, _bh) = stub_backend().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_router = Router::new().route(
        "/echo",
        axum::routing::post(|body: String| async move { body }),
    );
    let _uh = tokio::spawn(async move { axum::serve(listener, upstream_router).await.unwrap() });

    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: format!("http://{addr}"),
    }];
    let app = app(test_config(backend.clone(), routes));
    let cookie = seeded_cookie(app.clone(), &backend).await;

    let resp = app
        .oneshot(with_test_peer(
            Request::post("/api/echo")
                .header("cookie", &cookie)
                .body(Body::from("hello upstream"))
                .unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(String::from_utf8(body.to_vec()).unwrap(), "hello upstream");
}

#[tokio::test]
async fn unmatched_path_is_not_found() {
    let (backend, _bh) = stub_backend().await;
    let app = app(test_config(backend, vec![]));

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/no-such-route")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_is_exempt_from_rate_limiting() {
    // /health has no bucket at all -- infra that polls it shouldn't get
    // caught by a limit meant for auth abuse or proxy flooding.
    let (backend, _bh) = stub_backend().await;
    let mut config = test_config(backend, vec![]);
    config.rate_limit_max_attempts = 1;
    config.rate_limit_window_secs = 60;
    let app = app(config);

    for _ in 0..5 {
        let resp = app
            .clone()
            .oneshot(with_test_peer(
                Request::get("/health").body(Body::empty()).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn proxy_rate_limit_is_independent_from_the_auth_bucket() {
    // Hammering the proxy fallback shouldn't burn /login's budget, and vice
    // versa -- they're two separate buckets, not one shared across all routes.
    let (backend, _bh) = stub_backend().await;
    let mut config = test_config(backend, vec![]);
    config.rate_limit_max_attempts = 1;
    config.rate_limit_window_secs = 60;
    let app = app(config);

    let first_proxy_hit = app
        .clone()
        .oneshot(with_test_peer(
            Request::get("/no-such-route").body(Body::empty()).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(first_proxy_hit.status(), StatusCode::NOT_FOUND);

    let second_proxy_hit = app
        .clone()
        .oneshot(with_test_peer(
            Request::get("/another-no-such-route")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(second_proxy_hit.status(), StatusCode::TOO_MANY_REQUESTS);

    // The proxy bucket being exhausted doesn't touch /login's separate one.
    let login_resp = app.oneshot(login_request("http://admin.test/")).await.unwrap();
    assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);
}
