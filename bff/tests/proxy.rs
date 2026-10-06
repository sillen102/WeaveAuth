use anyhow::Context;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use common::model::token::GrantType;
use std::net::SocketAddr;
use tower::ServiceExt;
use weaveauth_bff::config::{Config, RouteConfig};
use weaveauth_bff::server::app;

/// The rate limiter's key extractor reads `ConnectInfo<SocketAddr>`,
/// which `axum::serve` only populates via `into_make_service_with_connect_info`
/// -- these tests call the router directly via `oneshot`, so it has to be
/// inserted by hand.
fn with_test_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

fn login_request(redirect_uri: &str) -> anyhow::Result<Request<Body>> {
    Ok(with_test_peer(
        Request::post("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", "http://login.test")
            .body(Body::from(format!(
                "email=alice&password=hunter2&redirect_uri={}&next=http%3A%2F%2Flogin.test%2F",
                url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>()
            )))?,
    ))
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
        rate_limit_proxy_max_attempts: 1000,
        trusted_proxies: vec![],
        docs_enabled: false,
        login_public_url: "http://login.test".into(),
    }
}

async fn stub_backend() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
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
                    let redirect_uri = q.get("redirect_uri").cloned().unwrap_or_default();
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
                    "refresh_expires_at": chrono::Utc::now() + chrono::Duration::days(30),
                    "user_id": uuid::Uuid::new_v4(),
                }))
            }),
        );
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((format!("http://{addr}"), handle))
}

/// Like `stub_backend`, but its `/oauth/token` route branches on `grant_type`
/// so refresh-flow tests can control both the initial login's token expiries
/// and what the refresh grant hands back, and counts how many times it was
/// asked to refresh so tests can assert on that.
async fn stub_backend_with_expiry(
    access_expires_at: chrono::DateTime<chrono::Utc>,
    refresh_expires_at: chrono::DateTime<chrono::Utc>,
    refresh_failure: Option<StatusCode>,
) -> anyhow::Result<(
    String,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
)> {
    use axum::response::IntoResponse;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let refresh_calls_for_route = refresh_calls.clone();
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
                    let redirect_uri = q.get("redirect_uri").cloned().unwrap_or_default();
                    axum::response::Redirect::to(&format!("{redirect_uri}?code=stub-code"))
                },
            ),
        )
        .route(
            "/oauth/token",
            post(
                move |Form(body): Form<std::collections::HashMap<String, String>>| {
                    let refresh_calls = refresh_calls_for_route.clone();
                    async move {
                        if body.get("grant_type").map(String::as_str)
                            == Some(GrantType::RefreshToken.as_ref())
                        {
                            refresh_calls.fetch_add(1, Ordering::SeqCst);
                            if let Some(status) = refresh_failure {
                                return (status, "refresh failed").into_response();
                            }
                            return Json(serde_json::json!({
                                "access_token": "refreshed-access-token",
                                "refresh_token": "refreshed-refresh-token",
                                "token_type": "Bearer",
                                "expires_at": chrono::Utc::now() + chrono::Duration::minutes(15),
                                "refresh_expires_at": chrono::Utc::now() + chrono::Duration::days(30),
                                "user_id": uuid::Uuid::new_v4(),
                            }))
                            .into_response();
                        }
                        Json(serde_json::json!({
                            "access_token": "stub-access-token",
                            "refresh_token": "stub-refresh-token",
                            "token_type": "Bearer",
                            "expires_at": access_expires_at,
                            "refresh_expires_at": refresh_expires_at,
                            "user_id": uuid::Uuid::new_v4(),
                        }))
                        .into_response()
                    }
                },
            ),
        );
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((format!("http://{addr}"), refresh_calls, handle))
}

async fn stub_upstream() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route(
            "/whoami/{id}",
            get(
                |Path(id): Path<String>, headers: axum::http::HeaderMap| async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let has_cookie = headers.contains_key("cookie");
                    format!("id={id} auth={auth} cookie={has_cookie}")
                },
            ),
        )
        .route("/headers", get(echo_headers).post(echo_headers))
        .route(
            "/cache-control",
            get(
                |Query(query): Query<std::collections::HashMap<String, String>>| async move {
                    ([("cache-control", query["value"].clone())], "body")
                },
            ),
        )
        .route(
            "/every-header",
            get(|| async {
                (
                    [
                        ("content-type", "text/plain"),
                        ("content-disposition", "attachment"),
                        ("content-security-policy", "sandbox"),
                        ("cache-control", "private"),
                        ("x-content-type-options", "bogus"),
                        ("set-cookie", "wa_session=fixated; Path=/"),
                        ("clear-site-data", "\"cookies\""),
                        ("service-worker-allowed", "/"),
                        (
                            "strict-transport-security",
                            "max-age=63072000; includeSubDomains",
                        ),
                        ("alt-svc", "h3=\"evil.test:443\""),
                        ("x-upstream", "anything"),
                    ],
                    "body",
                )
            }),
        );
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((format!("http://{addr}"), handle))
}

async fn echo_headers(
    headers: axum::http::HeaderMap,
) -> Json<std::collections::BTreeMap<String, Vec<String>>> {
    let mut seen = std::collections::BTreeMap::<String, Vec<String>>::new();
    for (name, value) in &headers {
        seen.entry(name.to_string())
            .or_default()
            .push(value.to_str().unwrap_or("<binary>").to_string());
    }
    Json(seen)
}

fn extract_session_cookie(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .map(str::to_string)
        .unwrap_or_default()
}

#[tokio::test]
async fn proxies_authenticated_request_swapping_cookie_for_bearer_token() -> anyhow::Result<()> {
    let (backend, _bh) = stub_backend().await?;
    let (upstream, _uh) = stub_upstream().await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: upstream,
    }];
    let app = app(test_config(backend, routes)).unwrap();

    let login_resp = app
        .clone()
        .oneshot(login_request("http://admin.test/")?)
        .await?;
    let set_cookie = login_resp
        .headers()
        .get("set-cookie")
        .context("login response missing set-cookie header")?
        .to_str()?
        .to_string();
    let cookie = extract_session_cookie(&set_cookie);

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", &cookie)
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert_eq!(body, "id=42 auth=Bearer stub-access-token cookie=false");
    Ok(())
}

#[tokio::test]
async fn missing_session_cookie_is_unauthorized() -> anyhow::Result<()> {
    let (backend, _bh) = stub_backend().await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: "http://unused.test".into(),
    }];
    let app = app(test_config(backend, routes)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42").body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn unknown_session_cookie_is_unauthorized() -> anyhow::Result<()> {
    let (backend, _bh) = stub_backend().await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: "http://unused.test".into(),
    }];
    let app = app(test_config(backend, routes)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", "wa_session=does-not-exist")
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn seeded_cookie(app: Router, backend: &str) -> anyhow::Result<String> {
    let login_resp = app.oneshot(login_request("http://admin.test/")?).await?;
    let _ = backend; // kept for call-site clarity
    let set_cookie = login_resp
        .headers()
        .get("set-cookie")
        .context("login response missing set-cookie header")?
        .to_str()?
        .to_string();
    Ok(extract_session_cookie(&set_cookie))
}

#[tokio::test]
async fn longest_matching_prefix_wins() -> anyhow::Result<()> {
    let (backend, _bh) = stub_backend().await?;
    let (general_upstream, _gh) = stub_upstream().await?;
    let (specific_upstream, _sh) = stub_upstream().await?;
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
    let app = app(test_config(backend.clone(), routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), &backend).await?;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/v2/whoami/1")
                .header("cookie", &cookie)
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let body = String::from_utf8(body.to_vec())?;
    // Only reachable if the /api/v2 route (not the shorter /api one) matched --
    // both upstream stub servers use the same handler, so this just confirms we
    // got a valid response through the more specific prefix instead of a 404
    // from the general one having a different path shape once stripped.
    assert!(body.starts_with("id=1 "));
    Ok(())
}

#[tokio::test]
async fn query_string_is_forwarded_to_upstream() -> anyhow::Result<()> {
    let (backend, _bh) = stub_backend().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let upstream_router = Router::new().route(
        "/echo",
        get(|uri: axum::http::Uri| async move { uri.query().unwrap_or("").to_string() }),
    );
    let _uh = tokio::spawn(async move {
        let _ = axum::serve(listener, upstream_router).await;
    });

    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: format!("http://{addr}"),
    }];
    let app = app(test_config(backend.clone(), routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), &backend).await?;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/echo?foo=bar&baz=1")
                .header("cookie", &cookie)
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    assert_eq!(String::from_utf8(body.to_vec())?, "foo=bar&baz=1");
    Ok(())
}

#[tokio::test]
async fn request_body_is_forwarded_to_upstream() -> anyhow::Result<()> {
    let (backend, _bh) = stub_backend().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let upstream_router = Router::new().route(
        "/echo",
        axum::routing::post(|body: String| async move { body }),
    );
    let _uh = tokio::spawn(async move {
        let _ = axum::serve(listener, upstream_router).await;
    });

    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: format!("http://{addr}"),
    }];
    let app = app(test_config(backend.clone(), routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), &backend).await?;

    let resp = app
        .oneshot(with_test_peer(
            Request::post("/api/echo")
                .header("cookie", &cookie)
                .header("origin", "http://login.test")
                .body(Body::from("hello upstream"))?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    assert_eq!(String::from_utf8(body.to_vec())?, "hello upstream");
    Ok(())
}

#[tokio::test]
async fn unmatched_path_is_not_found() -> anyhow::Result<()> {
    let (backend, _bh) = stub_backend().await?;
    let app = app(test_config(backend, vec![])).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/no-such-route").body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn health_is_exempt_from_rate_limiting() -> anyhow::Result<()> {
    // /health has no bucket at all -- infra that polls it shouldn't get
    // caught by a limit meant for auth abuse or proxy flooding.
    let (backend, _bh) = stub_backend().await?;
    let mut config = test_config(backend, vec![]);
    config.rate_limit_max_attempts = 1;
    let app = app(config).unwrap();

    for _ in 0..5 {
        let resp = app
            .clone()
            .oneshot(with_test_peer(Request::get("/health").body(Body::empty())?))
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    Ok(())
}

#[tokio::test]
async fn proxy_rate_limit_is_independent_from_the_auth_bucket() -> anyhow::Result<()> {
    // Hammering the proxy fallback shouldn't burn /login's budget, and vice
    // versa -- they're separate buckets, each sized by its own setting.
    let (backend, _bh) = stub_backend().await?;
    let mut config = test_config(backend, vec![]);
    config.rate_limit_max_attempts = 1;
    config.rate_limit_proxy_max_attempts = 2;
    let app = app(config).unwrap();

    let proxy_hit = || async {
        let resp = app
            .clone()
            .oneshot(with_test_peer(
                Request::get("/no-such-route").body(Body::empty())?,
            ))
            .await?;
        anyhow::Ok(resp.status())
    };
    assert_eq!(proxy_hit().await?, StatusCode::NOT_FOUND);
    assert_eq!(proxy_hit().await?, StatusCode::NOT_FOUND);
    assert_eq!(proxy_hit().await?, StatusCode::TOO_MANY_REQUESTS);

    // The proxy bucket being exhausted doesn't touch /login's separate one.
    let login_resp = app.oneshot(login_request("http://admin.test/")?).await?;
    assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);
    Ok(())
}

#[tokio::test]
async fn access_token_within_the_refresh_leeway_is_refreshed_even_though_not_yet_expired()
-> anyhow::Result<()> {
    // Still technically valid, but expiring soon enough that the request
    // could plausibly reach backend after it dies in transit -- the proxy
    // should refresh it up front rather than gamble on the network being fast.
    let expiring_very_soon = chrono::Utc::now() + chrono::Duration::seconds(1);
    let refresh_still_valid = chrono::Utc::now() + chrono::Duration::days(30);
    let (backend, _refresh_calls, _bh) =
        stub_backend_with_expiry(expiring_very_soon, refresh_still_valid, None).await?;
    let (upstream, _uh) = stub_upstream().await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: upstream,
    }];
    let app = app(test_config(backend, routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), "").await?;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", &cookie)
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert_eq!(
        body,
        "id=42 auth=Bearer refreshed-access-token cookie=false"
    );
    Ok(())
}

#[tokio::test]
async fn expired_access_token_is_transparently_refreshed() -> anyhow::Result<()> {
    let already_expired = chrono::Utc::now() - chrono::Duration::minutes(1);
    let refresh_still_valid = chrono::Utc::now() + chrono::Duration::days(30);
    let (backend, _refresh_calls, _bh) =
        stub_backend_with_expiry(already_expired, refresh_still_valid, None).await?;
    let (upstream, _uh) = stub_upstream().await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: upstream,
    }];
    let app = app(test_config(backend, routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), "").await?;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", &cookie)
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let body = String::from_utf8(body.to_vec())?;
    // Not the token from login (already expired) -- the refreshed one.
    assert_eq!(
        body,
        "id=42 auth=Bearer refreshed-access-token cookie=false"
    );
    Ok(())
}

#[tokio::test]
async fn refreshed_token_is_persisted_so_a_second_request_does_not_refresh_again()
-> anyhow::Result<()> {
    let already_expired = chrono::Utc::now() - chrono::Duration::minutes(1);
    let refresh_still_valid = chrono::Utc::now() + chrono::Duration::days(30);
    let (backend, refresh_calls, _bh) =
        stub_backend_with_expiry(already_expired, refresh_still_valid, None).await?;
    let (upstream, _uh) = stub_upstream().await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: upstream,
    }];
    let app = app(test_config(backend, routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), "").await?;

    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(with_test_peer(
                Request::get("/api/whoami/42")
                    .header("cookie", &cookie)
                    .body(Body::empty())?,
            ))
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    assert_eq!(refresh_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn expired_access_and_refresh_token_is_unauthorized() -> anyhow::Result<()> {
    let already_expired = chrono::Utc::now() - chrono::Duration::minutes(1);
    let refresh_also_expired = chrono::Utc::now() - chrono::Duration::seconds(1);
    let (backend, _refresh_calls, _bh) =
        stub_backend_with_expiry(already_expired, refresh_also_expired, None).await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: "http://unused.test".into(),
    }];
    let app = app(test_config(backend, routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), "").await?;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", &cookie)
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn failed_refresh_call_is_unauthorized() -> anyhow::Result<()> {
    // Expiry-wise the refresh token still looks valid, but backend rejects
    // the refresh call itself (e.g. it was already revoked/rotated there).
    let already_expired = chrono::Utc::now() - chrono::Duration::minutes(1);
    let refresh_still_valid = chrono::Utc::now() + chrono::Duration::days(30);
    let (backend, _refresh_calls, _bh) = stub_backend_with_expiry(
        already_expired,
        refresh_still_valid,
        Some(StatusCode::BAD_REQUEST),
    )
    .await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: "http://unused.test".into(),
    }];
    let app = app(test_config(backend, routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), "").await?;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", &cookie)
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn backend_failing_the_refresh_call_is_bad_gateway_not_unauthorized() -> anyhow::Result<()> {
    // A 5xx from backend says nothing about the session, so it must not
    // look like an expired one (which would bounce the user to login).
    let already_expired = chrono::Utc::now() - chrono::Duration::minutes(1);
    let refresh_still_valid = chrono::Utc::now() + chrono::Duration::days(30);
    let (backend, _refresh_calls, _bh) = stub_backend_with_expiry(
        already_expired,
        refresh_still_valid,
        Some(StatusCode::INTERNAL_SERVER_ERROR),
    )
    .await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: "http://unused.test".into(),
    }];
    let app = app(test_config(backend, routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), "").await?;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", &cookie)
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

#[tokio::test]
async fn unparseable_refresh_response_is_bad_gateway() -> anyhow::Result<()> {
    // 200 with a body that isn't a token response: backend answered, but
    // nothing says the session is dead.
    let already_expired = chrono::Utc::now() - chrono::Duration::minutes(1);
    let refresh_still_valid = chrono::Utc::now() + chrono::Duration::days(30);
    let (backend, _refresh_calls, _bh) =
        stub_backend_with_expiry(already_expired, refresh_still_valid, Some(StatusCode::OK))
            .await?;
    let routes = vec![RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: "http://unused.test".into(),
    }];
    let app = app(test_config(backend, routes)).unwrap();
    let cookie = seeded_cookie(app.clone(), "").await?;

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/api/whoami/42")
                .header("cookie", &cookie)
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

/// Sends `req` (with the session cookie added) through a proxy app routing
/// `/api` to the stub upstream, returning the response.
async fn through_proxy(
    req: axum::http::request::Builder,
) -> anyhow::Result<axum::response::Response> {
    send_to_app(req, true).await
}

/// Sends `req` to an app with `/api` routed to the stub upstream, with or without the
/// session cookie.
async fn send_to_app(
    req: axum::http::request::Builder,
    with_session: bool,
) -> anyhow::Result<axum::response::Response> {
    let (backend, _bh) = stub_backend().await?;
    let (upstream, _uh) = stub_upstream().await?;
    let app = app(test_config(
        backend.clone(),
        vec![RouteConfig {
            path_prefix: "/api".into(),
            upstream_url: upstream,
        }],
    ))
    .unwrap();
    let req = if with_session {
        req.header("cookie", seeded_cookie(app.clone(), &backend).await?)
    } else {
        req
    };
    Ok(app
        .oneshot(with_test_peer(req.body(Body::empty())?))
        .await?)
}

#[tokio::test]
async fn only_allowlisted_headers_and_the_bearer_token_reach_the_upstream() -> anyhow::Result<()> {
    let mut req = Request::get("/api/headers");
    for (name, value) in [
        ("content-type", "application/json"),
        ("accept", "application/json"),
        ("user-agent", "test"),
        ("x-request-id", "req-1"),
        ("x-forwarded-for", "6.6.6.6"),
        ("forwarded", "for=6.6.6.6"),
        ("x-forwarded-host", "evil.test"),
        ("x-real-ip", "6.6.6.6"),
        ("x-original-url", "/admin"),
        ("authorization", "Bearer forged"),
        ("connection", "Upgrade, authorization, content-type"),
        ("upgrade", "websocket"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("sec-websocket-version", "13"),
    ] {
        req = req.header(name, value);
    }
    let resp = through_proxy(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let seen: std::collections::BTreeMap<String, Vec<String>> = serde_json::from_slice(&body)?;

    assert_eq!(
        seen.keys().map(String::as_str).collect::<Vec<_>>(),
        ["authorization", "content-type", "host"]
    );
    assert_eq!(seen["authorization"], ["Bearer stub-access-token"]);
    assert_eq!(seen["content-type"], ["application/json"]);
    Ok(())
}

#[tokio::test]
async fn a_post_from_a_trusted_origin_or_bff_itself_is_forwarded() -> anyhow::Result<()> {
    for origin in ["http://login.test", "http://bff.test"] {
        let resp = through_proxy(Request::post("/api/headers").header("origin", origin)).await?;
        assert_eq!(resp.status(), StatusCode::OK, "{origin}");
    }
    Ok(())
}

#[tokio::test]
async fn a_post_from_another_origin_is_forbidden() -> anyhow::Result<()> {
    let resp =
        through_proxy(Request::post("/api/headers").header("origin", "https://evil.test")).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp =
        through_proxy(Request::post("/api/headers").header("referer", "https://evil.test/page"))
            .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn every_non_safe_method_naming_no_origin_is_forbidden() -> anyhow::Result<()> {
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let resp = through_proxy(Request::builder().method(method).uri("/api/headers")).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method}");
    }
    Ok(())
}

#[tokio::test]
async fn safe_methods_need_no_origin() -> anyhow::Result<()> {
    for method in ["GET", "HEAD"] {
        let resp = through_proxy(Request::builder().method(method).uri("/api/headers")).await?;
        assert_eq!(resp.status(), StatusCode::OK, "{method}");
    }
    Ok(())
}

#[tokio::test]
async fn only_allowlisted_upstream_headers_reach_the_browser() -> anyhow::Result<()> {
    let resp = through_proxy(Request::get("/api/every-header")).await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let mut names: Vec<_> = resp.headers().keys().map(|name| name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            // The CORS layer's, on every response, even one without an `Origin`.
            "access-control-allow-credentials",
            "access-control-expose-headers",
            "cache-control",
            "content-disposition",
            "content-security-policy",
            "content-type",
            "vary",
            "x-content-type-options",
        ]
    );
    assert_eq!(resp.headers()["cache-control"], "private");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    assert_eq!(&body[..], b"body");
    Ok(())
}

#[tokio::test]
async fn a_proxied_response_without_caching_rules_is_not_stored() -> anyhow::Result<()> {
    let resp = through_proxy(Request::get("/api/headers")).await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    Ok(())
}

/// The `Cache-Control` the browser gets when the upstream sends `upstream`.
async fn cache_control_through_proxy(upstream: &str) -> anyhow::Result<String> {
    let uri = format!(
        "/api/cache-control?value={}",
        percent_encoding::utf8_percent_encode(upstream, percent_encoding::NON_ALPHANUMERIC)
    );
    let resp = through_proxy(Request::get(uri)).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let values: Vec<&str> = resp
        .headers()
        .get_all("cache-control")
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<_, _>>()?;
    Ok(values.join(", "))
}

#[tokio::test]
async fn a_cacheable_proxied_response_is_kept_out_of_shared_caches() -> anyhow::Result<()> {
    for upstream in [
        "max-age=60",
        "max-age=60, must-revalidate",
        "max-age=60, private=\"x-foo\"",
    ] {
        assert_eq!(
            cache_control_through_proxy(upstream).await?,
            format!("{upstream}, private")
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_upstream_that_settles_shared_caching_is_left_alone() -> anyhow::Result<()> {
    for upstream in [
        "public, max-age=60",
        "max-age=60, S-MAXAGE=30",
        "private",
        "no-store",
    ] {
        assert_eq!(cache_control_through_proxy(upstream).await?, upstream);
    }
    Ok(())
}

fn preflight(origin: &str) -> axum::http::request::Builder {
    Request::options("/api/headers")
        .header("origin", origin)
        .header("access-control-request-method", "PUT")
        .header("access-control-request-headers", "content-type,x-custom")
}

fn header<'a>(resp: &'a axum::response::Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn a_preflight_from_a_trusted_origin_is_answered_without_a_session() -> anyhow::Result<()> {
    for origin in ["http://login.test", "http://bff.test"] {
        let resp = send_to_app(preflight(origin), false).await?;

        assert!(resp.status().is_success(), "{origin}: {}", resp.status());
        assert_eq!(header(&resp, "access-control-allow-origin"), Some(origin));
        assert_eq!(
            header(&resp, "access-control-allow-credentials"),
            Some("true")
        );
        assert_eq!(header(&resp, "access-control-allow-methods"), Some("PUT"));
        assert!(header(&resp, "access-control-max-age").is_some());
    }
    Ok(())
}

#[tokio::test]
async fn a_preflight_from_another_origin_is_not_allowed() -> anyhow::Result<()> {
    let resp = send_to_app(preflight("https://evil.test"), false).await?;

    // Answered by bff: proxied, it would get 401 (no session).
    assert!(resp.status().is_success(), "{}", resp.status());
    assert_eq!(header(&resp, "access-control-allow-origin"), None);
    Ok(())
}

#[tokio::test]
async fn a_preflight_may_only_ask_for_headers_bff_forwards() -> anyhow::Result<()> {
    let resp = send_to_app(preflight("http://login.test"), false).await?;

    assert_eq!(
        header(&resp, "access-control-allow-headers"),
        Some("content-type")
    );
    Ok(())
}

#[tokio::test]
async fn any_options_is_answered_by_bff_without_a_session_or_the_upstream() -> anyhow::Result<()> {
    for path in ["/api/headers", "/no-such-route"] {
        for with_session in [false, true] {
            let resp = send_to_app(Request::options(path), with_session).await?;

            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{path}, session: {with_session}"
            );
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
            assert!(body.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn proxied_responses_carry_cors_headers_for_a_trusted_origin_only() -> anyhow::Result<()> {
    let resp =
        through_proxy(Request::get("/api/headers").header("origin", "http://login.test")).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        header(&resp, "access-control-allow-origin"),
        Some("http://login.test")
    );
    assert_eq!(
        header(&resp, "access-control-allow-credentials"),
        Some("true")
    );

    let resp =
        through_proxy(Request::get("/api/headers").header("origin", "https://evil.test")).await?;
    assert_eq!(header(&resp, "access-control-allow-origin"), None);
    Ok(())
}

#[tokio::test]
async fn an_unauthenticated_request_still_carries_cors_headers() -> anyhow::Result<()> {
    let resp = send_to_app(
        Request::get("/api/headers").header("origin", "http://login.test"),
        false,
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        header(&resp, "access-control-allow-origin"),
        Some("http://login.test")
    );
    Ok(())
}

#[tokio::test]
async fn form_routes_get_no_cors_headers() -> anyhow::Result<()> {
    let resp = send_to_app(preflight("http://login.test").uri("/login"), false).await?;

    assert_eq!(header(&resp, "access-control-allow-origin"), None);
    Ok(())
}

#[tokio::test]
async fn a_rate_limited_proxy_response_still_carries_cors_headers() -> anyhow::Result<()> {
    let (backend, _bh) = stub_backend().await?;
    let mut config = test_config(backend, vec![]);
    config.rate_limit_proxy_max_attempts = 1;
    let app = app(config).unwrap();
    let hit = || {
        app.clone().oneshot(with_test_peer(
            Request::get("/no-such-route")
                .header("origin", "http://login.test")
                .body(Body::empty())
                .unwrap(),
        ))
    };

    assert_eq!(hit().await?.status(), StatusCode::NOT_FOUND);
    let resp = hit().await?;

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        header(&resp, "access-control-allow-origin"),
        Some("http://login.test")
    );
    Ok(())
}
