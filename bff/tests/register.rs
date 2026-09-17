use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
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
        expiry_sweep_interval_secs: 60,
        docs_enabled: false,
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

/// Stub backend that treats one specific email as already registered.
/// Also stands in for `/oauth/login`, `/oauth/authorize` and `/oauth/token`
/// so the auto-login step after a successful registration has something real
/// to drive.
async fn stub_backend() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route(
            "/register",
            post(|Json(body): Json<serde_json::Value>| async move {
                if body["email"] == "taken" {
                    StatusCode::BAD_REQUEST
                } else if body["email"] == "check-extra" && body["company"] != "Acme" {
                    // Only reachable if bff actually forwarded the extra
                    // `company` field through to this stub backend.
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::CREATED
                }
            }),
        )
        .route(
            "/oauth/login",
            post(|Json(_body): Json<serde_json::Value>| async move {
                Json(serde_json::json!({"login_session": "stub-session"}))
            }),
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
                    "access_token": "test-access-token",
                    "refresh_token": "test-refresh-token",
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

fn register_request(email: &str, redirect_uri: &str, next: &str) -> anyhow::Result<Request<Body>> {
    register_request_with_extra(email, redirect_uri, next, &[])
}

fn register_request_with_extra(
    email: &str,
    redirect_uri: &str,
    next: &str,
    extra: &[(&str, &str)],
) -> anyhow::Result<Request<Body>> {
    let mut body = format!(
        "email={email}&password=hunter2&redirect_uri={}&next={}",
        url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(next.as_bytes()).collect::<String>()
    );
    for (key, value) in extra {
        body.push('&');
        body.push_str(key);
        body.push('=');
        body.push_str(&url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>());
    }
    Ok(with_test_peer(
        Request::post("/register")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", "http://login.test")
            .body(Body::from(body))?,
    ))
}

#[tokio::test]
async fn registering_immediately_logs_in_and_lands_on_redirect_uri() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(register_request("alice", "http://admin.test/", "http://login.test/register.html")?)
        .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://admin.test/"));

    let set_cookie = resp.headers().get("set-cookie").and_then(|v| v.to_str().ok());
    assert!(set_cookie.is_some_and(|c| c.starts_with("wa_session=") && c.contains("HttpOnly")));
    Ok(())
}

#[tokio::test]
async fn appends_error_query_param_when_backend_rejects() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(register_request("taken", "http://admin.test/", "http://login.test/register.html")?)
        .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://login.test/register.html?error=1"));
    Ok(())
}

#[tokio::test]
async fn forwards_extra_form_fields_to_backend() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(register_request_with_extra(
            "check-extra",
            "http://admin.test/",
            "http://login.test/register.html",
            &[("company", "Acme")],
        )?)
        .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://admin.test/"));
    Ok(())
}

#[tokio::test]
async fn rate_limits_repeated_attempts_from_the_same_ip() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let mut config = test_config(backend);
    config.rate_limit_max_attempts = 1;
    config.rate_limit_window_secs = 60;
    let app = app(config).unwrap();

    let first = app
        .clone()
        .oneshot(register_request("alice", "http://admin.test/", "http://login.test/register.html")?)
        .await?;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);

    let second = app
        .oneshot(register_request("bob", "http://admin.test/", "http://login.test/register.html")?)
        .await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

#[tokio::test]
async fn returns_bad_gateway_when_backend_unreachable() -> anyhow::Result<()> {
    let app = app(test_config("http://127.0.0.1:1".into())).unwrap();

    let resp = app
        .oneshot(register_request("alice", "http://admin.test/", "http://login.test/register.html")?)
        .await?;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}
