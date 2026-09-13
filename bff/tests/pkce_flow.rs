use anyhow::Context;
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
    }
}

/// The rate limiter keys on `ConnectInfo<SocketAddr>`, which `axum::serve`
/// only populates via `into_make_service_with_connect_info` -- these tests
/// call the router directly via `oneshot`, so it has to be inserted by hand.
fn with_test_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

fn login_form_body(redirect_uri: &str) -> Body {
    Body::from(format!(
        "identifier=alice&password=hunter2&redirect_uri={}&next=http%3A%2F%2Flogin.test%2F",
        urlencoding_encode(redirect_uri)
    ))
}

fn login_request(redirect_uri: &str) -> anyhow::Result<Request<Body>> {
    Ok(with_test_peer(
        Request::post("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", "http://login.test")
            .body(login_form_body(redirect_uri))?,
    ))
}

/// Minimal `application/x-www-form-urlencoded` value escaping -- just enough
/// for the URLs these tests send, avoids pulling in a whole crate for it.
fn urlencoding_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Stands in for backend: a real (in-process) /oauth/login + /oauth/authorize +
/// /oauth/token, since bff drives the whole exchange server-to-server and needs
/// a real redirect response to read `code` out of. Mirrors backend's allowlist
/// check (only "http://admin.test" / "http://admin.test/" are allowed), accepts
/// identifier "alice" / password "hunter2" as the only valid user, and requires
/// /oauth/authorize's `login_session` to match what /oauth/login just handed out
/// (mirroring backend's real authenticate-before-authorize enforcement).
async fn stub_backend() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route(
            "/oauth/login",
            post(|Json(body): Json<serde_json::Value>| async move {
                if body["identifier"] == "alice" && body["password"] == "hunter2" {
                    Ok(Json(serde_json::json!({"login_session": "stub-session"})))
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            }),
        )
        .route(
            "/oauth/authorize",
            get(
                |axum::extract::Query(q): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
                    assert!(q.contains_key("code_challenge"));
                    assert_eq!(
                        q.get("code_challenge_method").map(String::as_str),
                        Some("S256")
                    );
                    if q.get("login_session").map(String::as_str) != Some("stub-session") {
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                    let redirect_uri = q.get("redirect_uri").cloned().unwrap_or_default();
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

#[tokio::test]
async fn login_exchanges_code_sets_session_cookie_and_redirects_without_token_in_url()
-> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app.oneshot(login_request("http://admin.test/")?).await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .context("missing location header")?;
    assert_eq!(loc, "http://admin.test/");
    assert!(!loc.contains("access_token"));

    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .context("missing set-cookie header")?;
    assert!(set_cookie.starts_with("wa_session="));
    assert!(set_cookie.contains("HttpOnly"));
    Ok(())
}

#[tokio::test]
async fn login_rejects_wrong_credentials_before_touching_authorize() -> anyhow::Result<()> {
    // /oauth/authorize returns a distinct failure status if hit -- credentials
    // are verified first, per RFC 6749 4.1.1 (authenticate the resource owner
    // before issuing a code), so a bad password must never reach it. If it
    // regresses, bff's redirect-with-code exchange breaks and the final
    // assertion below (a plain SEE_OTHER back to `next`) fails.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route(
            "/oauth/login",
            post(|| async { StatusCode::UNAUTHORIZED }),
        )
        .route(
            "/oauth/authorize",
            get(|| async { StatusCode::IM_A_TEAPOT }),
        );
    let _h = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let app = app(test_config(format!("http://{addr}"))).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::post("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", "http://login.test")
                .body(Body::from(
                    "identifier=alice&password=wrong&redirect_uri=http%3A%2F%2Fadmin.test%2F&next=http%3A%2F%2Flogin.test%2F",
                ))?,
        ))
        .await?;

    // A plain form POST can't show an inline error via JS, so wrong
    // credentials bounce back to `next` (the login page) instead of a bare 401.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://login.test/?error=1"));
    Ok(())
}

#[tokio::test]
async fn login_requires_redirect_uri() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::post("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", "http://login.test")
                .body(Body::from("identifier=alice&password=hunter2"))?,
        ))
        .await?;

    // A missing required form field is a body-parsing failure, distinct from
    // the semantic 400s below (bad redirect_uri, wrong credentials).
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    Ok(())
}

#[tokio::test]
async fn login_forwards_redirect_uri_to_backend_and_rejects_when_backend_does() -> anyhow::Result<()>
{
    // A rejected redirect_uri (no code, no token) surfaces as 400, not a generic
    // gateway failure.
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app.oneshot(login_request("http://evil.test/")?).await?;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn login_rejects_redirect_uri_backend_does_not_allowlist_even_when_it_points_at_bff_itself()
-> anyhow::Result<()> {
    // A redirect_uri pointing at bff's own proxy routes (e.g. /downstream) fails
    // unless backend's allowlist includes it.
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(login_request("http://bff.test/downstream")?)
        .await?;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn login_returns_bad_gateway_when_backend_is_unreachable_or_broken() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new().route(
        "/oauth/login",
        post(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
    );
    let _h = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let app = app(test_config(format!("http://{addr}"))).unwrap();

    let resp = app.oneshot(login_request("http://admin.test/")?).await?;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

#[tokio::test]
async fn login_returns_bad_gateway_when_login_response_is_not_valid_json() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new().route("/oauth/login", post(|| async { StatusCode::OK }));
    let _h = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let app = app(test_config(format!("http://{addr}"))).unwrap();

    let resp = app.oneshot(login_request("http://admin.test/")?).await?;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

#[tokio::test]
async fn login_returns_bad_request_when_backend_token_exchange_fails() -> anyhow::Result<()> {
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
            post(|| async { StatusCode::BAD_REQUEST }),
        );
    let _h = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let app = app(test_config(format!("http://{addr}"))).unwrap();

    let resp = app.oneshot(login_request("http://admin.test/")?).await?;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn login_never_redirects_the_browser_to_backend() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend.clone())).unwrap();

    let resp = app.oneshot(login_request("http://admin.test/")?).await?;

    // The only response the browser ever sees is the final redirect straight to
    // the caller's redirect_uri -- never to backend.
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .context("missing location header")?;
    assert!(!loc.starts_with(&backend));
    Ok(())
}
