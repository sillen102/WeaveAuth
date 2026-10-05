use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::{Path, Query};
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use weaveauth_bff::config::{Config, RouteConfig};
use weaveauth_bff::server::app;

const ALICE: uuid::Uuid = uuid::Uuid::from_u128(1);
const BOB: uuid::Uuid = uuid::Uuid::from_u128(2);

fn test_config(backend_url: String) -> Config {
    Config {
        port: 8080,
        bff_url: "http://bff.test".into(),
        backend_url,
        session_cookie_name: "wa_session".into(),
        routes: vec![],
        trusted_origins: vec!["http://login.test".into()],
        rate_limit_max_attempts: 1000,
        rate_limit_proxy_max_attempts: 1000,
        trusted_proxies: vec![],
        docs_enabled: false,
        login_public_url: "http://login.test".into(),
    }
}

type Calls = Arc<Mutex<Vec<serde_json::Value>>>;

fn error_body(reason: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "timestamp": chrono::Utc::now(),
        "reason": reason,
        "details": "stub"
    }))
}

/// Backend stub recording every reset call. Request: "boom@example.com" is a
/// 500. Confirm: "good-token" with a password of 8+ characters resets Alice
/// (200), with a shorter one a `WeakPassword` 400; any other token an
/// `InvalidOrExpiredToken` 400. Logging in as "alice" or "bob" yields a
/// session for that user.
async fn stub_backend() -> anyhow::Result<(String, Calls)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let (on_request, on_confirm) = (calls.clone(), calls.clone());
    let router = Router::new()
        .route(
            "/oauth/password-reset/request",
            post(move |Json(body): Json<serde_json::Value>| {
                let calls = on_request.clone();
                async move {
                    let failing = body["email"] == "boom@example.com";
                    calls.lock().unwrap().push(body);
                    if failing {
                        StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        StatusCode::ACCEPTED
                    }
                }
            }),
        )
        .route(
            "/oauth/password-reset/confirm",
            post(move |Json(body): Json<serde_json::Value>| {
                let calls = on_confirm.clone();
                async move {
                    calls.lock().unwrap().push(body.clone());
                    let password = body["new_password"].as_str().unwrap_or_default();
                    if body["token"] != "good-token" {
                        (StatusCode::BAD_REQUEST, error_body("InvalidOrExpiredToken"))
                            .into_response()
                    } else if password.len() < 8 {
                        (StatusCode::BAD_REQUEST, error_body("WeakPassword")).into_response()
                    } else {
                        Json(serde_json::json!({"user_id": ALICE})).into_response()
                    }
                }
            }),
        )
        .route(
            "/oauth/login",
            post(|Json(body): Json<serde_json::Value>| async move {
                Json(serde_json::json!({"login_session": body["email"]}))
            }),
        )
        .route(
            "/oauth/authorize",
            get(|Query(q): Query<HashMap<String, String>>| async move {
                axum::response::Redirect::to(&format!(
                    "{}?code={}",
                    q["redirect_uri"], q["login_session"]
                ))
            }),
        )
        .route(
            "/oauth/token",
            post(|Form(body): Form<HashMap<String, String>>| async move {
                let user_id = if body.get("code").map(String::as_str) == Some("alice") {
                    ALICE
                } else {
                    BOB
                };
                Json(serde_json::json!({
                    "access_token": format!("{user_id}-access"),
                    "refresh_token": format!("{user_id}-refresh"),
                    "token_type": "Bearer",
                    "expires_at": chrono::Utc::now() + chrono::Duration::minutes(15),
                    "refresh_expires_at": chrono::Utc::now() + chrono::Duration::days(30),
                    "user_id": user_id,
                }))
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((format!("http://{addr}"), calls))
}

async fn post_form(
    backend: String,
    path: &str,
    body: &str,
    origin: &str,
) -> anyhow::Result<axum::response::Response> {
    let mut request = Request::post(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("origin", origin)
        .body(Body::from(body.to_string()))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    Ok(app(test_config(backend))?.oneshot(request).await?)
}

fn location(resp: &axum::response::Response) -> Option<&str> {
    resp.headers().get("location").and_then(|v| v.to_str().ok())
}

const LOGIN: &str = "http://login.test";

#[tokio::test]
async fn a_request_is_forwarded_and_lands_on_the_sent_page() -> anyhow::Result<()> {
    let (backend, calls) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/password-reset/request",
        "email=alice%40example.com",
        LOGIN,
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&resp),
        Some("http://login.test/forgot-password.html?status=sent")
    );
    assert_eq!(
        *calls.lock().unwrap(),
        vec![serde_json::json!({"email": "alice@example.com"})]
    );
    Ok(())
}

#[tokio::test]
async fn a_request_from_an_untrusted_origin_is_refused_and_not_forwarded() -> anyhow::Result<()> {
    let (backend, calls) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/password-reset/request",
        "email=alice%40example.com",
        "http://evil.test",
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(calls.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_request_fails_visibly_when_backend_is_down() -> anyhow::Result<()> {
    let resp = post_form(
        "http://127.0.0.1:1".to_string(),
        "/password-reset/request",
        "email=alice%40example.com",
        LOGIN,
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

#[tokio::test]
async fn a_request_backend_fails_is_not_reported_as_sent() -> anyhow::Result<()> {
    let (backend, _) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/password-reset/request",
        "email=boom%40example.com",
        LOGIN,
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

#[tokio::test]
async fn a_confirmed_reset_lands_on_the_login_page_without_signing_in() -> anyhow::Result<()> {
    let (backend, calls) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/password-reset/confirm",
        "token=good-token&new_password=long-enough",
        LOGIN,
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&resp),
        Some("http://login.test/login.html?status=password_reset")
    );
    assert!(resp.headers().get("set-cookie").is_none());
    assert_eq!(
        *calls.lock().unwrap(),
        vec![serde_json::json!({"token": "good-token", "new_password": "long-enough"})]
    );
    Ok(())
}

#[tokio::test]
async fn a_weak_password_returns_to_the_reset_page_without_the_token() -> anyhow::Result<()> {
    let (backend, _) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/password-reset/confirm",
        "token=good-token&new_password=short",
        LOGIN,
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&resp),
        Some("http://login.test/reset-password.html?status=weak_password")
    );
    Ok(())
}

#[tokio::test]
async fn an_unknown_token_sends_the_user_to_ask_for_a_new_link() -> anyhow::Result<()> {
    let (backend, _) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/password-reset/confirm",
        "token=spent-token&new_password=long-enough",
        LOGIN,
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&resp),
        Some("http://login.test/forgot-password.html?status=invalid_token")
    );
    Ok(())
}

// Anything but a token's own characters never reaches backend.
#[tokio::test]
async fn a_token_with_foreign_characters_is_refused_without_reaching_backend() -> anyhow::Result<()>
{
    let (backend, calls) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/password-reset/confirm",
        "token=good-token%23x%3Fy&new_password=long-enough",
        LOGIN,
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&resp),
        Some("http://login.test/forgot-password.html?status=invalid_token")
    );
    assert!(calls.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_confirm_from_an_untrusted_origin_is_refused_and_not_forwarded() -> anyhow::Result<()> {
    let (backend, calls) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/password-reset/confirm",
        "token=good-token&new_password=long-enough",
        "http://evil.test",
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(calls.lock().unwrap().is_empty());
    Ok(())
}

async fn stub_upstream() -> anyhow::Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new().route("/api/{rest}", get(|Path(_): Path<String>| async { "ok" }));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(format!("http://{addr}"))
}

fn with_peer(mut request: Request<Body>) -> Request<Body> {
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    request
}

async fn log_in(app: &Router, email: &str) -> anyhow::Result<String> {
    let request = Request::post("/login")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("origin", LOGIN)
        .body(Body::from(format!(
            "email={email}&password=x&redirect_uri=http%3A%2F%2Fapp.test%2F&next=http%3A%2F%2Flogin.test%2Flogin.html"
        )))?;
    let resp = app.clone().oneshot(with_peer(request)).await?;
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("a session cookie");
    Ok(set_cookie.split(';').next().unwrap_or_default().to_string())
}

async fn proxied_status(app: &Router, cookie: &str) -> anyhow::Result<StatusCode> {
    let request = Request::get("/api/thing")
        .header("cookie", cookie)
        .body(Body::empty())?;
    Ok(app.clone().oneshot(with_peer(request)).await?.status())
}

#[tokio::test]
async fn a_reset_signs_the_user_out_of_every_bff_session_and_no_one_else() -> anyhow::Result<()> {
    let (backend, _) = stub_backend().await?;
    let upstream = stub_upstream().await?;
    let app = app(Config {
        routes: vec![RouteConfig {
            path_prefix: "/api".into(),
            upstream_url: format!("{upstream}/api"),
        }],
        ..test_config(backend)
    })?;
    let alice_laptop = log_in(&app, "alice").await?;
    let alice_phone = log_in(&app, "alice").await?;
    let bob = log_in(&app, "bob").await?;
    assert_eq!(proxied_status(&app, &alice_laptop).await?, StatusCode::OK);

    let mut confirm = Request::post("/password-reset/confirm")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("origin", LOGIN)
        .body(Body::from("token=good-token&new_password=long-enough"))?;
    confirm = with_peer(confirm);
    let resp = app.clone().oneshot(confirm).await?;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    assert_eq!(
        proxied_status(&app, &alice_laptop).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        proxied_status(&app, &alice_phone).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(proxied_status(&app, &bob).await?, StatusCode::OK);
    Ok(())
}
