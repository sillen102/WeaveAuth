use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use weaveauth_bff::config::{Config, RouteConfig};
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
        rate_limit_proxy_max_attempts: 1000,
        trusted_proxies: vec![],
        docs_enabled: false,
        login_public_url: "http://login.test".into(),
    }
}

fn with_test_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

/// Backend stub. `/oauth/login`: "required@x" gets only a verification
/// session (verification required), "optional@x" gets both, anyone else a
/// plain login session. Session "good-session" + code "123456789" releases a
/// login session; another code is a 400, another session a 401. Resend
/// requests are recorded.
async fn stub_backend()
-> anyhow::Result<(String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let requested = Arc::new(Mutex::new(Vec::new()));
    let recorded = requested.clone();
    let router = Router::new()
        .route(
            "/oauth/login",
            post(|Json(body): Json<serde_json::Value>| async move {
                match body["email"].as_str() {
                    Some("required@x") => {
                        Json(serde_json::json!({"verification_session": "good-session", "verification_session_ttl_secs": 4321}))
                    }
                    Some("optional@x") => Json(serde_json::json!({
                        "login_session": "stub-session",
                        "verification_session": "good-session",
                        "verification_session_ttl_secs": 4321
                    })),
                    _ => Json(serde_json::json!({"login_session": "stub-session"})),
                }
            }),
        )
        .route(
            "/oauth/email-verification/confirm",
            post(|Json(body): Json<serde_json::Value>| async move {
                if body["verification_session"] == "locked-session" {
                    (
                        StatusCode::LOCKED,
                        Json(serde_json::json!({"status": "locked", "retry_after_secs": 3600})),
                    )
                        .into_response()
                } else if body["verification_session"] == "hard-session" {
                    (
                        StatusCode::LOCKED,
                        Json(serde_json::json!({"status": "locked_until_reset"})),
                    )
                        .into_response()
                } else if body["verification_session"] == "used-up-session" {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "timestamp": chrono::Utc::now(),
                            "reason": "CodeUsedUp",
                            "details": "email verification code used up by wrong attempts"
                        })),
                    )
                        .into_response()
                } else if body["verification_session"] != "good-session" {
                    StatusCode::UNAUTHORIZED.into_response()
                } else if body["code"] == "123456789" {
                    Json(serde_json::json!({"login_session": "stub-session"})).into_response()
                } else {
                    StatusCode::BAD_REQUEST.into_response()
                }
            }),
        )
        .route(
            "/oauth/email-verification/request",
            post(move |Json(body): Json<serde_json::Value>| {
                let recorded = recorded.clone();
                async move {
                    match body["verification_session"].as_str() {
                        Some("good-session") => {
                            recorded.lock().unwrap().push("resent".to_string());
                            (
                                StatusCode::ACCEPTED,
                                Json(serde_json::json!({"status": "sent", "expires_in_secs": 900})),
                            )
                                .into_response()
                        }
                        Some("cooling-session") => (
                            StatusCode::ACCEPTED,
                            Json(serde_json::json!(
                                {"status": "cooling_down", "retry_after_secs": 42}
                            )),
                        )
                            .into_response(),
                        Some("locked-session") => (
                            StatusCode::ACCEPTED,
                            Json(serde_json::json!({"status": "locked", "retry_after_secs": 3600})),
                        )
                            .into_response(),
                        Some("hard-session") => (
                            StatusCode::ACCEPTED,
                            Json(serde_json::json!({"status": "locked_until_reset"})),
                        )
                            .into_response(),
                        _ => StatusCode::UNAUTHORIZED.into_response(),
                    }
                }
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
    Ok((format!("http://{addr}"), requested, handle))
}

fn form_post(path: &str, body: &str, origin: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::post(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("origin", origin);
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    with_test_peer(request.body(Body::from(body.to_string())).unwrap())
}

fn location(resp: &axum::response::Response) -> Option<&str> {
    resp.headers().get("location").and_then(|v| v.to_str().ok())
}

fn set_cookies(resp: &axum::response::Response) -> Vec<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect()
}

const NEXT: &str = "next=http%3A%2F%2Flogin.test%2Fverify-email.html";
const REDIRECT: &str = "redirect_uri=http%3A%2F%2Fadmin.test%2F";
const LOGIN: &str = "http://login.test";
const GOOD_COOKIE: &str = "wa_verify_session=good-session";

async fn post_form(
    backend: String,
    path: &str,
    body: &str,
    origin: &str,
    cookie: Option<&str>,
) -> anyhow::Result<axum::response::Response> {
    let app = app(test_config(backend)).unwrap();
    Ok(app.oneshot(form_post(path, body, origin, cookie)).await?)
}

fn login_body(email: &str) -> String {
    format!("email={email}&password=x&{REDIRECT}&next=http%3A%2F%2Flogin.test%2Flogin.html")
}

#[tokio::test]
async fn login_where_verification_is_required_gets_only_the_restricted_cookie() -> anyhow::Result<()>
{
    let (backend, _, _h) = stub_backend().await?;

    let resp = post_form(backend, "/login", &login_body("required%40x"), LOGIN, None).await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&resp),
        Some("http://login.test/verify-email.html?redirect_uri=http%3A%2F%2Fadmin.test%2F")
    );
    let cookies = set_cookies(&resp);
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    assert!(
        cookies[0].starts_with("wa_verify_session=good-session;"),
        "{cookies:?}"
    );
    assert!(cookies[0].contains("Path=/verify-email"), "{cookies:?}");
    assert!(cookies[0].contains("HttpOnly"), "{cookies:?}");
    assert!(cookies[0].contains("Max-Age=4321"), "{cookies:?}");
    Ok(())
}

#[tokio::test]
async fn login_where_verification_is_optional_gets_both_cookies() -> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;

    let resp = post_form(backend, "/login", &login_body("optional%40x"), LOGIN, None).await?;

    assert_eq!(location(&resp), Some("http://admin.test/"));
    let cookies = set_cookies(&resp);
    assert!(
        cookies.iter().any(|c| c.starts_with("wa_session=")),
        "{cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with("wa_verify_session=")),
        "{cookies:?}"
    );
    Ok(())
}

#[tokio::test]
async fn the_restricted_cookie_gets_nothing_through_the_proxy() -> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;
    let mut config = test_config(backend);
    config.routes = vec![RouteConfig {
        path_prefix: "/app".into(),
        upstream_url: "http://127.0.0.1:1".into(),
    }];
    let app = app(config).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/app/secret")
                .header("cookie", GOOD_COOKIE)
                .body(Body::empty())
                .unwrap(),
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn the_right_code_completes_the_login_and_lands_on_the_destination() -> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/verify-email",
        &format!("code=123456789&{REDIRECT}&{NEXT}"),
        LOGIN,
        Some(GOOD_COOKIE),
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), Some("http://admin.test/"));
    let cookies = set_cookies(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("wa_session=") && c.contains("HttpOnly")),
        "{cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("wa_verify_session=;") && c.contains("Max-Age=0")),
        "{cookies:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_wrong_code_bounces_back_without_a_session() -> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/verify-email",
        &format!("code=000000000&{REDIRECT}&{NEXT}"),
        LOGIN,
        Some(GOOD_COOKIE),
    )
    .await?;

    assert_eq!(
        location(&resp),
        Some("http://login.test/verify-email.html?status=invalid")
    );
    assert!(set_cookies(&resp).is_empty());
    Ok(())
}

#[tokio::test]
async fn a_missing_or_unknown_verification_session_asks_for_a_new_login() -> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;

    for cookie in [None, Some("wa_verify_session=stale")] {
        let resp = post_form(
            backend.clone(),
            "/verify-email",
            &format!("code=123456789&{REDIRECT}&{NEXT}"),
            LOGIN,
            cookie,
        )
        .await?;

        assert_eq!(
            location(&resp),
            Some("http://login.test/verify-email.html?status=session_expired"),
            "{cookie:?}"
        );
        assert!(
            set_cookies(&resp).iter().any(|c| c.contains("Max-Age=0")),
            "{cookie:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn resend_uses_the_verification_session() -> anyhow::Result<()> {
    let (backend, requested, _h) = stub_backend().await?;

    let resp = post_form(
        backend.clone(),
        "/verify-email/resend",
        NEXT,
        LOGIN,
        Some(GOOD_COOKIE),
    )
    .await?;
    let without = post_form(backend, "/verify-email/resend", NEXT, LOGIN, None).await?;

    assert_eq!(
        location(&resp),
        Some("http://login.test/verify-email.html?status=sent&expires_in=900")
    );
    assert_eq!(requested.lock().unwrap().len(), 1);
    assert_eq!(
        location(&without),
        Some("http://login.test/verify-email.html?status=session_expired")
    );
    Ok(())
}

#[tokio::test]
async fn resend_inside_the_cooldown_bounces_with_the_seconds_left() -> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/verify-email/resend",
        NEXT,
        LOGIN,
        Some("wa_verify_session=cooling-session"),
    )
    .await?;

    assert_eq!(
        location(&resp),
        Some("http://login.test/verify-email.html?status=cooling_down&retry_after=42")
    );
    Ok(())
}

#[tokio::test]
async fn resend_while_locked_out_bounces_as_locked_with_the_seconds_left() -> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/verify-email/resend",
        NEXT,
        LOGIN,
        Some("wa_verify_session=locked-session"),
    )
    .await?;

    assert_eq!(
        location(&resp),
        Some("http://login.test/verify-email.html?status=locked&retry_after=3600")
    );
    assert!(
        set_cookies(&resp)
            .iter()
            .any(|c| c.starts_with("wa_verify_session=;") && c.contains("Max-Age=0")),
        "{:?}",
        set_cookies(&resp)
    );
    Ok(())
}

#[tokio::test]
async fn entering_a_code_while_locked_out_bounces_as_locked_and_clears_the_cookie()
-> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;

    for (cookie, expected) in [
        (
            "wa_verify_session=locked-session",
            "http://login.test/verify-email.html?status=locked&retry_after=3600",
        ),
        (
            "wa_verify_session=hard-session",
            "http://login.test/verify-email.html?status=locked_until_reset",
        ),
    ] {
        let resp = post_form(
            backend.clone(),
            "/verify-email",
            &format!("code=123456789&{REDIRECT}&{NEXT}"),
            LOGIN,
            Some(cookie),
        )
        .await?;

        assert_eq!(location(&resp), Some(expected), "{cookie}");
        assert!(
            set_cookies(&resp)
                .iter()
                .any(|c| c.starts_with("wa_verify_session=;") && c.contains("Max-Age=0")),
            "{cookie}: {:?}",
            set_cookies(&resp)
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_code_used_up_by_wrong_guesses_bounces_as_code_used_up_and_keeps_the_session()
-> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/verify-email",
        &format!("code=000000000&{REDIRECT}&{NEXT}"),
        LOGIN,
        Some("wa_verify_session=used-up-session"),
    )
    .await?;

    assert_eq!(
        location(&resp),
        Some("http://login.test/verify-email.html?status=code_used_up")
    );
    assert!(set_cookies(&resp).is_empty(), "{:?}", set_cookies(&resp));
    Ok(())
}

#[tokio::test]
async fn resend_while_hard_locked_bounces_as_locked_until_reset() -> anyhow::Result<()> {
    let (backend, _, _h) = stub_backend().await?;

    let resp = post_form(
        backend,
        "/verify-email/resend",
        NEXT,
        LOGIN,
        Some("wa_verify_session=hard-session"),
    )
    .await?;

    assert_eq!(
        location(&resp),
        Some("http://login.test/verify-email.html?status=locked_until_reset")
    );
    Ok(())
}

#[tokio::test]
async fn an_untrusted_origin_is_refused_without_contacting_backend() -> anyhow::Result<()> {
    let (backend, requested, _h) = stub_backend().await?;

    let verify = post_form(
        backend.clone(),
        "/verify-email",
        &format!("code=123456789&{REDIRECT}&{NEXT}"),
        "http://evil.test",
        Some(GOOD_COOKIE),
    )
    .await?;
    let resend = post_form(
        backend,
        "/verify-email/resend",
        NEXT,
        "http://evil.test",
        Some(GOOD_COOKIE),
    )
    .await?;

    assert_eq!(verify.status(), StatusCode::FORBIDDEN);
    assert_eq!(resend.status(), StatusCode::FORBIDDEN);
    assert!(requested.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_next_outside_the_trusted_origins_is_refused() -> anyhow::Result<()> {
    let (backend, requested, _h) = stub_backend().await?;

    for path in ["/verify-email", "/verify-email/resend"] {
        let resp = post_form(
            backend.clone(),
            path,
            &format!("code=123456789&{REDIRECT}&next=http%3A%2F%2Fevil.test%2F"),
            LOGIN,
            Some(GOOD_COOKIE),
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(requested.lock().unwrap().is_empty());
    Ok(())
}
