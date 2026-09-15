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

fn with_test_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

fn set_cookie_values(resp: &axum::response::Response) -> Vec<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect()
}

/// Stands in for backend's full oidc + password-login surface: `/oauth/oidc/google/login`
/// (redirects to a fake provider), `/oauth/oidc/google/callback` (accepts code=good-code
/// state=good-state, mirroring what bff forwards), plus `/oauth/authorize` and
/// `/oauth/token` -- `complete_login` drives those the same way it would after a
/// password login, once it has a login_session.
async fn stub_backend() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route(
            "/oauth/oidc/{provider}/login",
            get(|axum::extract::Path(provider): axum::extract::Path<String>| async move {
                if provider != "google" {
                    return Err(StatusCode::NOT_FOUND);
                }
                Ok(axum::response::Redirect::to(
                    "https://provider.test/consent?state=good-state",
                ))
            }),
        )
        .route(
            "/oauth/oidc/{provider}/callback",
            get(
                |axum::extract::Path(provider): axum::extract::Path<String>,
                 axum::extract::Query(q): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    if provider != "google" {
                        return Err(StatusCode::NOT_FOUND);
                    }
                    match (q.get("code").map(String::as_str), q.get("state").map(String::as_str)) {
                        (Some("good-code"), Some("good-state")) => Ok(Json(
                            serde_json::json!({"status": "authenticated", "login_session": "stub-session"}),
                        )),
                        (Some("unverified-code"), Some("unverified-state")) => Ok(Json(serde_json::json!({
                            "status": "password_confirmation_required",
                            "pending_link_token": "stub-pending-link-token",
                            "email": "squatter@example.com",
                        }))),
                        _ => Err(StatusCode::BAD_REQUEST),
                    }
                },
            ),
        )
        .route(
            "/oauth/oidc/confirm-link",
            post(|Json(body): Json<serde_json::Value>| async move {
                if body["pending_link_token"] == "stub-pending-link-token" && body["password"] == "correct-password"
                {
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
async fn oidc_login_relays_the_provider_redirect_and_sets_flow_cookies() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/oidc/google/login?redirect_uri=http%3A%2F%2Fadmin.test%2F&next=http%3A%2F%2Flogin.test%2F")
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .context("missing location header")?;
    assert_eq!(loc, "https://provider.test/consent?state=good-state");

    let cookies = set_cookie_values(&resp);
    assert!(cookies.iter().any(|c| c.starts_with("wa_oidc_redirect_uri=") && c.contains("Path=/oidc")));
    assert!(cookies.iter().any(|c| c.starts_with("wa_oidc_next=") && c.contains("Path=/oidc")));
    Ok(())
}

#[tokio::test]
async fn oidc_login_rejects_unknown_provider() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/oidc/unknown-provider/login?redirect_uri=http%3A%2F%2Fadmin.test%2F&next=http%3A%2F%2Flogin.test%2F")
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn oidc_callback_completes_login_and_clears_flow_cookies() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/oidc/google/callback?code=good-code&state=good-state")
                .header(
                    "cookie",
                    "wa_oidc_redirect_uri=http://admin.test/; wa_oidc_next=http://login.test/",
                )
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://admin.test/"));

    let cookies = set_cookie_values(&resp);
    assert!(cookies.iter().any(|c| c.starts_with("wa_session=") && c.contains("HttpOnly")));
    assert!(cookies.iter().any(|c| c.starts_with("wa_oidc_redirect_uri=") && c.contains("Max-Age=0")));
    assert!(cookies.iter().any(|c| c.starts_with("wa_oidc_next=") && c.contains("Max-Age=0")));
    Ok(())
}

#[tokio::test]
async fn oidc_callback_without_flow_cookies_is_bad_request() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/oidc/google/callback?code=good-code&state=good-state").body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn oidc_callback_bounces_to_next_when_backend_rejects_the_state() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/oidc/google/callback?code=good-code&state=wrong-state")
                .header(
                    "cookie",
                    "wa_oidc_redirect_uri=http://admin.test/; wa_oidc_next=http://login.test/",
                )
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://login.test/?error=1"));
    Ok(())
}

#[tokio::test]
async fn oidc_callback_bounces_to_login_with_pending_link_details_when_confirmation_is_required(
) -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::get("/oidc/google/callback?code=unverified-code&state=unverified-state")
                .header(
                    "cookie",
                    "wa_oidc_redirect_uri=http://admin.test/; wa_oidc_next=http://login.test/",
                )
                .body(Body::empty())?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .context("missing location header")?;
    assert_eq!(
        loc,
        "http://login.test/?pending_link_token=stub-pending-link-token&email=squatter%40example.com"
    );

    let cookies = set_cookie_values(&resp);
    assert!(cookies.iter().any(|c| c.starts_with("wa_oidc_redirect_uri=") && c.contains("Max-Age=0")));
    assert!(cookies.iter().any(|c| c.starts_with("wa_oidc_next=") && c.contains("Max-Age=0")));
    Ok(())
}

#[tokio::test]
async fn oidc_confirm_link_completes_login_with_the_correct_password() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::post("/oidc/confirm-link")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", "http://login.test")
                .body(Body::from(
                    "pending_link_token=stub-pending-link-token&password=correct-password\
                     &redirect_uri=http%3A%2F%2Fadmin.test%2F&next=http%3A%2F%2Flogin.test%2F",
                ))?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://admin.test/"));

    let cookies = set_cookie_values(&resp);
    assert!(cookies.iter().any(|c| c.starts_with("wa_session=") && c.contains("HttpOnly")));
    Ok(())
}

#[tokio::test]
async fn oidc_confirm_link_bounces_to_login_with_link_failed_on_wrong_password() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::post("/oidc/confirm-link")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", "http://login.test")
                .body(Body::from(
                    "pending_link_token=stub-pending-link-token&password=wrong-password\
                     &redirect_uri=http%3A%2F%2Fadmin.test%2F&next=http%3A%2F%2Flogin.test%2F",
                ))?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("http://login.test/?error=link_failed"));
    Ok(())
}

#[tokio::test]
async fn oidc_confirm_link_rejects_an_untrusted_origin() -> anyhow::Result<()> {
    let (backend, _h) = stub_backend().await?;
    let app = app(test_config(backend)).unwrap();

    let resp = app
        .oneshot(with_test_peer(
            Request::post("/oidc/confirm-link")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", "http://evil.test")
                .body(Body::from(
                    "pending_link_token=stub-pending-link-token&password=correct-password\
                     &redirect_uri=http%3A%2F%2Fadmin.test%2F&next=http%3A%2F%2Flogin.test%2F",
                ))?,
        ))
        .await?;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    Ok(())
}
