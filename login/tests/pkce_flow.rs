use axum::body::Body;
use axum::extract::Form;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use tower::ServiceExt;

use weaveauth_login::{app_with_state, AuthState, Config, PendingAuth};

fn test_config(backend_url: String) -> Config {
    Config {
        port: 8080,
        login_url: "http://login.test".into(),
        backend_url,
        default_redirect_uri: "http://admin.test".into(),
    }
}

async fn stub_backend() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route(
        "/oauth/token",
        post(
            |Form(body): Form<serde_json::Value>| async move {
                assert!(body["code"].is_string());
                assert!(body["code_verifier"].is_string());
                assert_eq!(body["grant_type"], "authorization_code");
                Json(serde_json::json!({
                    "access_token": "test-access-token",
                    "token_type": "Bearer"
                }))
            },
        ),
    );
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn login_redirects_to_authorize_with_pkce_params() {
    let (backend, _h) = stub_backend().await;
    let app = app_with_state(AuthState::new(test_config(backend.clone())));

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
    assert!(loc.starts_with(&format!(
        "{backend}/oauth/authorize?"
    )));
    assert!(loc.contains("response_type=code"));
    assert!(loc.contains("redirect_uri=http%3A%2F%2Flogin.test%2Fcallback"));
    assert!(loc.contains("code_challenge="));
    assert!(loc.contains("code_challenge_method=S256"));
    assert!(loc.contains("state="));
}

#[tokio::test]
async fn callback_exchanges_code_and_redirects_with_token() {
    let (backend, _h) = stub_backend().await;
    let state = AuthState::new(test_config(backend));
    state.pending.lock().unwrap().insert(
        "test-state".into(),
        PendingAuth {
            code_verifier: "test-verifier".into(),
            redirect_uri: "http://admin.test/".into(),
        },
    );
    let app = app_with_state(state);

    let resp = app
        .oneshot(
            Request::get("/callback?code=stub-code&state=test-state")
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
    assert_eq!(loc, "http://admin.test/?access_token=test-access-token");
}

#[tokio::test]
async fn callback_rejects_unknown_state() {
    let (backend, _h) = stub_backend().await;
    let app = app_with_state(AuthState::new(test_config(backend)));

    let resp = app
        .oneshot(
            Request::get("/callback?code=stub-code&state=unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn callback_rejects_missing_code() {
    let (backend, _h) = stub_backend().await;
    let state = AuthState::new(test_config(backend));
    state.pending.lock().unwrap().insert(
        "test-state".into(),
        PendingAuth {
            code_verifier: "test-verifier".into(),
            redirect_uri: "http://admin.test/".into(),
        },
    );
    let app = app_with_state(state);

    let resp = app
        .oneshot(
            Request::get("/callback?state=test-state")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn state_is_single_use() {
    let (backend, _h) = stub_backend().await;
    let state = AuthState::new(test_config(backend));
    state.pending.lock().unwrap().insert(
        "test-state".into(),
        PendingAuth {
            code_verifier: "test-verifier".into(),
            redirect_uri: "http://admin.test/".into(),
        },
    );
    let app = app_with_state(state);

    let first = app
        .clone()
        .oneshot(
            Request::get("/callback?code=stub-code&state=test-state")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(first.status().is_redirection());

    let second = app
        .oneshot(
            Request::get("/callback?code=stub-code&state=test-state")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
}