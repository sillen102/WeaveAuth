//! Logout and consent: the chains between login, Kratos and Hydra's admin API.

mod common;

use common::*;
use serde_json::json;
use weaveauth_login::{Config, app};

async fn setup() -> (axum::Router, std::sync::Arc<StubState>) {
    let (url, state) = stub().await;
    (app(config(&url)).unwrap(), state)
}

#[tokio::test]
async fn logout_ends_the_kratos_session_then_accepts_hydras_request() {
    let (app, state) = setup().await;

    let reply = get_with_cookie(
        &app,
        "/logout?logout_challenge=lc1",
        "ory_kratos_session=s; csrf=1",
    )
    .await;

    assert_eq!(reply.status, 303);
    assert_eq!(
        reply.header("location"),
        "http://login.test/oauth2/sessions/logout?logout_verifier=v"
    );
    // The cleared cookies Kratos answers with reach the browser.
    assert_eq!(
        reply.set_cookies(),
        vec!["ory_kratos_session=; Max-Age=0; Path=/".to_string()]
    );
    let kratos_token = state.requests("/self-service/logout/browser");
    assert_eq!(
        kratos_token[0].cookie(),
        Some("ory_kratos_session=s; csrf=1")
    );
    let ended = state.requests("/self-service/logout?");
    assert_eq!(ended[0].path_and_query, "/self-service/logout?token=tok");
    assert_eq!(ended[0].cookie(), Some("ory_kratos_session=s; csrf=1"));
    let accepted = state.requests("/admin/oauth2/auth/requests/logout/accept");
    assert_eq!(accepted[0].method, "PUT");
    assert_eq!(
        accepted[0].path_and_query,
        "/admin/oauth2/auth/requests/logout/accept?logout_challenge=lc1"
    );
    let order = state.all();
    let position = |needle: &str| order.iter().position(|line| line.contains(needle)).unwrap();
    assert!(
        position("/self-service/logout?token") < position("logout/accept"),
        "{order:?}"
    );
}

#[tokio::test]
async fn logout_without_a_kratos_session_still_finishes_hydras_logout() {
    let (app, state) = setup().await;
    *state.logged_in.lock().unwrap() = false;

    let reply = get(&app, "/logout?logout_challenge=lc1").await;

    assert_eq!(reply.status, 303);
    assert_eq!(state.requests("/self-service/logout?").len(), 0);
    assert_eq!(
        state.count("PUT", "/admin/oauth2/auth/requests/logout/accept"),
        1
    );
}

#[tokio::test]
async fn a_logout_the_app_did_not_start_is_not_accepted() {
    let (app, state) = setup().await;
    state.logout_request.lock().unwrap().1 = json!({"rp_initiated": false, "subject": "u1"});

    let reply = get(&app, "/logout?logout_challenge=lc1").await;

    assert_eq!(reply.status, 400);
    assert_eq!(
        state.count("PUT", "/admin/oauth2/auth/requests/logout/accept"),
        0
    );
    assert_eq!(
        state.requests("/self-service/logout").len(),
        0,
        "the session stays"
    );
}

#[tokio::test]
async fn logout_needs_a_challenge() {
    let (app, state) = setup().await;

    let reply = get(&app, "/logout").await;

    assert_eq!(reply.status, 400);
    assert!(state.all().is_empty());
}

#[tokio::test]
async fn logout_fails_generically_when_hydra_does() {
    let (url, state) = stub().await;
    *state.accept_logout_status.lock().unwrap() = axum::http::StatusCode::INTERNAL_SERVER_ERROR;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/logout?logout_challenge=lc1").await;

    assert_eq!(reply.status, 502);
    assert!(!reply.body.contains(&url));
}

#[tokio::test]
async fn consent_is_auto_accepted_for_the_configured_client_and_scopes() {
    let (app, state) = setup().await;

    let reply = get(&app, "/consent?consent_challenge=cc1").await;

    assert_eq!(reply.status, 303);
    assert_eq!(
        reply.header("location"),
        "http://login.test/oauth2/auth?consent_verifier=ok"
    );
    let accepted = &state.requests("/admin/oauth2/auth/requests/consent/accept")[0];
    assert_eq!(
        accepted.path_and_query,
        "/admin/oauth2/auth/requests/consent/accept?consent_challenge=cc1"
    );
    let body: serde_json::Value = serde_json::from_str(&accepted.body).unwrap();
    assert_eq!(body["grant_scope"], json!(["openid", "offline_access"]));
    assert_eq!(
        body["grant_access_token_audience"],
        json!(["https://api.test"]),
        "the client's own audience is not granted unasked"
    );
    assert_eq!(
        state.count("PUT", "/admin/oauth2/auth/requests/consent/reject"),
        0
    );
}

#[tokio::test]
async fn consent_for_any_other_client_is_rejected() {
    let (app, state) = setup().await;
    *state.consent_request.lock().unwrap() = consent_request("someone-else", &["openid"]);

    let reply = get(&app, "/consent?consent_challenge=cc1").await;

    assert_eq!(reply.status, 303);
    assert_eq!(
        reply.header("location"),
        "http://login.test/oauth2/auth?consent_verifier=denied"
    );
    assert_eq!(
        state.count("PUT", "/admin/oauth2/auth/requests/consent/accept"),
        0
    );
}

#[tokio::test]
async fn consent_for_scopes_beyond_the_allowed_ones_is_rejected() {
    let (app, state) = setup().await;
    *state.consent_request.lock().unwrap() =
        consent_request("bff", &["openid", "offline_access", "admin"]);

    let reply = get(&app, "/consent?consent_challenge=cc1").await;

    assert_eq!(
        reply.header("location"),
        "http://login.test/oauth2/auth?consent_verifier=denied"
    );
    assert_eq!(
        state.count("PUT", "/admin/oauth2/auth/requests/consent/accept"),
        0
    );
}

#[tokio::test]
async fn a_subset_of_the_allowed_scopes_is_granted_as_asked() {
    let (app, state) = setup().await;
    *state.consent_request.lock().unwrap() = consent_request("bff", &["openid"]);

    let reply = get(&app, "/consent?consent_challenge=cc1").await;

    assert_eq!(
        reply.header("location"),
        "http://login.test/oauth2/auth?consent_verifier=ok"
    );
    let body: serde_json::Value =
        serde_json::from_str(&state.requests("/admin/oauth2/auth/requests/consent/accept")[0].body)
            .unwrap();
    assert_eq!(body["grant_scope"], json!(["openid"]));
}

#[tokio::test]
async fn the_consent_client_is_configurable() {
    let (url, state) = stub().await;
    *state.consent_request.lock().unwrap() = consent_request("custom", &["openid"]);
    let app = app(Config {
        bff_client_id: "custom".into(),
        ..config(&url)
    })
    .unwrap();

    let reply = get(&app, "/consent?consent_challenge=cc1").await;

    assert_eq!(
        reply.header("location"),
        "http://login.test/oauth2/auth?consent_verifier=ok"
    );
}

#[tokio::test]
async fn consent_needs_a_challenge_and_fails_generically() {
    let (app, state) = setup().await;

    assert_eq!(get(&app, "/consent").await.status, 400);
    assert!(state.all().is_empty());

    let app = weaveauth_login::app(config("http://127.0.0.1:1")).unwrap();
    let reply = get(&app, "/consent?consent_challenge=cc1").await;
    assert_eq!(reply.status, 502);
    assert!(!reply.body.contains("127.0.0.1"));
}

#[tokio::test]
async fn logout_clears_the_cookies_even_when_hydra_fails_to_accept() {
    let (url, state) = stub().await;
    *state.accept_logout_status.lock().unwrap() = axum::http::StatusCode::INTERNAL_SERVER_ERROR;
    let app = app(config(&url)).unwrap();

    let reply = get_with_cookie(&app, "/logout?logout_challenge=lc1", "ory_kratos_session=s").await;

    assert_eq!(reply.status, 502);
    assert_eq!(
        reply.set_cookies(),
        vec!["ory_kratos_session=; Max-Age=0; Path=/".to_string()]
    );
}
