//! A session whose access token expired is refreshed at Hydra by the proxy: with client
//! authentication, once per session at a time, and without bringing back a session that ended.

mod support;

use axum::http::StatusCode;
use std::sync::Arc;
use std::time::Duration;
use support::*;
use tokio::sync::Semaphore;
use uuid::Uuid;

const SUB: Uuid = Uuid::from_u128(0x5b1d3d0e_3a49_4a8f_9f43_1d1f0e0a7b11);

/// Logs in with access tokens inside the refresh leeway, so the first proxied request has to
/// refresh. Refreshes afterwards hand out tokens that last `refreshed_ttl_secs`.
async fn expired_session(bff: &Bff, refreshed_ttl_secs: i64) -> Session {
    bff.hydra.with(|hydra| hydra.access_ttl_secs = 1);
    let session = bff.login(SUB, Some("sid-1")).await;
    bff.hydra
        .with(|hydra| hydra.access_ttl_secs = refreshed_ttl_secs);
    session
}

/// Waits until Hydra has been asked to refresh `calls` times.
async fn wait_for_refresh_calls(bff: &Bff, calls: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while bff.hydra.with(|hydra| hydra.refresh_calls) < calls {
        assert!(
            std::time::Instant::now() < deadline,
            "no refresh reached Hydra"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn token_seen(response: axum::response::Response) -> String {
    assert_eq!(response.status(), StatusCode::OK);
    body_text(response).await
}

#[tokio::test]
async fn an_expired_access_token_is_refreshed_before_the_request_goes_upstream() {
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;

    let seen = token_seen(bff.whoami(&session.cookie).await).await;

    // Not the token from login (inside the refresh leeway) -- the refreshed one.
    assert_eq!(seen, "Bearer access-2");
}

#[tokio::test]
async fn the_refresh_proves_the_client_and_names_the_refresh_token() {
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;

    bff.whoami(&session.cookie).await;

    bff.hydra.with(|hydra| {
        let request = hydra.requests.last().unwrap();
        assert_eq!(request.form["grant_type"], "refresh_token");
        assert_eq!(request.form["refresh_token"], "refresh-1");
        assert!(!request.form.contains_key("client_secret"));
        assert!(
            request
                .authorization
                .as_deref()
                .unwrap()
                .starts_with("Basic "),
            "{:?}",
            request.authorization
        );
    });
}

#[tokio::test]
async fn a_token_about_to_expire_is_refreshed_up_front() {
    let bff = Bff::start_proxied().await;
    // Still valid, but dying before the request could plausibly reach the upstream.
    bff.hydra.with(|hydra| hydra.access_ttl_secs = 2);
    let session = bff.login(SUB, None).await;
    bff.hydra.with(|hydra| hydra.access_ttl_secs = 900);

    let seen = token_seen(bff.whoami(&session.cookie).await).await;

    assert_eq!(seen, "Bearer access-2");
}

#[tokio::test]
async fn a_valid_access_token_is_used_as_is() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(SUB, None).await;

    let seen = token_seen(bff.whoami(&session.cookie).await).await;

    assert_eq!(seen, "Bearer access-1");
    assert_eq!(bff.hydra.with(|hydra| hydra.refresh_calls), 0);
}

#[tokio::test]
async fn a_refreshed_token_is_kept_so_the_next_request_does_not_refresh_again() {
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;

    for _ in 0..3 {
        assert_eq!(
            token_seen(bff.whoami(&session.cookie).await).await,
            "Bearer access-2"
        );
    }

    assert_eq!(bff.hydra.with(|hydra| hydra.refresh_calls), 1);
}

#[tokio::test]
async fn each_refresh_presents_the_refresh_token_the_last_one_returned() {
    let bff = Bff::start_proxied().await;
    // Tokens always inside the refresh leeway, so every request refreshes.
    let session = expired_session(&bff, 1).await;

    for expected in ["access-2", "access-3", "access-4"] {
        assert_eq!(
            token_seen(bff.whoami(&session.cookie).await).await,
            format!("Bearer {expected}")
        );
    }

    bff.hydra.with(|hydra| {
        assert_eq!(hydra.refresh_calls, 3);
        assert!(
            !hydra.chain_revoked,
            "a spent refresh token was presented again"
        );
    });
}

#[tokio::test]
async fn concurrent_requests_share_one_refresh() {
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;
    let gate = Arc::new(Semaphore::new(0));
    bff.hydra
        .with(|hydra| hydra.refresh_gate = Some(gate.clone()));

    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (bff, cookie) = (bff.clone(), session.cookie.clone());
        calls.spawn(async move { bff.whoami(&cookie).await });
    }
    // Hydra is slow to answer the one refresh; the others have time to pile up behind it.
    wait_for_refresh_calls(&bff, 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    gate.add_permits(8);
    let mut seen = Vec::new();
    while let Some(response) = calls.join_next().await {
        seen.push(token_seen(response.unwrap()).await);
    }

    assert_eq!(seen, vec!["Bearer access-2"; 8]);
    bff.hydra.with(|hydra| {
        assert_eq!(
            hydra.refresh_calls, 1,
            "the requests refreshed on their own"
        );
        assert!(!hydra.chain_revoked);
    });
}

#[tokio::test]
async fn sessions_refresh_independently() {
    let bff = Bff::start_proxied().await;
    let first = expired_session(&bff, 900).await;
    let second = expired_session(&bff, 900).await;
    let gate = Arc::new(Semaphore::new(0));
    bff.hydra
        .with(|hydra| hydra.refresh_gate = Some(gate.clone()));

    let mut calls = tokio::task::JoinSet::new();
    for session in [&first, &second] {
        let (bff, cookie) = (bff.clone(), session.cookie.clone());
        calls.spawn(async move { bff.whoami(&cookie).await.status() });
    }
    // Both refreshes are at Hydra at the same time: neither session waited for the other's.
    wait_for_refresh_calls(&bff, 2).await;
    gate.add_permits(2);
    while let Some(status) = calls.join_next().await {
        assert_eq!(status.unwrap(), StatusCode::OK);
    }

    assert_eq!(bff.hydra.with(|hydra| hydra.max_refreshes_in_flight), 2);
}

#[tokio::test]
async fn a_failed_refresh_leaves_no_stuck_lock_and_the_next_request_tries_again() {
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;
    bff.hydra
        .with(|hydra| hydra.refresh_failures.push_back((500, "server_error")));

    let failed = bff.whoami(&session.cookie).await;
    let retried = tokio::time::timeout(Duration::from_secs(5), bff.whoami(&session.cookie))
        .await
        .expect("the session's refresh lock was left held");

    assert_eq!(failed.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(token_seen(retried).await, "Bearer access-2");
    assert_eq!(bff.hydra.with(|hydra| hydra.refresh_calls), 2);
}

#[tokio::test]
async fn requests_queued_behind_a_failing_refresh_all_finish() {
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;
    let gate = Arc::new(Semaphore::new(0));
    bff.hydra.with(|hydra| {
        hydra.refresh_failures.push_back((500, "server_error"));
        hydra.refresh_gate = Some(gate.clone());
    });

    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let (bff, cookie) = (bff.clone(), session.cookie.clone());
        calls.spawn(async move { bff.whoami(&cookie).await.status() });
    }
    wait_for_refresh_calls(&bff, 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.add_permits(4);
    let mut statuses = Vec::new();
    let all = async {
        while let Some(status) = calls.join_next().await {
            statuses.push(status.unwrap());
        }
    };
    tokio::time::timeout(Duration::from_secs(10), all)
        .await
        .expect("a request hung behind the failed refresh");

    statuses.sort();
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 3);
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::BAD_GATEWAY)
            .count(),
        1
    );
}

async fn refresh_failing_with(status: u16, error: &'static str) -> (StatusCode, StatusCode, usize) {
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;
    bff.hydra
        .with(|hydra| hydra.refresh_failures.push_back((status, error)));

    let first = bff.whoami(&session.cookie).await;
    let second = bff.whoami(&session.cookie).await;

    let calls = bff.hydra.with(|hydra| hydra.refresh_calls);
    (first.status(), second.status(), calls)
}

#[tokio::test]
async fn a_refresh_token_hydra_refuses_ends_the_session() {
    for (status, error) in [
        (400, "invalid_grant"),
        (401, "token_inactive"),
        (403, "access_denied"),
    ] {
        let (first, second, calls) = refresh_failing_with(status, error).await;

        assert_eq!(first, StatusCode::UNAUTHORIZED, "{status} {error}");
        assert_eq!(second, StatusCode::UNAUTHORIZED, "{status} {error}");
        assert_eq!(
            calls, 1,
            "{status} {error}: the dead session was refreshed again"
        );
    }
}

#[tokio::test]
async fn hydra_rejecting_the_client_does_not_end_the_session() {
    for (status, error) in [(401, "invalid_client"), (400, "unauthorized_client")] {
        let (first, second, _) = refresh_failing_with(status, error).await;

        assert_eq!(first, StatusCode::BAD_GATEWAY, "{status} {error}");
        assert_eq!(second, StatusCode::OK, "{status} {error}");
    }
}

#[tokio::test]
async fn a_session_whose_refresh_token_expired_needs_a_new_login_without_asking_hydra() {
    let bff = Bff::start_with(|config| {
        config.hydra_refresh_token_ttl_secs = 1;
        config.routes = vec![api_route("http://unused.test".into())];
    })
    .await;
    let session = expired_session(&bff, 900).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let response = bff.whoami(&session.cookie).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(bff.hydra.with(|hydra| hydra.refresh_calls), 0);
}

#[tokio::test]
async fn a_refresh_renews_the_refresh_token_lifetime() {
    let upstream = stub_upstream().await;
    let bff = Bff::start_with(|config| {
        config.hydra_refresh_token_ttl_secs = 3;
        config.routes = vec![api_route(upstream)];
    })
    .await;
    // Every request refreshes, so each one is a chance for the lifetime to run out.
    let session = expired_session(&bff, 1).await;

    tokio::time::sleep(Duration::from_millis(2000)).await;
    let first = bff.whoami(&session.cookie).await.status();
    tokio::time::sleep(Duration::from_millis(2000)).await;
    // 4s after login: past the login's refresh token lifetime (3s), inside the renewed one.
    let second = bff.whoami(&session.cookie).await.status();

    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::OK);
}

#[tokio::test]
async fn a_refresh_without_a_rotated_token_keeps_the_old_refresh_expiry() {
    let upstream = stub_upstream().await;
    let bff = Bff::start_with(|config| {
        config.hydra_refresh_token_ttl_secs = 3;
        config.routes = vec![api_route(upstream)];
    })
    .await;
    let session = expired_session(&bff, 1).await;
    bff.hydra.with(|hydra| hydra.no_refresh_token = true);

    tokio::time::sleep(Duration::from_millis(2000)).await;
    let first = bff.whoami(&session.cookie).await.status();
    tokio::time::sleep(Duration::from_millis(2000)).await;
    // 4s after login: past the login's refresh token lifetime, which that refresh did not renew.
    let second = bff.whoami(&session.cookie).await.status();

    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_logout_during_a_refresh_is_not_undone_by_it() {
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;
    let gate = Arc::new(Semaphore::new(0));
    bff.hydra
        .with(|hydra| hydra.refresh_gate = Some(gate.clone()));
    let refreshing = {
        let (bff, cookie) = (bff.clone(), session.cookie.clone());
        tokio::spawn(async move { bff.whoami(&cookie).await })
    };
    // Hydra has issued the new tokens but its answer has not reached bff yet.
    wait_for_refresh_calls(&bff, 1).await;

    let logout = bff
        .logout(Some("http://app.test"), Some(&session.cookie), "")
        .await;
    gate.add_permits(1);
    let refreshed = refreshing.await.unwrap();

    assert_eq!(logout.status(), StatusCode::SEE_OTHER);
    assert_eq!(refreshed.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        bff.whoami(&session.cookie).await.status(),
        StatusCode::UNAUTHORIZED,
        "the refresh brought the session back"
    );
    // The tokens the late refresh got must not outlive the logout.
    assert!(
        bff.hydra
            .with(|hydra| hydra.revoked.contains(&"refresh-2".to_string()))
    );
}

#[tokio::test]
async fn a_refresh_that_returns_no_id_token_keeps_the_one_logout_needs() {
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;
    bff.hydra
        .with(|hydra| hydra.refresh_returns_id_token = false);
    bff.whoami(&session.cookie).await;

    let response = bff
        .logout(Some("http://app.test"), Some(&session.cookie), "")
        .await;

    assert!(query_of(&location(&response)).contains_key("id_token_hint"));
}

#[tokio::test]
async fn a_refresh_that_returns_an_id_token_does_not_replace_the_one_logout_sends() {
    use base64::Engine;
    let bff = Bff::start_proxied().await;
    let session = expired_session(&bff, 900).await;
    bff.whoami(&session.cookie).await;
    assert_eq!(bff.hydra.with(|hydra| hydra.refresh_calls), 1);

    let response = bff
        .logout(Some("http://app.test"), Some(&session.cookie), "")
        .await;

    let hint = query_of(&location(&response))["id_token_hint"].clone();
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(hint.split('.').nth(1).unwrap())
        .unwrap();
    let claims = String::from_utf8(claims).unwrap();
    assert!(claims.contains(&at_hash("access-1")), "{claims}");
    assert!(!claims.contains(&at_hash("access-2")), "{claims}");
}
