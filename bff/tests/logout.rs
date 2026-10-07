//! `POST /logout`: drops the session, revokes its refresh token and sends the browser to Hydra.

mod support;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use support::*;
use uuid::Uuid;

const SUB: Uuid = Uuid::from_u128(0x5b1d3d0e_3a49_4a8f_9f43_1d1f0e0a7b11);

#[tokio::test]
async fn logout_ends_the_session_revokes_the_refresh_token_and_goes_to_hydra() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(SUB, Some("sid-1")).await;
    assert_eq!(bff.whoami(&session.cookie).await.status(), StatusCode::OK);

    let response = bff
        .logout(Some("http://app.test"), Some(&session.cookie), "")
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let to = location(&response);
    assert!(
        to.starts_with("http://hydra.test/oauth2/sessions/logout?"),
        "{to}"
    );
    let query = query_of(&to);
    assert_eq!(
        query["post_logout_redirect_uri"], "http://bff.test/logged-out",
        "Hydra may only send the browser back to bff itself"
    );
    let hint = query["id_token_hint"].clone();
    let payload = hint.split('.').nth(1).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(
        claims["sub"],
        SUB.to_string(),
        "the hint is the session's id_token"
    );
    let cleared = set_cookie(&response, "wa_session").expect("session cookie cleared");
    assert!(cleared.starts_with("wa_session=;"), "{cleared}");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert_eq!(
        bff.whoami(&session.cookie).await.status(),
        StatusCode::UNAUTHORIZED,
        "the session id still works"
    );
    assert_eq!(bff.hydra.with(|hydra| hydra.revoked.clone()), ["refresh-1"]);
}

#[tokio::test]
async fn logout_hands_the_app_destination_to_hydra_as_state_when_it_is_allowed() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(SUB, None).await;

    let response = bff
        .logout(
            Some("http://app.test"),
            Some(&session.cookie),
            "?redirect_uri=http%3A%2F%2Fapp.test%2Fdashboard",
        )
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let query = query_of(&location(&response));
    assert_eq!(query["state"], "http://app.test/dashboard");
    assert_eq!(
        query["post_logout_redirect_uri"],
        "http://bff.test/logged-out"
    );
}

#[tokio::test]
async fn logout_drops_a_redirect_uri_off_the_allowlist_but_still_logs_out() {
    let bff = Bff::start_proxied().await;

    for (index, rejected) in [
        "http%3A%2F%2Fevil.test%2F",
        "http%3A%2F%2Fapp.test",
        "http%3A%2F%2Fapp.test%40evil.test%2F",
        "",
    ]
    .into_iter()
    .enumerate()
    {
        let session = bff.login(SUB, None).await;

        let response = bff
            .logout(
                Some("http://app.test"),
                Some(&session.cookie),
                &format!("?redirect_uri={rejected}"),
            )
            .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{rejected}");
        let query = query_of(&location(&response));
        assert!(!query.contains_key("state"), "{rejected}: {query:?}");
        assert!(query.contains_key("id_token_hint"), "{rejected}");
        let cleared = set_cookie(&response, "wa_session").expect("session cookie cleared");
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert_eq!(
            bff.whoami(&session.cookie).await.status(),
            StatusCode::UNAUTHORIZED,
            "{rejected}"
        );
        assert_eq!(
            bff.hydra.with(|hydra| hydra.revoked.len()),
            index + 1,
            "{rejected}"
        );
    }
}

#[tokio::test]
async fn logout_needs_a_trusted_origin() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(SUB, None).await;

    for origin in [
        None,
        Some("http://evil.test"),
        Some("http://app.test.evil.test"),
        Some("null"),
        Some("https://app.test"),
    ] {
        let response = bff.logout(origin, Some(&session.cookie), "").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{origin:?}");
        assert!(set_cookies(&response).is_empty());
    }
    assert_eq!(
        bff.whoami(&session.cookie).await.status(),
        StatusCode::OK,
        "a cross-site request logged the user out"
    );
    assert!(bff.hydra.with(|hydra| hydra.revoked.is_empty()));
}

#[tokio::test]
async fn bffs_own_origin_and_the_referer_fallback_are_trusted_too() {
    let bff = Bff::start_proxied().await;

    for (origin, referer) in [
        (Some("http://bff.test"), None),
        (None, Some("http://app.test/page")),
    ] {
        let session = bff.login(SUB, None).await;
        let mut req = axum::http::Request::post("/logout").header("cookie", &session.cookie);
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        if let Some(referer) = referer {
            req = req.header("referer", referer);
        }

        let response = bff.send(req.body(axum::body::Body::empty()).unwrap()).await;

        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "{origin:?} {referer:?}"
        );
    }
}

#[tokio::test]
async fn logout_without_a_session_still_goes_to_hydra_without_a_hint() {
    let bff = Bff::start_proxied().await;

    for cookie in [None, Some("wa_session=unknown")] {
        let response = bff.logout(Some("http://app.test"), cookie, "").await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{cookie:?}");
        let query = query_of(&location(&response));
        assert!(!query.contains_key("id_token_hint"), "{cookie:?}");
        assert!(!query.contains_key("state"), "{cookie:?}");
        assert_eq!(
            query["post_logout_redirect_uri"],
            "http://bff.test/logged-out"
        );
    }
    assert!(bff.hydra.with(|hydra| hydra.revoked.is_empty()));
}

#[tokio::test]
async fn logout_ends_the_session_even_when_hydra_cannot_revoke() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(SUB, None).await;
    bff.hydra.with(|hydra| hydra.revoke_status = 500);

    let response = bff
        .logout(Some("http://app.test"), Some(&session.cookie), "")
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        bff.whoami(&session.cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_only_ends_the_session_it_was_called_with() {
    let bff = Bff::start_proxied().await;
    let mine = bff.login(SUB, Some("sid-1")).await;
    let other_device = bff.login(SUB, Some("sid-2")).await;

    bff.logout(Some("http://app.test"), Some(&mine.cookie), "")
        .await;

    assert_eq!(
        bff.whoami(&mine.cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        bff.whoami(&other_device.cookie).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn logout_is_not_a_get() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(SUB, None).await;

    let response = bff.get("/logout", Some(&session.cookie)).await;

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(bff.whoami(&session.cookie).await.status(), StatusCode::OK);
}
