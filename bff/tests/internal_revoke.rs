//! `POST /internal/revoke`: hooks ending every session of a user after a recovery or a
//! password change.

mod support;

use axum::http::StatusCode;
use support::*;
use uuid::Uuid;

const ALICE: Uuid = Uuid::from_u128(0x5b1d3d0e_3a49_4a8f_9f43_1d1f0e0a7b11);
const BOB: Uuid = Uuid::from_u128(0x7c2e4e1f_4b5a_4b9a_8a54_2e2a1f1b8c22);

fn bearer() -> String {
    format!("Bearer {INTERNAL_API_KEY}")
}

fn body_for(user: Uuid) -> String {
    format!(r#"{{"sub":"{user}"}}"#)
}

async fn works(bff: &Bff, session: &Session) -> bool {
    bff.whoami(&session.cookie).await.status() == StatusCode::OK
}

#[tokio::test]
async fn with_the_key_it_ends_every_session_of_that_user_and_only_theirs() {
    let bff = Bff::start_proxied().await;
    let phone = bff.login(ALICE, Some("sid-1")).await;
    let laptop = bff.login(ALICE, Some("sid-2")).await;
    let bobs = bff.login(BOB, Some("sid-3")).await;

    let response = bff.internal_revoke(Some(&bearer()), &body_for(ALICE)).await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!works(&bff, &phone).await);
    assert!(!works(&bff, &laptop).await);
    assert!(works(&bff, &bobs).await);
}

#[tokio::test]
async fn the_refresh_tokens_of_the_ended_sessions_are_revoked_at_hydra_too() {
    let bff = Bff::start_proxied().await;
    bff.login(ALICE, Some("sid-1")).await;
    bff.login(BOB, Some("sid-2")).await;
    bff.login(ALICE, Some("sid-3")).await;

    bff.internal_revoke(Some(&bearer()), &body_for(ALICE)).await;

    let mut revoked = bff.hydra.with(|hydra| hydra.revoked.clone());
    revoked.sort();
    assert_eq!(revoked, ["refresh-1", "refresh-3"]);
}

#[tokio::test]
async fn it_ends_the_sessions_even_when_hydra_cannot_revoke() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(ALICE, None).await;
    bff.hydra.with(|hydra| hydra.revoke_status = 500);

    let response = bff.internal_revoke(Some(&bearer()), &body_for(ALICE)).await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!works(&bff, &session).await);
}

#[tokio::test]
async fn without_the_key_it_ends_nothing() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(ALICE, None).await;
    let body = body_for(ALICE);
    let almost = format!("Bearer {INTERNAL_API_KEY}x");
    let shorter = format!("Bearer {}", &INTERNAL_API_KEY[..INTERNAL_API_KEY.len() - 1]);
    let wrong_scheme = format!("Basic {INTERNAL_API_KEY}");
    let bare = INTERNAL_API_KEY.to_string();

    for authorization in [
        None,
        Some(""),
        Some("Bearer "),
        Some("Bearer"),
        Some(almost.as_str()),
        Some(shorter.as_str()),
        Some(wrong_scheme.as_str()),
        Some(bare.as_str()),
        Some("Bearer wrong-key"),
    ] {
        let response = bff.internal_revoke(authorization, &body).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{authorization:?}"
        );
        assert!(
            works(&bff, &session).await,
            "{authorization:?} ended the session"
        );
    }
}

#[tokio::test]
async fn the_key_is_checked_before_the_body_is_read() {
    let bff = Bff::start_proxied().await;

    let response = bff
        .internal_revoke(Some("Bearer wrong-key"), "not json")
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_body_that_is_not_a_user_id_is_a_client_error_that_ends_nothing() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(ALICE, None).await;

    for body in [
        "",
        "not json",
        "{}",
        r#"{"sub":"alice"}"#,
        r#"{"sub":null}"#,
        r#"{"sub":5}"#,
    ] {
        let response = bff.internal_revoke(Some(&bearer()), body).await;
        assert!(
            response.status().is_client_error(),
            "{body}: {}",
            response.status()
        );
        assert!(works(&bff, &session).await, "{body}");
    }
}

#[tokio::test]
async fn a_user_with_no_sessions_is_not_an_error() {
    let bff = Bff::start_proxied().await;

    let response = bff.internal_revoke(Some(&bearer()), &body_for(ALICE)).await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
