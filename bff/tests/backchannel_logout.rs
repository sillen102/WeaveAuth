//! `POST /backchannel-logout` on the internal listener: Hydra logging a user out.

mod support;

use axum::http::StatusCode;
use support::*;
use uuid::Uuid;

const ALICE: Uuid = Uuid::from_u128(0x5b1d3d0e_3a49_4a8f_9f43_1d1f0e0a7b11);
const BOB: Uuid = Uuid::from_u128(0x7c2e4e1f_4b5a_4b9a_8a54_2e2a1f1b8c22);

async fn works(bff: &Bff, session: &Session) -> bool {
    bff.whoami(&session.cookie).await.status() == StatusCode::OK
}

#[tokio::test]
async fn a_token_for_a_user_and_a_session_ends_that_session_only() {
    let bff = Bff::start_proxied().await;
    let phone = bff.login(ALICE, Some("sid-phone")).await;
    let laptop = bff.login(ALICE, Some("sid-laptop")).await;
    let bobs = bff.login(BOB, Some("sid-phone")).await;

    let response = bff
        .backchannel_logout(&sign(&logout_claims(Some(ALICE), Some("sid-phone"))))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
    assert!(!works(&bff, &phone).await, "the named session survived");
    assert!(
        works(&bff, &laptop).await,
        "another session of the user was ended"
    );
    assert!(works(&bff, &bobs).await, "another user's session was ended");
}

#[tokio::test]
async fn the_refresh_token_of_an_ended_session_is_revoked_at_hydra_too() {
    let bff = Bff::start_proxied().await;
    bff.login(ALICE, Some("sid-phone")).await;
    bff.login(ALICE, Some("sid-laptop")).await;

    bff.backchannel_logout(&sign(&logout_claims(None, Some("sid-phone"))))
        .await;

    // Hydra's own logout does not revoke the refresh tokens bff holds.
    assert_eq!(bff.hydra.with(|hydra| hydra.revoked.clone()), ["refresh-1"]);
}

#[tokio::test]
async fn hydras_own_token_shape_names_only_a_session() {
    // aud, events, iat, iss, jti and sid: no sub, no exp, no nonce.
    let bff = Bff::start_proxied().await;
    let session = bff.login(ALICE, Some("sid-phone")).await;
    let claims = logout_claims(None, Some("sid-phone"));
    assert!(claims.get("sub").is_none() && claims.get("exp").is_none());

    let response = bff.backchannel_logout(&sign(&claims)).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!works(&bff, &session).await);
}

#[tokio::test]
async fn a_token_for_a_user_alone_ends_every_session_of_the_user() {
    let bff = Bff::start_proxied().await;
    let phone = bff.login(ALICE, Some("sid-phone")).await;
    let laptop = bff.login(ALICE, Some("sid-laptop")).await;
    let bobs = bff.login(BOB, Some("sid-phone")).await;

    let response = bff
        .backchannel_logout(&sign(&logout_claims(Some(ALICE), None)))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!works(&bff, &phone).await);
    assert!(!works(&bff, &laptop).await);
    assert!(works(&bff, &bobs).await);
}

#[tokio::test]
async fn a_token_for_a_session_alone_ends_the_sessions_with_that_sid() {
    let bff = Bff::start_proxied().await;
    let phone = bff.login(ALICE, Some("sid-phone")).await;
    let laptop = bff.login(ALICE, Some("sid-laptop")).await;

    let response = bff
        .backchannel_logout(&sign(&logout_claims(None, Some("sid-phone"))))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!works(&bff, &phone).await);
    assert!(works(&bff, &laptop).await);
}

#[tokio::test]
async fn a_user_with_no_sessions_here_is_not_an_error() {
    let bff = Bff::start_proxied().await;

    let response = bff
        .backchannel_logout(&sign(&logout_claims(Some(ALICE), None)))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_token_that_does_not_verify_ends_nothing() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(ALICE, Some("sid-1")).await;
    let valid = logout_claims(Some(ALICE), Some("sid-1"));
    let with = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut claims = valid.clone();
        change(&mut claims);
        sign(&claims)
    };
    let without = |name: &'static str| {
        with(&move |claims| {
            claims.as_object_mut().unwrap().remove(name);
        })
    };
    let cases = [
        ("signed by another key", sign_with(OTHER_KEY, &valid)),
        (
            "another issuer",
            with(&|claims| claims["iss"] = "http://evil.test".into()),
        ),
        (
            "another audience",
            with(&|claims| claims["aud"] = serde_json::json!(["another-client"])),
        ),
        ("no audience", without("aud")),
        ("no issuer", without("iss")),
        ("with a nonce", with(&|claims| claims["nonce"] = "n".into())),
        ("no events", without("events")),
        (
            "wrong event",
            with(&|claims| {
                claims["events"] = serde_json::json!({"http://schemas.openid.net/event/other": {}})
            }),
        ),
        ("no jti", without("jti")),
        ("no iat", without("iat")),
        (
            "stale iat",
            with(&|claims| claims["iat"] = (now() - 3600).into()),
        ),
        (
            "future iat",
            with(&|claims| claims["iat"] = (now() + 3600).into()),
        ),
        (
            "expired",
            with(&|claims| claims["exp"] = (now() - 3600).into()),
        ),
        (
            "no sub or sid",
            with(&|claims| {
                let claims = claims.as_object_mut().unwrap();
                claims.remove("sub");
                claims.remove("sid");
            }),
        ),
        (
            "a subject that is not a user",
            with(&|claims| claims["sub"] = "alice".into()),
        ),
        ("not a JWT", "garbage".to_string()),
        ("empty", String::new()),
        ("an id_token", {
            let mut id_token = valid.clone();
            id_token["nonce"] = "n".into();
            id_token["exp"] = (now() + 3600).into();
            sign(&id_token)
        }),
    ];

    for (name, token) in cases {
        let response = bff.backchannel_logout(&token).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        assert!(works(&bff, &session).await, "{name} ended the session");
    }
}

#[tokio::test]
async fn a_token_cannot_be_replayed() {
    let bff = Bff::start_proxied().await;
    let first = bff.login(ALICE, Some("sid-1")).await;
    let token = sign(&logout_claims(Some(ALICE), None));

    let accepted = bff.backchannel_logout(&token).await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert!(!works(&bff, &first).await);
    // The user logs in again; the captured token must not end that login too.
    let second = bff.login(ALICE, Some("sid-2")).await;
    let replayed = bff.backchannel_logout(&token).await;

    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
    assert!(
        works(&bff, &second).await,
        "a replayed token ended a later login"
    );
}

#[tokio::test]
async fn an_unverified_token_does_not_use_up_its_jti() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(ALICE, Some("sid-1")).await;
    let claims = logout_claims(Some(ALICE), None);

    let forged = bff.backchannel_logout(&sign_with(OTHER_KEY, &claims)).await;
    // Control: the same claims, signed by Hydra's key, do log the user out.
    let genuine = bff.backchannel_logout(&sign(&claims)).await;

    assert_eq!(forged.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        genuine.status(),
        StatusCode::OK,
        "a forged token burnt the jti"
    );
    assert!(!works(&bff, &session).await);
}

/// Hydra's public key, as PEM and DER, in both the SPKI and the PKCS#1 encoding.
fn public_key_encodings() -> Vec<Vec<u8>> {
    use base64::Engine;
    [
        include_str!("fixtures/hydra_pub.pem"),
        include_str!("fixtures/hydra_pub_pkcs1.pem"),
    ]
    .into_iter()
    .flat_map(|pem| {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();
        [pem.as_bytes().to_vec(), der]
    })
    .collect()
}

#[tokio::test]
async fn a_token_signed_with_an_hmac_key_made_of_the_public_key_is_refused() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(ALICE, Some("sid-1")).await;
    let claims = logout_claims(Some(ALICE), None);

    for secret in public_key_encodings() {
        for algorithm in [
            jsonwebtoken::Algorithm::HS256,
            jsonwebtoken::Algorithm::HS384,
            jsonwebtoken::Algorithm::HS512,
        ] {
            let mut header = jsonwebtoken::Header::new(algorithm);
            header.kid = Some(KID.to_string());
            let forged = jsonwebtoken::encode(
                &header,
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(&secret),
            )
            .unwrap();

            let response = bff.backchannel_logout(&forged).await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{algorithm:?}");
            assert!(works(&bff, &session).await, "{algorithm:?}");
        }
    }
    // Control: the same claims, signed by Hydra's key, do log the user out.
    let genuine = bff.backchannel_logout(&sign(&claims)).await;
    assert_eq!(genuine.status(), StatusCode::OK);
    assert!(!works(&bff, &session).await);
}

#[tokio::test]
async fn an_unreachable_hydra_keys_endpoint_is_unavailable_not_a_refusal() {
    let bff =
        Bff::start_with(|config| config.hydra_internal_url = "http://127.0.0.1:1".into()).await;

    let response = bff
        .backchannel_logout(&sign(&logout_claims(Some(ALICE), None)))
        .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_request_must_be_a_form_with_a_logout_token() {
    let bff = Bff::start_proxied().await;
    let token = sign(&logout_claims(Some(ALICE), None));

    let json = bff
        .send_internal(
            axum::http::Request::post("/backchannel-logout")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(format!(
                    r#"{{"logout_token":"{token}"}}"#
                )))
                .unwrap(),
        )
        .await;
    let no_field = bff
        .send_internal(
            axum::http::Request::post("/backchannel-logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from("other=1"))
                .unwrap(),
        )
        .await;

    assert!(json.status().is_client_error(), "{}", json.status());
    assert!(no_field.status().is_client_error(), "{}", no_field.status());
}

#[tokio::test]
async fn the_public_listener_does_not_serve_the_internal_routes() {
    let bff = Bff::start_proxied().await;
    let token = sign(&logout_claims(Some(ALICE), None));

    let logout = bff
        .send(
            axum::http::Request::post("/backchannel-logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(form_body(&[("logout_token", &token)]))
                .unwrap(),
        )
        .await;
    let revoke = bff
        .send(
            axum::http::Request::post("/internal/revoke")
                .header("authorization", format!("Bearer {INTERNAL_API_KEY}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap(),
        )
        .await;

    assert_eq!(logout.status(), StatusCode::NOT_FOUND);
    assert_eq!(revoke.status(), StatusCode::NOT_FOUND);
}
