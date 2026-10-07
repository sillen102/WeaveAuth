mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{Call, Harness, ID, identity_json, token_hook_body};

fn kratos_with(
    email: &str,
    verified: bool,
) -> impl Fn(&Call) -> (u16, Value) + Send + Sync + use<> {
    let email = email.to_string();
    move |call: &Call| {
        let id = call.path().rsplit('/').next().unwrap_or_default();
        (200, identity_json(id, &email, verified))
    }
}

async fn harness_with_claims(
    claims: impl Fn(&Call) -> (u16, Value) + Send + Sync + 'static,
) -> Harness {
    let mut harness = Harness::with(
        kratos_with("alice@example.com", true),
        support::no_content,
        support::no_content,
    )
    .await;
    harness.config.login_claims_handler = Some(harness.webhook("claims", claims).await);
    harness
}

#[tokio::test]
async fn adds_the_identity_email_and_the_deployers_claims_to_the_access_token() {
    let harness = harness_with_claims(|_| (200, json!({"roles": ["admin"]}))).await;

    let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::OK);
    let access = &body["session"]["access_token"];
    assert_eq!(access["email"], "alice@example.com");
    assert_eq!(access["email_verified"], true);
    assert_eq!(access["roles"], json!(["admin"]));
    let id_token = &body["session"]["id_token"];
    assert_eq!(id_token["email"], "alice@example.com");
    assert_eq!(id_token["email_verified"], true);
    assert!(
        id_token.get("roles").is_none(),
        "deployer claims are for the access token"
    );
}

#[tokio::test]
async fn looks_the_subject_up_in_kratos_and_hands_the_webhook_user_id_and_email() {
    let harness = harness_with_claims(|_| (200, json!({}))).await;

    harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    let kratos = harness.log.of("kratos");
    assert_eq!(kratos.len(), 1);
    assert_eq!(kratos[0].method, "GET");
    assert_eq!(kratos[0].path(), format!("/admin/identities/{ID}"));
    let webhook = harness.log.of("claims");
    assert_eq!(
        webhook[0].body,
        json!({"user_id": ID, "email": "alice@example.com", "email_verified": true, "client_id": "bff", "scopes": ["openid", "offline_access"]})
    );
}

#[tokio::test]
async fn the_claims_webhook_is_told_when_the_email_is_unverified() {
    let mut harness = Harness::with(
        kratos_with("ceo@corp.example", false),
        support::no_content,
        support::no_content,
    )
    .await;
    harness.config.require_verified_email = false;
    harness.config.login_claims_handler =
        Some(harness.webhook("claims", |_| (200, json!({}))).await);

    let (status, _) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(harness.log.of("claims")[0].body["email_verified"], false);
}

#[tokio::test]
async fn a_deactivated_identity_gets_no_token_and_the_webhook_is_not_asked() {
    for state in ["inactive", "deactivated", ""] {
        let mut harness = Harness::with(
            move |call: &Call| {
                let id = call.path().rsplit('/').next().unwrap_or_default();
                let mut identity = identity_json(id, "alice@example.com", true);
                identity["state"] = state.into();
                (200, identity)
            },
            support::no_content,
            support::no_content,
        )
        .await;
        harness.config.login_claims_handler = Some(
            harness
                .webhook("claims", |_| (200, json!({"roles": ["admin"]})))
                .await,
        );

        let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

        assert_eq!(status, StatusCode::FORBIDDEN, "{state:?}");
        assert_eq!(body["reason"], "IdentityInactive", "{state:?}");
        assert!(body.get("session").is_none(), "{state:?}");
        assert!(harness.log.of("claims").is_empty(), "{state:?}");
    }
}

#[tokio::test]
async fn an_identity_without_an_email_is_denied_and_so_is_one_whose_state_is_missing() {
    for (what, patch) in [
        ("no email", json!({"traits": {}})),
        ("no state", json!({"state": null})),
    ] {
        let harness = Harness::with(
            move |call: &Call| {
                let id = call.path().rsplit('/').next().unwrap_or_default();
                let mut identity = identity_json(id, "alice@example.com", true);
                for (key, value) in patch.as_object().unwrap() {
                    identity[key] = value.clone();
                }
                (200, identity)
            },
            support::no_content,
            support::no_content,
        )
        .await;

        let (status, _) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

        assert_eq!(status, StatusCode::FORBIDDEN, "{what}");
    }
}

#[tokio::test]
async fn a_claims_answer_over_the_size_limit_fails_closed() {
    let harness =
        harness_with_claims(|_| (200, json!({"roles": "x".repeat(2 * 1024 * 1024)}))).await;

    let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.get("session").is_none());
}

#[tokio::test]
async fn an_unverified_email_is_reported_as_such() {
    let mut harness = Harness::with(
        kratos_with("alice@example.com", false),
        support::no_content,
        support::no_content,
    )
    .await;
    harness.config.login_claims_handler = None;
    harness.config.require_verified_email = false;

    let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["session"]["access_token"]["email_verified"], false);
}

#[tokio::test]
async fn an_unverified_email_gets_no_token_by_default_and_the_webhook_is_not_asked() {
    let mut harness = Harness::with(
        kratos_with("alice@example.com", false),
        support::no_content,
        support::no_content,
    )
    .await;
    harness.config.login_claims_handler =
        Some(harness.webhook("claims", |_| (200, json!({}))).await);

    let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["reason"], "EmailNotVerified");
    assert!(body.get("session").is_none());
    assert!(harness.log.of("claims").is_empty());
}

#[tokio::test]
async fn without_a_claims_webhook_only_the_email_claims_are_added() {
    let harness = Harness::new().await;

    let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["session"]["access_token"],
        json!({"email": "alice@example.com", "email_verified": true})
    );
}

#[tokio::test]
async fn a_claim_named_like_one_the_token_already_carries_is_refused() {
    for reserved in [
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti",
        "email",
        "email_verified",
        "scp",
        "client_id",
        "ext",
        "sid",
        "nonce",
        "auth_time",
        "acr",
        "amr",
        "at_hash",
        "c_hash",
        "rat",
        "scope",
        "azp",
        "cnf",
        "act",
        "may_act",
        "typ",
        "token_use",
    ] {
        let harness =
            harness_with_claims(move |_| (200, json!({"roles": ["x"], reserved: "spoofed"}))).await;

        let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

        assert_eq!(status, StatusCode::FORBIDDEN, "{reserved}");
        assert_eq!(body["reason"], "ReservedClaimOverridden", "{reserved}");
        assert!(
            body.get("session").is_none(),
            "{reserved}: no claims may be issued"
        );
        assert!(!body.to_string().contains("spoofed"), "{reserved}");
    }
}

#[tokio::test]
async fn an_ordinary_claim_name_is_not_mistaken_for_a_reserved_one() {
    let harness =
        harness_with_claims(|_| (200, json!({"email_domain": "example.com", "emails": 2}))).await;

    let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["session"]["access_token"]["email_domain"],
        "example.com"
    );
}

#[tokio::test]
async fn fails_closed_when_the_claims_webhook_fails() {
    for (what, status, body) in [
        (
            "5xx",
            500,
            json!({"error": "internal db password is hunter2"}),
        ),
        ("4xx", 403, json!({})),
        ("unknown user", 404, json!({})),
        ("not an object", 200, json!(["roles"])),
    ] {
        let harness = harness_with_claims(move |_| (status, body.clone())).await;

        let (code, response) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

        assert_eq!(code, StatusCode::BAD_GATEWAY, "{what}");
        assert_eq!(response["reason"], "DownstreamServiceFailed", "{what}");
        assert!(response.get("session").is_none(), "{what}");
        assert!(!response.to_string().contains("hunter2"), "{what}");
    }
}

#[tokio::test]
async fn fails_closed_when_the_claims_webhook_is_unreachable() {
    let mut harness = Harness::new().await;
    harness.config.login_claims_handler = Some(weaveauth_hooks::config::WebhookConfig {
        url: "http://127.0.0.1:1/hook".to_string(),
        timeout_secs: 1,
        bearer_token: None,
    });

    let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.get("session").is_none());
}

#[tokio::test]
async fn a_subject_kratos_does_not_know_is_denied() {
    let harness = Harness::with(
        |_| {
            (
                404,
                json!({"error": {"message": "Unable to locate the resource"}}),
            )
        },
        support::no_content,
        support::no_content,
    )
    .await;

    let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["reason"], "IdentityNotFound");
}

#[tokio::test]
async fn fails_closed_when_kratos_is_down() {
    let harness = Harness::with(
        |_| (500, json!({})),
        support::no_content,
        support::no_content,
    )
    .await;

    let (status, body) = harness.post("/hydra/token-hook", token_hook_body(ID)).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["reason"], "IdentityLookupFailed");
}

#[tokio::test]
async fn a_subject_that_is_not_an_identity_id_is_denied_without_asking_kratos() {
    let harness = Harness::new().await;

    for subject in [
        "not-a-uuid",
        "../admin/identities",
        "11111111-1111-4111-8111-111111111111/sessions",
    ] {
        let (status, body) = harness
            .post("/hydra/token-hook", token_hook_body(subject))
            .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "{subject:?}");
        assert_eq!(body["reason"], "InvalidSubject");
    }
    assert!(harness.log.calls().is_empty());
}

#[tokio::test]
async fn the_subject_may_come_from_the_claims_when_the_session_has_none() {
    let harness = Harness::new().await;
    let mut body = token_hook_body(ID);
    body["session"]["id_token"]["subject"] = json!("");

    let (status, _) = harness.post("/hydra/token-hook", body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        harness.log.of("kratos")[0].path(),
        format!("/admin/identities/{ID}")
    );
}

#[tokio::test]
async fn the_refresh_grant_gets_fresh_claims_too() {
    let harness = harness_with_claims(|_| (200, json!({"roles": ["admin"]}))).await;
    let mut body = token_hook_body(ID);
    body["request"]["grant_types"] = json!(["refresh_token"]);

    let (status, response) = harness.post("/hydra/token-hook", body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["session"]["access_token"]["roles"],
        json!(["admin"])
    );
}

#[tokio::test]
async fn a_request_without_a_client_id_is_rejected() {
    let harness = harness_with_claims(|_| (200, json!({}))).await;
    let mut body = token_hook_body(ID);
    body["request"].as_object_mut().unwrap().remove("client_id");

    let (status, _) = harness.post("/hydra/token-hook", body).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
