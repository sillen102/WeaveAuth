mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{Call, Harness, ID, identity_json, profile_api};

const PHONE_SCOPE: &str = "https://www.googleapis.com/auth/contacts.readonly";
const TOKEN: &str = "provider-access-token";

/// Kratos with an identity whose OIDC credential holds `TOKEN` for google.
fn kratos_with_token(call: &Call) -> (u16, Value) {
    match call.method.as_str() {
        "GET" => {
            let mut identity = identity_json(ID, "alice@example.com", false);
            identity["credentials"]["oidc"] = json!({"type": "oidc", "config": {"providers": [
                {"provider": "google", "subject": "1", "initial_access_token": TOKEN}
            ]}});
            (200, identity)
        }
        _ => (204, Value::Null),
    }
}

struct Setup {
    harness: Harness,
}

async fn setup(
    apis: impl FnOnce(&str) -> Vec<weaveauth_hooks::config::ProfileApiConfig>,
    provider: impl Fn(&Call) -> (u16, Value) + Send + Sync + 'static,
    registration: impl Fn(&Call) -> (u16, Value) + Send + Sync + 'static,
) -> Setup {
    let mut harness =
        Harness::with(kratos_with_token, support::no_content, support::no_content).await;
    let provider_stub = support::Stub::start("provider", &harness.log, provider).await;
    harness.config.profile_apis.insert(
        "google".to_string(),
        apis(&format!("{}/me", provider_stub.url)),
    );
    harness.config.registration_handler = Some(harness.webhook("registration", registration).await);
    Setup { harness }
}

fn phone(_: &Call) -> (u16, Value) {
    (
        200,
        json!({"phoneNumbers": [{"canonicalForm": "+46701234567"}]}),
    )
}

fn oidc_body() -> Value {
    json!({
        "identity_id": ID,
        "email": "alice@example.com",
        "traits": {"email": "alice@example.com", "name": "Alice"},
        "flow_id": "f",
        "provider": "google",
    })
}

fn ok(_: &Call) -> (u16, Value) {
    (200, json!({}))
}

fn phone_api(
    required: bool,
    scope: Option<&'static str>,
) -> impl FnOnce(&str) -> Vec<weaveauth_hooks::config::ProfileApiConfig> {
    move |url| {
        vec![profile_api(
            url.to_string(),
            &[("phone_number", "/phoneNumbers/0/canonicalForm")],
            required,
            scope,
        )]
    }
}

fn deleted(harness: &Harness) -> bool {
    harness
        .log
        .of("kratos")
        .iter()
        .any(|c| c.method == "DELETE" && c.path() == format!("/admin/identities/{ID}"))
}

fn registration_calls(harness: &Harness) -> Vec<Call> {
    harness.log.of("registration")
}

#[tokio::test]
async fn a_password_registration_forwards_the_traits_as_fields_and_the_verified_flag() {
    let mut harness = Harness::new().await;
    harness.config.registration_handler = Some(harness.webhook("registration", ok).await);
    let body = json!({"identity_id": ID, "email": "alice@example.com", "traits": {"email": "alice@example.com", "name": "Alice", "age": 33, "nested": {"x": 1}, "none": null}});

    let (status, _) = harness.post("/kratos/after-registration", body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        harness.log.of("kratos")[0].uri,
        format!("/admin/identities/{ID}"),
        "no provider tokens are asked for"
    );
    assert_eq!(
        registration_calls(&harness)[0].body,
        json!({"user_id": ID, "email": "alice@example.com", "email_verified": true, "fields": {"name": "Alice", "age": "33"}})
    );
}

#[tokio::test]
async fn an_oidc_registration_adds_what_the_profile_api_returns_using_the_stored_token() {
    let s = setup(phone_api(true, None), phone, ok).await;

    let (status, _) = s
        .harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::OK);
    let kratos = s.harness.log.of("kratos");
    assert_eq!(
        kratos[0].uri,
        format!("/admin/identities/{ID}?include_credential=oidc")
    );
    let provider = s.harness.log.of("provider");
    assert_eq!(
        provider[0].authorization.as_deref(),
        Some(&*format!("Bearer {TOKEN}"))
    );
    let registration = &registration_calls(&s.harness)[0].body;
    assert_eq!(
        registration["fields"],
        json!({"name": "Alice", "phone_number": "+46701234567"})
    );
    assert_eq!(
        registration["email_verified"], false,
        "the address the provider returned is not one Kratos verified"
    );
    assert!(!deleted(&s.harness));
}

#[tokio::test]
async fn a_required_api_that_fails_blocks_the_registration_and_deletes_the_identity() {
    for (what, provider) in [
        (
            "5xx",
            (|_: &Call| (500, json!({"error": "quota exceeded for key abc"})))
                as fn(&Call) -> (u16, Value),
        ),
        ("no value at the pointer", |_: &Call| {
            (200, json!({"other": 1}))
        }),
    ] {
        let s = setup(phone_api(true, None), provider, ok).await;

        let (status, body) = s
            .harness
            .post("/kratos/after-registration", oidc_body())
            .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{what}");
        assert_eq!(body["reason"], "ProfileApiFailed", "{what}");
        assert!(registration_calls(&s.harness).is_empty(), "{what}");
        assert!(deleted(&s.harness), "{what}");
        assert!(
            !body.to_string().contains("abc") && !body.to_string().contains("/me"),
            "{what}: {body}"
        );
    }
}

#[tokio::test]
async fn an_optional_api_that_fails_is_left_out_and_the_registration_goes_on() {
    for provider in [
        (|_: &Call| (500, json!({}))) as fn(&Call) -> (u16, Value),
        |_| (200, json!({"other": 1})),
    ] {
        let s = setup(phone_api(false, None), provider, ok).await;

        let (status, _) = s
            .harness
            .post("/kratos/after-registration", oidc_body())
            .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            registration_calls(&s.harness)[0].body["fields"],
            json!({"name": "Alice"})
        );
        assert!(!deleted(&s.harness));
    }
}

#[tokio::test]
async fn an_optional_api_keeps_the_fields_it_found_when_another_pointer_is_missing() {
    let s = setup(
        |url| {
            vec![profile_api(
                url.to_string(),
                &[
                    ("phone_number", "/phoneNumbers/0/canonicalForm"),
                    ("birthday", "/birthdays/0/date"),
                ],
                false,
                None,
            )]
        },
        phone,
        ok,
    )
    .await;

    let (status, _) = s
        .harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        registration_calls(&s.harness)[0].body["fields"],
        json!({"name": "Alice", "phone_number": "+46701234567"})
    );
}

#[tokio::test]
async fn a_required_api_with_a_missing_pointer_fails_even_when_it_found_other_fields() {
    let s = setup(
        |url| {
            vec![profile_api(
                url.to_string(),
                &[
                    ("phone_number", "/phoneNumbers/0/canonicalForm"),
                    ("birthday", "/birthdays/0/date"),
                ],
                true,
                None,
            )]
        },
        phone,
        ok,
    )
    .await;

    let (status, _) = s
        .harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(deleted(&s.harness));
}

#[tokio::test]
async fn a_declined_scope_fails_a_required_call_without_calling_it() {
    let s = setup(phone_api(true, Some(PHONE_SCOPE)), phone, ok).await;
    let mut body = oidc_body();
    body["granted_scopes"] = json!(["openid", "email"]);

    let (status, response) = s.harness.post("/kratos/after-registration", body).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response["reason"], "ConsentRequired");
    assert!(s.harness.log.of("provider").is_empty());
    assert!(registration_calls(&s.harness).is_empty());
    assert!(deleted(&s.harness));
}

#[tokio::test]
async fn a_declined_scope_skips_an_optional_call_without_calling_it() {
    let s = setup(phone_api(false, Some(PHONE_SCOPE)), phone, ok).await;
    let mut body = oidc_body();
    body["granted_scopes"] = json!(["openid", "email"]);

    let (status, _) = s.harness.post("/kratos/after-registration", body).await;

    assert_eq!(status, StatusCode::OK);
    assert!(s.harness.log.of("provider").is_empty());
    assert_eq!(
        registration_calls(&s.harness)[0].body["fields"],
        json!({"name": "Alice"})
    );
}

#[tokio::test]
async fn a_granted_scope_lets_the_call_through() {
    let s = setup(phone_api(true, Some(PHONE_SCOPE)), phone, ok).await;
    let mut body = oidc_body();
    body["granted_scopes"] = json!(["openid", PHONE_SCOPE]);

    let (status, _) = s.harness.post("/kratos/after-registration", body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(s.harness.log.of("provider").len(), 1);
}

#[tokio::test]
async fn a_request_that_reports_no_scopes_counts_as_granting_what_was_asked() {
    let s = setup(phone_api(true, Some(PHONE_SCOPE)), phone, ok).await;

    let (status, _) = s
        .harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(s.harness.log.of("provider").len(), 1);
}

#[tokio::test]
async fn without_a_stored_token_a_required_api_fails_and_an_optional_one_is_skipped() {
    for (required, expected) in [
        (true, StatusCode::UNPROCESSABLE_ENTITY),
        (false, StatusCode::OK),
    ] {
        let mut harness = Harness::with(
            |call| {
                if call.method == "GET" {
                    (200, identity_json(ID, "alice@example.com", false))
                } else {
                    (204, Value::Null)
                }
            },
            support::no_content,
            support::no_content,
        )
        .await;
        let stub = support::Stub::start("provider", &harness.log, phone).await;
        harness.config.profile_apis.insert(
            "google".into(),
            phone_api(required, None)(&format!("{}/me", stub.url)),
        );
        harness.config.registration_handler = Some(harness.webhook("registration", ok).await);

        let (status, _) = harness
            .post("/kratos/after-registration", oidc_body())
            .await;

        assert_eq!(status, expected, "required={required}");
        assert!(harness.log.of("provider").is_empty());
    }
}

#[tokio::test]
async fn a_provider_without_configured_apis_does_not_ask_kratos_for_its_tokens() {
    let mut harness = Harness::new().await;
    harness.config.registration_handler = Some(harness.webhook("registration", ok).await);
    let mut body = oidc_body();
    body["provider"] = json!("github");

    let (status, _) = harness.post("/kratos/after-registration", body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        harness.log.of("kratos")[0].uri,
        format!("/admin/identities/{ID}")
    );
}

#[tokio::test]
async fn a_registration_webhook_failing_with_a_401_is_a_failure_not_a_rejection() {
    let mut harness = Harness::new().await;
    harness.config.registration_handler =
        Some(harness.webhook("registration", |_| (401, json!({}))).await);

    let (status, body) = harness
        .post(
            "/kratos/after-registration",
            json!({"identity_id": ID, "email": "a@example.com", "traits": {}}),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_ne!(body["reason"], "RegistrationRejected");
}

#[tokio::test]
async fn a_rejection_by_the_registration_webhook_blocks_with_a_message_and_deletes_the_identity() {
    let s = setup(phone_api(false, None), phone, |_| {
        (422, json!({"reason": "blocked domain acme.test"}))
    })
    .await;

    let (status, body) = s
        .harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["reason"], "RegistrationRejected");
    // The shape Kratos needs to show a validation message instead of a generic failure.
    assert_eq!(body["messages"][0]["messages"][0]["type"], "error");
    assert!(body["messages"][0]["messages"][0]["text"].is_string());
    assert!(deleted(&s.harness));
    assert!(!body.to_string().contains("acme.test"));
}

#[tokio::test]
async fn a_broken_registration_webhook_blocks_and_deletes_the_identity() {
    let mut harness = Harness::new().await;
    harness.config.registration_handler = Some(
        harness
            .webhook("registration", |_| {
                (500, json!({"error": "db password hunter2"}))
            })
            .await,
    );

    let (status, body) = harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["reason"], "RegistrationHandlerFailed");
    assert!(deleted(&harness));
    assert!(!body.to_string().contains("hunter2"));
}

#[tokio::test]
async fn an_unreachable_registration_webhook_blocks_and_deletes_the_identity() {
    let mut harness = Harness::new().await;
    harness.config.registration_handler = Some(weaveauth_hooks::config::WebhookConfig {
        url: "http://127.0.0.1:1/hook".into(),
        timeout_secs: 1,
        bearer_token: None,
    });

    let (status, _) = harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(deleted(&harness));
}

#[tokio::test]
async fn a_failed_delete_does_not_replace_the_error_the_registration_is_blocked_with() {
    let mut harness = Harness::with(
        |call| match call.method.as_str() {
            "DELETE" => (500, json!({})),
            "GET" => (200, identity_json(ID, "a@example.com", true)),
            _ => (204, Value::Null),
        },
        support::no_content,
        support::no_content,
    )
    .await;
    harness.config.registration_handler =
        Some(harness.webhook("registration", |_| (422, json!({}))).await);

    let (status, body) = harness
        .post(
            "/kratos/after-registration",
            json!({"identity_id": ID, "email": "a@example.com", "traits": {}}),
        )
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["reason"], "RegistrationRejected");
}

#[tokio::test]
async fn without_a_registration_webhook_the_registration_passes() {
    let harness = Harness::new().await;

    let (status, _) = harness
        .post(
            "/kratos/after-registration",
            json!({"identity_id": ID, "email": "a@example.com", "traits": {}}),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(harness.log.calls().is_empty());
}

#[tokio::test]
async fn an_identity_id_that_is_not_a_uuid_is_an_invalid_request_and_calls_nothing() {
    let harness = Harness::new().await;

    let (status, _) = harness
        .post(
            "/kratos/after-registration",
            json!({"identity_id": "../x", "email": "a@example.com", "traits": {}}),
        )
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(harness.log.calls().is_empty());
}

#[tokio::test]
async fn a_kratos_outage_while_reading_the_token_blocks_the_registration() {
    let s = setup(phone_api(false, None), phone, ok).await;
    let mut harness = s.harness;
    harness.kratos = support::Stub::start("kratos2", &harness.log, |_| (500, json!({}))).await;
    harness.config.kratos_admin_url = harness.kratos.url.clone();

    let (status, body) = harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["reason"], "IdentityLookupFailed");
}

#[tokio::test]
async fn an_identity_kratos_no_longer_has_gets_a_4xx_kratos_does_not_retry_and_no_webhook_call() {
    let mut harness = Harness::with(
        |call| {
            if call.method == "GET" {
                (
                    404,
                    json!({"error": {"message": "Unable to locate the resource"}}),
                )
            } else {
                (204, Value::Null)
            }
        },
        support::no_content,
        support::no_content,
    )
    .await;
    harness.config.registration_handler = Some(harness.webhook("registration", ok).await);

    let (status, body) = harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::GONE);
    assert_eq!(body["reason"], "IdentityGone");
    assert!(registration_calls(&harness).is_empty());
}

#[tokio::test]
async fn a_registration_that_outlives_its_budget_still_deletes_the_identity() {
    let mut harness = Harness::new().await;
    harness.config.request_timeout_secs = 2;
    let mut hanging = harness.webhook("registration", ok).await;
    hanging.url = format!("{}/hook", support::hanging_server().await);
    hanging.timeout_secs = 30;
    harness.config.registration_handler = Some(hanging);

    let (status, body) = harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(body["reason"], "RegistrationTimedOut");
    assert!(deleted(&harness));
}

#[tokio::test]
async fn a_profile_api_answer_over_the_size_limit_counts_as_a_failed_call() {
    let s = setup(
        phone_api(true, None),
        |_| {
            (
                200,
                json!({"phoneNumbers": [{"canonicalForm": "x".repeat(2 * 1024 * 1024)}]}),
            )
        },
        ok,
    )
    .await;

    let (status, body) = s
        .harness
        .post("/kratos/after-registration", oidc_body())
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["reason"], "ProfileApiFailed");
}
