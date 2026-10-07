//! The base configuration: an address must be verified before anyone is signed in. Every test
//! uses its own users (and its own fake-IdP issuer), so they share one stack without meeting.
#![cfg(feature = "docker")]

use serde_json::json;
use std::time::Duration;
use weaveauth_system_tests::support::browser::{Body, Follow};
use weaveauth_system_tests::support::flows::*;
use weaveauth_system_tests::support::stack::{BFF_INTERNAL_API_KEY, REDIRECT_URI};
use weaveauth_system_tests::support::{Options, Stack, shared};

async fn stack() -> &'static Stack {
    shared(Options::default()).await
}

fn password_credentials() -> serde_json::Value {
    json!({"password": {"config": {"password": PASSWORD}}})
}

#[tokio::test]
async fn password_registration_verifies_first_then_proxied_jwt_carries_claims() {
    let stack = stack().await;
    let email = unique_email("reg");
    let b = stack.browser();

    let page = register_via_bff(stack, &b, &email, PASSWORD).await;
    assert!(!landed_on_app(&page), "signed in before verifying");
    assert!(!has_session(stack, &b));
    assert_eq!(page.url.path(), "/verification", "ended at {}", page.url);
    assert_eq!(whoami(stack, &b).await.status, 401);

    let done = verify_email(stack, &b, &page, &email).await;
    assert!(
        landed_on_app(&done),
        "ended at {} ({})",
        done.url,
        done.status
    );
    assert!(has_session(stack, &b));

    let id = stack.identity_id(&email).await;
    let token = upstream_token(stack, &b).await;
    let claims = verified_claims(stack, &token).await;
    assert_eq!(claims["sub"], id);
    assert_eq!(claims["email"], email);
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["roles"], json!(["member"]));
    assert_eq!(claims["aud"], json!(["weaveauth"]));

    let registrations = stack.stubs.registrations();
    let registered = registrations.iter().find(|r| r["email"] == email);
    assert_eq!(registered.map(|r| &r["user_id"]), Some(&json!(id)));
}

#[tokio::test]
async fn claims_follow_the_claims_webhook() {
    let stack = stack().await;
    let email = unique_email("admin");
    stack
        .create_identity(&email, true, password_credentials())
        .await;
    let b = session_for(stack, &email, PASSWORD).await;
    let claims = verified_claims(stack, &upstream_token(stack, &b).await).await;
    assert_eq!(claims["roles"], json!(["member", "admin"]));
}

#[tokio::test]
async fn a_claims_handler_that_sets_a_reserved_claim_gets_no_token_issued() {
    let stack = stack().await;
    let email = unique_email("evil");
    stack
        .create_identity(&email, true, password_credentials())
        .await;
    let b = stack.browser();

    let resp = login_via_bff(stack, &b, &email, PASSWORD).await;
    assert!(
        !landed_on_app(&resp),
        "a token was issued with a spoofed claim"
    );
    assert!(!has_session(stack, &b));
    assert_eq!(whoami(stack, &b).await.status, 401);
}

#[tokio::test]
async fn unverified_password_login_starts_verification_instead_of_a_session() {
    let stack = stack().await;
    let email = unique_email("unv");
    stack
        .create_identity(&email, false, password_credentials())
        .await;
    let b = stack.browser();

    let resp = login_via_bff(stack, &b, &email, PASSWORD).await;
    assert!(
        !landed_on_app(&resp),
        "signed in with an unverified address"
    );
    assert_eq!(resp.url.path(), "/verification", "ended at {}", resp.url);
    assert!(!has_session(stack, &b));
    assert_eq!(whoami(stack, &b).await.status, 401);
    // Not the verification mail only: the code is mailed.
    mail_code(stack, &email, "verification code", 1).await;
}

#[tokio::test]
async fn google_sign_in_registers_a_verified_provider_email() {
    let stack = stack().await;
    let b = stack.browser();
    let page = bff_login(stack, &b).await;
    let lf = flow_of(stack, &b, "login", &page).await;
    // Kratos puts the provider's `label` (not its id) in the button text; login shows it as is.
    let button = lf["ui"]["nodes"]
        .as_array()
        .and_then(|nodes| nodes.iter().find(|n| n["attributes"]["value"] == "fake"))
        .expect("the fake provider's button");
    assert_eq!(button["meta"]["label"]["text"], "Sign in with Fake fake");
    let resp = provider(&b, &lf, "fake", Follow::Until(REDIRECT_URI)).await;
    assert!(
        landed_on_app(&resp),
        "ended at {} ({})",
        resp.url,
        resp.status
    );
    assert!(has_session(stack, &b));

    let email = "idp-user@example.test";
    let id = stack.identity_id(email).await;
    let claims = verified_claims(stack, &upstream_token(stack, &b).await).await;
    assert_eq!(claims["sub"], id);
    assert_eq!(claims["email"], email);
    assert_eq!(claims["email_verified"], true);
    let registered = stack.stubs.registrations();
    assert!(
        registered.iter().any(|r| r["user_id"] == json!(id)),
        "{registered:?}"
    );

    // A second sign-in finds the same identity.
    let again = stack.browser();
    let page = bff_login(stack, &again).await;
    let lf = flow_of(stack, &again, "login", &page).await;
    let resp = provider(&again, &lf, "fake", Follow::Until(REDIRECT_URI)).await;
    assert!(
        landed_on_app(&resp),
        "ended at {} ({})",
        resp.url,
        resp.status
    );
    let claims = verified_claims(stack, &upstream_token(stack, &again).await).await;
    assert_eq!(claims["sub"], id);
}

#[tokio::test]
async fn google_sign_in_without_a_phone_number_never_shows_the_registration_form() {
    let stack = stack().await;
    let b = stack.browser();
    let page = bff_login(stack, &b).await;
    let lf = flow_of(stack, &b, "login", &page).await;
    let resp = provider(&b, &lf, "fakenophone", Follow::Until(REDIRECT_URI)).await;
    assert!(
        landed_on_app(&resp),
        "ended at {} ({})",
        resp.url,
        resp.status
    );
    assert!(has_session(stack, &b));
    let id = stack.identity_id("idp-nophone@example.test").await;
    assert!(
        stack.identity("idp-nophone@example.test").await["traits"]
            .get("phone_number")
            .is_none()
    );
    assert!(
        stack
            .stubs
            .registrations()
            .iter()
            .any(|r| r["user_id"] == json!(id)),
        "registration handler not called"
    );
}

#[tokio::test]
async fn google_sign_up_missing_a_trait_can_be_completed_on_the_form() {
    let stack = stack().await;
    let b = stack.browser();
    let page = bff_login(stack, &b).await;
    let lf = flow_of(stack, &b, "login", &page).await;
    let resp = provider(&b, &lf, "fakenolast", Follow::Until(REDIRECT_URI)).await;
    assert_eq!(resp.url.path(), "/registration", "ended at {}", resp.url);

    // The traits and the button must be one form, as the browser posts it.
    let form = resp
        .body
        .split("<form")
        .find(|form| form.contains("name=\"provider\""))
        .expect("the continue button");
    assert!(form.contains("name=\"traits.last_name\""), "{}", resp.body);

    assert!(!resp.body.contains("traits.email"), "{}", resp.body);

    let rf = flow_of(stack, &b, "registration", &resp).await;
    let mut values = form_values(&rf, "oidc");
    values.retain(|(name, _)| name != "traits.last_name" && name != "traits.email");
    values.push(("traits.last_name".into(), "Ciccone".into()));
    values.push(("provider".into(), "fakenolast".into()));
    let action = rf["ui"]["action"].as_str().expect("flow action");
    let done = b
        .post_form(action, &values, &[], Follow::Until(REDIRECT_URI))
        .await;
    assert!(
        landed_on_app(&done),
        "ended at {} ({})",
        done.url,
        done.status
    );
    let identity = stack.identity("idp-nolast@example.test").await;
    assert_eq!(identity["traits"]["last_name"], "Ciccone");
    assert_eq!(identity["verifiable_addresses"][0]["verified"], true);
}

#[tokio::test]
async fn google_sign_up_form_cannot_swap_the_providers_email_for_a_verified_one() {
    let stack = stack().await;
    let b = stack.browser();
    let page = bff_login(stack, &b).await;
    let lf = flow_of(stack, &b, "login", &page).await;
    let resp = provider(&b, &lf, "faketamper", Follow::Until(REDIRECT_URI)).await;
    assert!(
        !resp.body.contains("traits.email"),
        "the form offers the provider's email as an input"
    );

    // A hand-made post can still name another address; it must not come out verified or signed in.
    let rf = flow_of(stack, &b, "registration", &resp).await;
    let mut values = form_values(&rf, "oidc");
    values.retain(|(name, _)| name != "traits.last_name" && name != "traits.email");
    values.push(("traits.last_name".into(), "Ciccone".into()));
    values.push(("traits.email".into(), "not-mine@example.test".into()));
    values.push(("provider".into(), "faketamper".into()));
    let action = rf["ui"]["action"].as_str().expect("flow action");
    let done = b
        .post_form(action, &values, &[], Follow::Until(REDIRECT_URI))
        .await;
    assert!(
        !landed_on_app(&done),
        "signed in on an address nobody proved"
    );
    assert!(!has_session(stack, &b));
    let identity = stack.identity("not-mine@example.test").await;
    assert_eq!(identity["verifiable_addresses"][0]["verified"], false);
}

#[tokio::test]
async fn google_sign_in_with_an_unverified_provider_email_must_verify() {
    let stack = stack().await;
    let b = stack.browser();
    let page = bff_login(stack, &b).await;
    let lf = flow_of(stack, &b, "login", &page).await;
    let resp = provider(&b, &lf, "fakeu", Follow::Until(REDIRECT_URI)).await;
    assert!(
        !landed_on_app(&resp),
        "signed in on an unverified provider email"
    );
    assert!(!has_session(stack, &b));
    assert_eq!(resp.url.path(), "/verification", "ended at {}", resp.url);

    let email = "idp-unverified@example.test";
    let identity = stack.identity(email).await;
    assert_eq!(identity["verifiable_addresses"][0]["verified"], false);

    let done = verify_email(stack, &b, &resp, email).await;
    assert!(
        landed_on_app(&done),
        "ended at {} ({})",
        done.url,
        done.status
    );
    let claims = verified_claims(stack, &upstream_token(stack, &b).await).await;
    assert_eq!(claims["email_verified"], true);
}

#[tokio::test]
async fn google_sign_in_to_an_existing_email_must_confirm_with_the_password() {
    let stack = stack().await;
    let email = "pw-user@example.test";
    let id = stack
        .create_identity(email, true, password_credentials())
        .await;
    let b = stack.browser();
    let page = bff_login(stack, &b).await;
    let lf = flow_of(stack, &b, "login", &page).await;

    let resp = provider(&b, &lf, "fakelink", Follow::Until(REDIRECT_URI)).await;
    assert!(
        !landed_on_app(&resp),
        "linked without confirming the password"
    );
    assert!(!has_session(stack, &b));
    let confirm = flow_of(stack, &b, "login", &resp).await;
    assert!(
        !first_message(&confirm).is_empty(),
        "the flow should say why"
    );
    let linked = stack.identity(email).await;
    assert!(
        linked["credentials"].get("oidc").is_none(),
        "linked early: {linked}"
    );

    let done = submit(
        &b,
        &confirm,
        "password",
        &[("identifier", email), ("password", PASSWORD)],
        Follow::Until(REDIRECT_URI),
    )
    .await;
    assert!(
        landed_on_app(&done),
        "ended at {} ({})",
        done.url,
        done.status
    );
    let linked = stack.identity(email).await;
    assert!(linked["credentials"].get("oidc").is_some(), "{linked}");
    assert!(linked["credentials"].get("password").is_some(), "{linked}");
    let claims = verified_claims(stack, &upstream_token(stack, &b).await).await;
    assert_eq!(claims["sub"], id);
}

#[tokio::test]
async fn recovery_ends_every_old_session_and_purges_credentials_and_oidc_links() {
    let stack = stack().await;
    let email = "recover-user@example.test".to_string();
    let credentials = json!({
        "password": {"config": {"password": PASSWORD}},
        "oidc": {"config": {"providers": [{"subject": "recover-sub", "provider": "fakerecover"}]}},
    });
    let id = stack.create_identity(&email, true, credentials).await;
    // The admin API cannot create these, so they go in the way Kratos would have written them.
    let passkey = json!({"credentials": [{
        "id": "AAECAwQFBgcICQoLDA0ODw==", "public_key": "AAEC", "attestation_type": "none",
        "is_passwordless": true, "display_name": "key", "added_at": "2026-01-01T00:00:00Z",
        "authenticator": {"aaguid": "AAAAAAAAAAAAAAAAAAAAAA==", "sign_count": 0, "clone_warning": false}
    }], "user_handle": "AAEC"});
    stack.add_credential(&id, "passkey", &passkey).await;
    // The provider link works before recovery, so a refusal afterwards is the unlink's doing.
    let before = stack.browser();
    let page = bff_login(stack, &before).await;
    let lf = flow_of(stack, &before, "login", &page).await;
    let signed = provider(&before, &lf, "fakerecover", Follow::Until(REDIRECT_URI)).await;
    assert!(
        landed_on_app(&signed),
        "the social login works before recovery"
    );
    // Three ways of being signed in: a bff session, a Kratos session of its own, a refresh token.
    let old_bff = session_for(stack, &email, PASSWORD).await;
    assert_eq!(whoami(stack, &old_bff).await.status, 200);
    assert!(kratos_session_active(stack, &old_bff).await);
    let tokens = direct_tokens(stack, &stack.browser(), Some((&email, PASSWORD))).await;
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();
    let (_, listed) = stack
        .kratos("GET", &format!("/admin/identities/{id}/sessions"), None)
        .await;
    let old_sessions: Vec<serde_json::Value> = listed
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| s["id"].clone())
        .collect();
    assert!(
        old_sessions.len() >= 2,
        "expected the two sign-ins: {listed}"
    );
    // Second factors would have asked for a code at sign-in, so they are added afterwards.
    stack
        .add_credential(
            &id,
            "totp",
            &json!({"totp_url": "otpauth://totp/x:y?secret=JBSWY3DPEHPK3PXP"}),
        )
        .await;
    stack
        .add_credential(&id, "lookup_secret", &json!({"recovery_codes": []}))
        .await;
    let before = stack.identity(&email).await;
    for kind in ["password", "oidc", "passkey", "totp", "lookup_secret"] {
        assert!(
            before["credentials"].get(kind).is_some(),
            "setup lacks {kind}: {before}"
        );
    }

    // Recover with the mailed code.
    let b = stack.browser();
    let rf = new_flow(stack, &b, "recovery", None).await;
    submit(&b, &rf, "code", &[("email", &email)], Follow::No).await;
    let rf = flow(stack, &b, "recovery", rf["id"].as_str().expect("flow id")).await;
    let code = mail_code(stack, &email, "Reset your password", 1).await;
    let resp = submit(&b, &rf, "code", &[("code", &code)], Follow::No).await;
    assert_eq!(
        resp.status, 303,
        "recovery answered {}: {}",
        resp.status, resp.body
    );
    let target = resp.redirect_target().expect("recovery redirect");
    assert_eq!(
        target.path(),
        "/settings",
        "the code was not accepted: {target}"
    );

    assert_eq!(
        whoami(stack, &old_bff).await.status,
        401,
        "old bff session survived"
    );
    assert!(
        !kratos_session_active(stack, &old_bff).await,
        "old Kratos session survived"
    );
    let (status, error) = refresh(stack, &refresh_token).await;
    assert_ne!(status, 200, "old refresh token still works");
    assert_eq!(error["error"], "invalid_grant");

    let identity = stack.identity(&email).await;
    for kind in ["passkey", "totp", "lookup_secret", "webauthn"] {
        assert!(
            identity["credentials"].get(kind).is_none(),
            "{kind} survived: {identity}"
        );
    }
    let links = identity["credentials"]["oidc"]["identifiers"]
        .as_array()
        .map_or(0, Vec::len);
    assert_eq!(links, 0, "a social login link survived: {identity}");
    let old_password = login_via_bff(stack, &stack.browser(), &email, PASSWORD).await;
    assert!(
        !landed_on_app(&old_password),
        "the old password still signs in"
    );
    let (_, sessions) = stack
        .kratos("GET", &format!("/admin/identities/{id}/sessions"), None)
        .await;
    let remaining: Vec<&serde_json::Value> = sessions
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| &s["id"])
        .filter(|id| old_sessions.contains(id))
        .collect();
    assert!(
        remaining.is_empty(),
        "old Kratos sessions remain: {remaining:?}"
    );
    // The unlinked provider account, same verified email, must not sign in to the identity.
    let idp = stack.browser();
    let page = bff_login(stack, &idp).await;
    let lf = flow_of(stack, &idp, "login", &page).await;
    let signed = provider(&idp, &lf, "fakerecover", Follow::Until(REDIRECT_URI)).await;
    assert!(
        !landed_on_app(&signed),
        "the old social login still reaches the account"
    );
    assert!(!has_session(stack, &idp));

    let settings = b
        .get_json(resp.location().expect("settings redirect"))
        .await;
    assert_eq!(
        settings.status, 200,
        "the recovery session itself must survive"
    );
    let settings_flow_id = target
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .expect("settings flow id")
        .1
        .to_string();
    // login replaces this message's text (`RECOVERY_SUCCESSFUL_ID`).
    let first = flow(stack, &b, "settings", &settings_flow_id).await;
    assert!(
        first["ui"]["messages"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|m| m["id"] == 1060001),
        "{first}"
    );
    // login's `recovering()` keys the password-only settings page on this, not on the message.
    submit(&b, &first, "password", &[("password", "x")], Follow::No).await;
    let sf = flow(stack, &b, "settings", &settings_flow_id).await;
    let request_url = url::Url::parse(sf["request_url"].as_str().expect("request_url"))
        .expect("request_url is a URL");
    assert_eq!(request_url.path(), "/self-service/recovery", "{sf}");

    // Saving the new password leads to the app's sign-in, where the new password works.
    let new_password = "a-new-Password-after-recovery-9";
    let saved = submit(
        &b,
        &sf,
        "password",
        &[("password", new_password)],
        Follow::Until(REDIRECT_URI),
    )
    .await;
    assert_eq!(saved.url.path(), "/login", "{} {}", saved.url, saved.body);
    let lf = flow_of(stack, &b, "login", &saved).await;
    let signed = submit(
        &b,
        &lf,
        "password",
        &[("identifier", &email), ("password", new_password)],
        Follow::Until(REDIRECT_URI),
    )
    .await;
    assert!(landed_on_app(&signed), "{} {}", signed.status, signed.body);
}

#[tokio::test]
async fn logout_through_bff_ends_the_bff_kratos_and_hydra_sessions() {
    let stack = stack().await;
    let email = unique_email("logout");
    stack
        .create_identity(&email, true, password_credentials())
        .await;
    let b = session_for(stack, &email, PASSWORD).await;
    assert_eq!(whoami(stack, &b).await.status, 200);

    let resp = b
        .send(
            "POST",
            &format!("{}/logout", stack.bff_url),
            Body::None,
            &[("origin", stack.bff_url.as_str())],
            Follow::Until(REDIRECT_URI),
        )
        .await;
    assert!(
        landed_on_app(&resp),
        "logout ended at {} ({})",
        resp.url,
        resp.status
    );
    assert_eq!(whoami(stack, &b).await.status, 401);
    assert!(
        !kratos_session_active(stack, &b).await,
        "Kratos session survived the logout"
    );
    let page = bff_login(stack, &b).await;
    assert!(!landed_on_app(&page), "Hydra still remembers the login");
}

#[tokio::test]
async fn a_logout_link_the_app_did_not_start_signs_nobody_out() {
    let stack = stack().await;
    let email = unique_email("bare-logout");
    stack
        .create_identity(&email, true, password_credentials())
        .await;
    let b = session_for(stack, &email, PASSWORD).await;

    // Hydra's logout endpoint with no id_token_hint, as any page could send the browser to.
    let url = format!("{}/oauth2/sessions/logout", stack.login_url);
    let resp = b.get(&url, Follow::All).await;
    assert_eq!(
        resp.status, 400,
        "login accepted a bare logout: {}",
        resp.url
    );
    assert_eq!(whoami(stack, &b).await.status, 200);
    assert!(kratos_session_active(stack, &b).await);
}

#[tokio::test]
async fn hydra_back_channel_logout_ends_the_bff_session() {
    let stack = stack().await;
    let email = unique_email("backchannel");
    stack
        .create_identity(&email, true, password_credentials())
        .await;
    let bystander = session_for(stack, &unique_email_user(stack).await, PASSWORD).await;
    let b = session_for(stack, &email, PASSWORD).await;
    assert_eq!(whoami(stack, &b).await.status, 200);

    // The same browser signs in to Hydra a second time, which shares the login session; ending
    // that one through Hydra directly never touches bff's own logout.
    let tokens = direct_tokens(stack, &b, None).await;
    let hint = tokens["id_token"].as_str().expect("id_token");
    let url = format!(
        "{}/oauth2/sessions/logout?id_token_hint={hint}&post_logout_redirect_uri={}/logged-out&state={}",
        stack.login_url, stack.bff_url, REDIRECT_URI,
    );
    let resp = b.get(&url, Follow::Until(REDIRECT_URI)).await;
    assert!(
        landed_on_app(&resp),
        "logout ended at {} ({})",
        resp.url,
        resp.status
    );

    let mut status = 200;
    for _ in 0..20 {
        status = whoami(stack, &b).await.status;
        if status == 401 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(status, 401, "the bff session outlived Hydra's logout");
    assert_eq!(
        whoami(stack, &bystander).await.status,
        200,
        "another user's session ended"
    );
}

#[tokio::test]
async fn internal_revoke_needs_the_api_key_and_ends_only_that_users_sessions() {
    let stack = stack().await;
    let (victim, other) = (unique_email("revoke"), unique_email("revoke-other"));
    let sub = stack
        .create_identity(&victim, true, password_credentials())
        .await;
    stack
        .create_identity(&other, true, password_credentials())
        .await;
    let victim_session = session_for(stack, &victim, PASSWORD).await;
    let other_session = session_for(stack, &other, PASSWORD).await;

    let revoke = |key: Option<&'static str>| {
        let mut request = stack
            .http
            .post(format!("{}/internal/revoke", stack.bff_internal_url))
            .json(&json!({"sub": sub}));
        if let Some(key) = key {
            request = request.bearer_auth(key);
        }
        async move { request.send().await.expect("revoke").status().as_u16() }
    };
    assert_eq!(revoke(None).await, 401);
    assert_eq!(revoke(Some("not-the-key")).await, 401);
    assert_eq!(
        whoami(stack, &victim_session).await.status,
        200,
        "revoked without the key"
    );

    assert_eq!(revoke(Some(BFF_INTERNAL_API_KEY)).await, 204);
    assert_eq!(whoami(stack, &victim_session).await.status, 401);
    assert_eq!(
        whoami(stack, &other_session).await.status,
        200,
        "another user's session ended"
    );
}

/// A signed-up user for tests that need a bystander; returns its email.
async fn unique_email_user(stack: &Stack) -> String {
    let email = unique_email("bystander");
    stack
        .create_identity(&email, true, password_credentials())
        .await;
    email
}
