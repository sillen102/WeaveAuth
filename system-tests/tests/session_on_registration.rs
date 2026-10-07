//! The `session-on-registration.yml` overlay: registering signs the user in at once and
//! unverified addresses may sign in, so the verified-first gates are off.
#![cfg(feature = "docker")]

use serde_json::json;
use weaveauth_system_tests::support::flows::*;
use weaveauth_system_tests::support::{Options, Stack, shared};

async fn stack() -> &'static Stack {
    shared(Options {
        session_on_registration: true,
    })
    .await
}

#[tokio::test]
async fn password_registration_signs_in_at_once_with_an_unverified_address() {
    let stack = stack().await;
    let email = unique_email("overlay");
    let b = stack.browser();

    let resp = register_via_bff(stack, &b, &email, PASSWORD).await;
    assert!(
        landed_on_app(&resp),
        "ended at {} ({})",
        resp.url,
        resp.status
    );
    assert!(has_session(stack, &b));

    let claims = verified_claims(stack, &upstream_token(stack, &b).await).await;
    assert_eq!(claims["sub"], stack.identity_id(&email).await);
    assert_eq!(claims["email"], email);
    assert_eq!(claims["email_verified"], false);
    assert_eq!(claims["roles"], json!(["member"]));
    // The verification mail still goes out.
    mail_code(stack, &email, "verification code", 1).await;
}

#[tokio::test]
async fn unverified_password_login_is_allowed() {
    let stack = stack().await;
    let email = unique_email("overlay-login");
    stack
        .create_identity(
            &email,
            false,
            json!({"password": {"config": {"password": PASSWORD}}}),
        )
        .await;
    let b = session_for(stack, &email, PASSWORD).await;
    let claims = verified_claims(stack, &upstream_token(stack, &b).await).await;
    assert_eq!(claims["email_verified"], false);
}
