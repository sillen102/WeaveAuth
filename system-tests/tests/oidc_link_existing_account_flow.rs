//! An OIDC login for an email that already belongs to an existing but
//! unverified password account can't be trusted to just authenticate as
//! that account (see `OidcLinkOutcome::RequiresPasswordConfirmation` in
//! `backend/src/storage/in_memory.rs`) -- the account owner has to prove
//! they hold the password first, via bff's `/oidc/confirm-link`. This test
//! drives that whole hand-off across real `backend`+`bff` servers plus the
//! fake IdP: register a password account, attempt an OIDC login against the
//! same email, then confirm the link with the account's password.

#[allow(dead_code)]
mod support;

use std::sync::Arc;

use reqwest::cookie::CookieStore;
use reqwest::Url;
use support::config::{FINAL_REDIRECT, NEXT, NEXT_ORIGIN};
use support::http::{redirect_target, stop_at_real_hosts, urlencoding};
use support::{fake_idp, servers};

const EMAIL: &str = "bob@example.com";
const PASSWORD: &str = "bobs-strong-password";

fn backend_config(issuer: String, oidc_callback_url: String) -> weaveauth::config::Config {
    let mut providers = std::collections::HashMap::new();
    providers.insert(
        "google".to_string(),
        weaveauth::config::OidcProviderConfig {
            client_id: fake_idp::CLIENT_ID.to_string(),
            client_secret: fake_idp::CLIENT_SECRET.to_string().into(),
            issuer,
            redirect_uri: oidc_callback_url,
        },
    );
    weaveauth::config::Config {
        oidc_providers: providers,
        ..support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
    }
}

fn bff_config(backend_url: String, bff_url: String) -> weaveauth_bff::config::Config {
    support::config::bff_config(backend_url, bff_url, vec![NEXT_ORIGIN.to_string()])
}

#[tokio::test]
async fn oidc_login_into_unverified_account_requires_password_then_links() -> anyhow::Result<()> {
    // The provider itself confirms this email -- what makes the account
    // untrustworthy here is that it's an *existing, unverified* local
    // account, not anything about the provider's own claim.
    let idp = fake_idp::start(EMAIL, true).await?;

    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");
    let callback_url = format!("{bff_url}/oidc/google/callback");

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config(idp.issuer.clone(), callback_url)).await?;
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone()))?;

    // A password account with this exact email, unverified (registration
    // never verifies an email on its own -- see `backend/src/server/api/register.rs`).
    // Registered with its own throwaway client/jar -- registration
    // auto-logs in, and that unrelated session cookie would otherwise
    // contaminate the "no session yet" check below.
    let register_resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("{bff_url}/register"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("email", EMAIL), ("password", PASSWORD), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT_ORIGIN)])
        .send()
        .await?;
    assert_eq!(register_resp.status(), reqwest::StatusCode::SEE_OTHER, "setup: registration should succeed");

    let jar = Arc::new(reqwest::cookie::Jar::default());
    let client = reqwest::Client::builder().cookie_provider(jar.clone()).redirect(stop_at_real_hosts()).build()?;

    // The OIDC login: provider confirms the email, but backend refuses to
    // silently authenticate as the matching unverified account -- bff
    // bounces to `next` carrying the email and a pending-link cookie
    // instead of a session.
    let login_url = format!(
        "{bff_url}/oidc/google/login?redirect_uri={}&next={}",
        urlencoding(FINAL_REDIRECT),
        urlencoding(NEXT),
    );
    let oidc_resp = client.get(&login_url).send().await?;
    let target = redirect_target(&oidc_resp);
    assert_eq!(target, format!("{NEXT}?email={}", urlencoding(EMAIL)), "expected the password-confirmation hand-off");

    // The pending-link cookie is scoped to `/oidc` (see `FLOW_COOKIE_PATH` in
    // `bff/src/server/api/oidc.rs`), so it's only visible to the jar under
    // that path -- the root origin URL used for the session-cookie checks
    // below wouldn't see it.
    let bff_oidc_path: Url = format!("{bff_url}/oidc/").parse()?;
    let cookies_before_link =
        jar.cookies(&bff_oidc_path).map(|v| v.to_str().unwrap_or_default().to_string()).unwrap_or_default();
    assert!(
        cookies_before_link.contains("wa_oidc_pending_link_token="),
        "expected a pending-link cookie, got: {cookies_before_link}"
    );

    let bff_origin: Url = bff_url.parse()?;
    let cookies_before_link_root =
        jar.cookies(&bff_origin).map(|v| v.to_str().unwrap_or_default().to_string()).unwrap_or_default();
    assert!(!cookies_before_link_root.contains("wa_session="), "no session should exist before confirming the password");

    // Confirming with the account's real password finishes the login --
    // same landing spot and session cookie shape as a plain OIDC login.
    let confirm_resp = client
        .post(format!("{bff_url}/oidc/confirm-link"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("password", PASSWORD), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT)])
        .send()
        .await?;
    let confirm_target = redirect_target(&confirm_resp);
    assert_eq!(confirm_target, FINAL_REDIRECT, "correct password should complete the link and land on redirect_uri");

    let cookies_after_link =
        jar.cookies(&bff_origin).map(|v| v.to_str().unwrap_or_default().to_string()).unwrap_or_default();
    assert!(cookies_after_link.contains("wa_session="), "expected a real bff session cookie, got: {cookies_after_link}");

    Ok(())
}

/// The wrong password must not complete the link -- bff bounces back to
/// `next` with `?error=link_failed` and no session, per
/// `bff/src/server/api/oidc.rs`'s `link_failed_redirect`.
#[tokio::test]
async fn confirm_link_with_the_wrong_password_does_not_authenticate() -> anyhow::Result<()> {
    let idp = fake_idp::start(EMAIL, true).await?;

    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");
    let callback_url = format!("{bff_url}/oidc/google/callback");

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config(idp.issuer.clone(), callback_url)).await?;
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone()))?;

    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("{bff_url}/register"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("email", EMAIL), ("password", PASSWORD), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT_ORIGIN)])
        .send()
        .await?;

    let jar = Arc::new(reqwest::cookie::Jar::default());
    let client = reqwest::Client::builder().cookie_provider(jar.clone()).redirect(stop_at_real_hosts()).build()?;

    let login_url = format!(
        "{bff_url}/oidc/google/login?redirect_uri={}&next={}",
        urlencoding(FINAL_REDIRECT),
        urlencoding(NEXT),
    );
    client.get(&login_url).send().await?;

    let confirm_resp = client
        .post(format!("{bff_url}/oidc/confirm-link"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("password", "definitely-not-it"), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT)])
        .send()
        .await?;
    let confirm_target = redirect_target(&confirm_resp);
    assert_eq!(confirm_target, format!("{NEXT}?error=link_failed"));

    let bff_origin: Url = bff_url.parse()?;
    let cookies = jar.cookies(&bff_origin).map(|v| v.to_str().unwrap_or_default().to_string()).unwrap_or_default();
    assert!(!cookies.contains("wa_session="), "wrong password must not authenticate");

    Ok(())
}
