//! A plain password login through real `bff` and `backend` servers:
//! register an account first (its own throwaway request), then drive
//! `POST /login` -- the third entry point (alongside `/register` and the
//! OIDC callback) that converges on the same server-to-server PKCE exchange
//! in `bff/src/server/api/complete_login.rs`.

#[allow(dead_code)]
mod support;

use support::config::{FINAL_REDIRECT, NEXT_ORIGIN};
use support::servers;

const EMAIL: &str = "carol@example.com";
const PASSWORD: &str = "carols-strong-password";

fn backend_config() -> weaveauth::config::Config {
    support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
}

fn bff_config(backend_url: String, bff_url: String) -> weaveauth_bff::config::Config {
    support::config::bff_config(backend_url, bff_url, vec![NEXT_ORIGIN.to_string()])
}

async fn register(client: &reqwest::Client, bff_url: &str) -> anyhow::Result<()> {
    let resp = client
        .post(format!("{bff_url}/register"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("email", EMAIL), ("password", PASSWORD), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT_ORIGIN)])
        .send()
        .await?;
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER, "setup: registration should succeed");
    Ok(())
}

/// Correct credentials against an already-registered account land on
/// `redirect_uri` with a real bff session cookie -- same one-response shape
/// as registration's own auto-login, driven here through `/login` instead.
#[tokio::test]
async fn password_login_authenticates_an_existing_account() -> anyhow::Result<()> {
    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config()).await?;
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone()))?;

    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
    register(&client, &bff_url).await?;

    let resp = client
        .post(format!("{bff_url}/login"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("email", EMAIL), ("password", PASSWORD), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT_ORIGIN)])
        .send()
        .await?;

    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let location = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok());
    assert_eq!(location, Some(FINAL_REDIRECT), "should land on redirect_uri");

    let cookies: Vec<String> =
        resp.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).map(str::to_string).collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("wa_session=") && c.contains("HttpOnly")),
        "expected a real bff session cookie, got: {cookies:?}"
    );

    Ok(())
}

/// A wrong password must not authenticate -- bounces to `next` with
/// `?error=1` and no session, same shape as every other credential-rejection
/// path in this suite.
#[tokio::test]
async fn password_login_with_the_wrong_password_does_not_authenticate() -> anyhow::Result<()> {
    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config()).await?;
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone()))?;

    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
    register(&client, &bff_url).await?;

    let resp = client
        .post(format!("{bff_url}/login"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("email", EMAIL), ("password", "definitely-not-it"), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT_ORIGIN)])
        .send()
        .await?;

    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let location = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok());
    assert_eq!(location, Some(format!("{NEXT_ORIGIN}?error=1").as_str()));
    assert!(resp.headers().get("set-cookie").is_none(), "wrong password must not authenticate");

    Ok(())
}

/// An email with no account at all is rejected the same way a wrong
/// password is -- no timing/response-shape difference an attacker could use
/// to enumerate registered emails.
#[tokio::test]
async fn password_login_for_an_unknown_email_does_not_authenticate() -> anyhow::Result<()> {
    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config()).await?;
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone()))?;

    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;

    let resp = client
        .post(format!("{bff_url}/login"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("email", "nobody@example.com"), ("password", PASSWORD), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT_ORIGIN)])
        .send()
        .await?;

    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let location = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok());
    assert_eq!(location, Some(format!("{NEXT_ORIGIN}?error=1").as_str()));
    assert!(resp.headers().get("set-cookie").is_none());

    Ok(())
}
