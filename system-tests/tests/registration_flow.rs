//! Drives a plain password registration through real `bff` and `backend`
//! servers: bff forwards to backend's `/register`, then auto-logs the new
//! user in via the same server-to-server PKCE exchange OIDC login uses --
//! this is the seam that flow shares with `oidc_full_flow.rs`, exercised
//! here from its own entry point (`/register`) instead.

#[allow(dead_code)]
mod support;

use support::config::{FINAL_REDIRECT, NEXT_ORIGIN};
use support::servers;

fn backend_config() -> weaveauth::config::Config {
    support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
}

fn bff_config(backend_url: String, bff_url: String) -> weaveauth_bff::config::Config {
    support::config::bff_config(backend_url, bff_url, vec![NEXT_ORIGIN.to_string()])
}

/// Registering with fresh credentials creates the account on backend and
/// immediately logs it in -- landing on `redirect_uri` with a real bff
/// session cookie in one response, no further redirect chase needed (unlike
/// the OIDC flow, `start_register` never bounces the browser off-service).
#[tokio::test]
async fn registration_creates_the_account_and_logs_it_in() -> anyhow::Result<()> {
    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config()).await?;
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone()))?;

    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;

    let resp = client
        .post(format!("{bff_url}/register"))
        .header("origin", NEXT_ORIGIN)
        .form(&[
            ("email", "new-user@example.com"),
            ("password", "correct-horse-battery-staple"),
            ("redirect_uri", FINAL_REDIRECT),
            ("next", NEXT_ORIGIN),
        ])
        .send()
        .await?;

    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let location = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok());
    assert_eq!(location, Some(FINAL_REDIRECT), "should land on redirect_uri, auto-logged-in");

    let cookies: Vec<String> =
        resp.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).map(str::to_string).collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("wa_session=") && c.contains("HttpOnly")),
        "expected a real bff session cookie, got: {cookies:?}"
    );

    Ok(())
}

/// Registering the same email twice must fail the second time -- backend's
/// own uniqueness check, surfaced through bff as a bounce to `next` with
/// `?error=1` rather than a second session.
#[tokio::test]
async fn registering_a_taken_email_bounces_to_next_with_an_error() -> anyhow::Result<()> {
    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config()).await?;
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone()))?;

    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;

    let register = |password: &'static str| {
        let client = client.clone();
        let bff_url = bff_url.clone();
        async move {
            client
                .post(format!("{bff_url}/register"))
                .header("origin", NEXT_ORIGIN)
                .form(&[
                    ("email", "squatter@example.com"),
                    ("password", password),
                    ("redirect_uri", FINAL_REDIRECT),
                    ("next", NEXT_ORIGIN),
                ])
                .send()
                .await
        }
    };

    let first = register("first-password").await?;
    assert_eq!(first.status(), reqwest::StatusCode::SEE_OTHER);

    let second = register("second-password").await?;
    assert_eq!(second.status(), reqwest::StatusCode::SEE_OTHER);
    let location = second.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok());
    assert_eq!(location, Some(format!("{NEXT_ORIGIN}?error=1").as_str()));
    assert!(second.headers().get("set-cookie").is_none(), "a rejected registration must not set a session");

    Ok(())
}
