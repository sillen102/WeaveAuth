//! Drives a third-party OIDC login across all three real hops -- browser to
//! bff, bff to backend, backend to the provider -- with `backend` and `bff`
//! each running as a real server on a real port, and the provider stood in
//! by `support::fake_idp`. `login` is deliberately not part of this: it's a
//! thin static form-poster with no OIDC logic of its own, and testing bff's
//! real endpoints directly covers what `login` would trigger without the
//! cost of a headless browser.
//!
//! This is the seam nothing else in the workspace's test suite covers:
//! `backend`'s own tests mock the provider but never involve `bff`, and
//! `bff`'s own tests mock `backend` but never involve the provider or the
//! real OIDC code exchange.

#[allow(dead_code)]
mod support;

use std::collections::HashMap;
use std::sync::Arc;

use reqwest::cookie::CookieStore;
use reqwest::Url;
use support::config::{FINAL_REDIRECT, NEXT, NEXT_ORIGIN};
use support::http::{redirect_target, stop_at_real_hosts, urlencoding};
use support::{fake_idp, servers};

fn backend_config_with_provider(issuer: String, oidc_callback_url: String) -> weaveauth::config::Config {
    let mut providers = HashMap::new();
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

/// The happy path: provider confirms a fresh, verified email, and the
/// browser lands on `redirect_uri` with a real bff session cookie -- proving
/// the full round trip (bff -> backend -> provider -> backend -> bff) works
/// against real HTTP servers on both ends, not stubs.
#[tokio::test]
async fn oidc_login_authenticates_through_every_real_hop() -> anyhow::Result<()> {
    let idp = fake_idp::start("alice@example.com", true).await?;

    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");
    let callback_url = format!("{bff_url}/oidc/google/callback");

    let (backend_url, _backend_handle) =
        servers::spawn_backend(&backend_config_with_provider(idp.issuer.clone(), callback_url)).await?;
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone()))?;

    let jar = Arc::new(reqwest::cookie::Jar::default());
    let client = reqwest::Client::builder().cookie_provider(jar.clone()).redirect(stop_at_real_hosts()).build()?;

    let login_url = format!(
        "{bff_url}/oidc/google/login?redirect_uri={}&next={}",
        urlencoding(FINAL_REDIRECT),
        urlencoding(NEXT),
    );
    let resp = client.get(&login_url).send().await?;
    let status = resp.status();
    let target = redirect_target(&resp);
    assert!(status.is_redirection(), "expected the chain to stop on a redirect to {FINAL_REDIRECT}, got {status}");
    assert_eq!(target, FINAL_REDIRECT, "should land on the caller's redirect_uri");

    let bff_origin: Url = bff_url.parse()?;
    let cookies = jar.cookies(&bff_origin).map(|v| v.to_str().unwrap_or_default().to_string()).unwrap_or_default();
    assert!(cookies.contains("wa_session="), "expected a real bff session cookie, got: {cookies}");

    Ok(())
}

/// The provider reports an unverified email -- backend refuses to link
/// accounts by an email it can't attest to (see `EmailNotVerified` in
/// `backend/src/server/api/oidc.rs`), so no session is ever established and
/// bff bounces back to `next` with `?error=1` instead of a cookie. Exercises
/// real branching in the cross-service contract, not just the happy path.
#[tokio::test]
async fn oidc_login_with_unverified_email_does_not_authenticate() -> anyhow::Result<()> {
    let idp = fake_idp::start("squatter@example.com", false).await?;

    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");
    let callback_url = format!("{bff_url}/oidc/google/callback");

    let (backend_url, _backend_handle) =
        servers::spawn_backend(&backend_config_with_provider(idp.issuer.clone(), callback_url)).await?;
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone()))?;

    let client = reqwest::Client::builder().cookie_store(true).redirect(stop_at_real_hosts()).build()?;

    let login_url = format!(
        "{bff_url}/oidc/google/login?redirect_uri={}&next={}",
        urlencoding(FINAL_REDIRECT),
        urlencoding(NEXT),
    );
    let resp = client.get(&login_url).send().await?;
    let target = redirect_target(&resp);

    assert_eq!(target, format!("{NEXT}?error=1"), "unverified email must not authenticate");

    Ok(())
}
