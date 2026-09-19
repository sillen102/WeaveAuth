//! The proxy flow: a session cookie minted by a real login gets swapped for
//! a real `Authorization: Bearer <access_token>` header and forwarded to a
//! stub upstream, over real HTTP through `backend`, `bff`, and the
//! upstream. `bff/tests/proxy.rs` already covers this thoroughly against a
//! *stubbed* backend (including every refresh-token edge case) -- what's
//! missing there, and what this file adds, is the same flow against a real
//! backend actually issuing and rotating real tokens.

#[allow(dead_code)]
mod support;

use support::config::{FINAL_REDIRECT, NEXT_ORIGIN};
use support::{servers, upstream};

const EMAIL: &str = "dave@example.com";
const PASSWORD: &str = "daves-strong-password";

fn backend_config() -> weaveauth::config::Config {
    support::config::backend_config(vec![FINAL_REDIRECT.to_string()])
}

fn bff_config(
    backend_url: String,
    bff_url: String,
    routes: Vec<weaveauth_bff::config::RouteConfig>,
) -> weaveauth_bff::config::Config {
    weaveauth_bff::config::Config {
        routes,
        ..support::config::bff_config(backend_url, bff_url, vec![NEXT_ORIGIN.to_string()])
    }
}

/// Registers an account and logs it in with a throwaway client, returning
/// just the `wa_session=...` cookie pair (no attributes) -- what a proxied
/// request needs to send back, same as a browser would.
async fn login_and_get_session_cookie(bff_url: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
    client
        .post(format!("{bff_url}/register"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("email", EMAIL), ("password", PASSWORD), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT_ORIGIN)])
        .send()
        .await?;
    let resp = client
        .post(format!("{bff_url}/login"))
        .header("origin", NEXT_ORIGIN)
        .form(&[("email", EMAIL), ("password", PASSWORD), ("redirect_uri", FINAL_REDIRECT), ("next", NEXT_ORIGIN)])
        .send()
        .await?;
    let set_cookie = resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("login response missing set-cookie"))?;
    Ok(set_cookie.split(';').next().unwrap_or_default().to_string())
}

/// A real session cookie gets swapped for a real bearer token, and the
/// request reaches the upstream with the session cookie itself stripped
/// (never leaked past bff).
#[tokio::test]
async fn proxy_swaps_session_cookie_for_a_real_bearer_token() -> anyhow::Result<()> {
    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");
    let (upstream_url, _upstream_handle) = upstream::start().await?;

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config()).await?;
    let routes = vec![weaveauth_bff::config::RouteConfig { path_prefix: "/api".to_string(), upstream_url }];
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone(), routes))?;

    let cookie = login_and_get_session_cookie(&bff_url).await?;

    let client = reqwest::Client::new();
    let resp = client.get(format!("{bff_url}/api/whoami/42")).header("cookie", &cookie).send().await?;

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await?;
    assert!(body.starts_with("id=42 auth=Bearer "), "expected a real bearer token forwarded, got: {body}");
    assert!(body.ends_with("cookie=false"), "the session cookie must not reach upstream, got: {body}");

    Ok(())
}

/// No session cookie at all -- bff must reject before ever reaching the
/// upstream, not forward an unauthenticated request.
#[tokio::test]
async fn proxy_without_a_session_cookie_is_unauthorized() -> anyhow::Result<()> {
    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");
    let (upstream_url, _upstream_handle) = upstream::start().await?;

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config()).await?;
    let routes = vec![weaveauth_bff::config::RouteConfig { path_prefix: "/api".to_string(), upstream_url }];
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone(), routes))?;

    let resp = reqwest::Client::new().get(format!("{bff_url}/api/whoami/42")).send().await?;

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

/// A garbage/unknown session cookie is rejected the same way a missing one
/// is -- there's no session behind it for bff to resolve to a token.
#[tokio::test]
async fn proxy_with_an_unknown_session_cookie_is_unauthorized() -> anyhow::Result<()> {
    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");
    let (upstream_url, _upstream_handle) = upstream::start().await?;

    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config()).await?;
    let routes = vec![weaveauth_bff::config::RouteConfig { path_prefix: "/api".to_string(), upstream_url }];
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone(), routes))?;

    let resp = reqwest::Client::new()
        .get(format!("{bff_url}/api/whoami/42"))
        .header("cookie", "wa_session=does-not-exist")
        .send()
        .await?;

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

/// Once the access token backing a session actually expires against a real
/// backend, the very next proxied request transparently redeems the refresh
/// token for a new one (see `resolve_bearer_token` in
/// `bff/src/server/api/proxy.rs`) and still reaches upstream -- no re-login
/// needed. `bff/tests/proxy.rs` pins this against a stubbed token endpoint;
/// this proves the same contract holds against backend's real one.
#[tokio::test]
async fn expired_access_token_is_transparently_refreshed_against_a_real_backend() -> anyhow::Result<()> {
    let (bff_addr, bff_listener) = servers::reserve_port().await?;
    let bff_url = format!("http://{bff_addr}");
    let (upstream_url, _upstream_handle) = upstream::start().await?;

    // A 1-second access token TTL, with the refresh token given plenty of
    // room -- forces the very next request after that second passes onto
    // the refresh path instead of the happy path above.
    let backend_config = weaveauth::config::Config { access_token_ttl_secs: 1, ..backend_config() };
    let (backend_url, _backend_handle) = servers::spawn_backend(&backend_config).await?;
    let routes = vec![weaveauth_bff::config::RouteConfig { path_prefix: "/api".to_string(), upstream_url }];
    let _bff_handle = servers::spawn_bff_on(bff_listener, bff_config(backend_url, bff_url.clone(), routes))?;

    let cookie = login_and_get_session_cookie(&bff_url).await?;
    let client = reqwest::Client::new();

    let first = client.get(format!("{bff_url}/api/whoami/1")).header("cookie", &cookie).send().await?;
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let first_body = first.text().await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let second = client.get(format!("{bff_url}/api/whoami/1")).header("cookie", &cookie).send().await?;
    assert_eq!(second.status(), reqwest::StatusCode::OK, "an expired access token should be transparently refreshed");
    let second_body = second.text().await?;

    assert_ne!(second_body, first_body, "refreshing should hand out a different access token");
    assert!(second_body.starts_with("id=1 auth=Bearer "));

    Ok(())
}
