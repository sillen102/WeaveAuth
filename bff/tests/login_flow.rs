//! `/login` and `/callback` against a stub Hydra: the allowlist, PKCE, `state`, the id_token
//! checks and the session they end in.

mod support;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use support::*;
use uuid::Uuid;

const SUB: Uuid = Uuid::from_u128(0x5b1d3d0e_3a49_4a8f_9f43_1d1f0e0a7b11);

#[tokio::test]
async fn login_sends_the_browser_to_hydra_with_pkce_state_and_nonce() {
    let bff = Bff::start().await;

    let response = bff.start_login("http://app.test/dashboard").await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let url = location(&response);
    assert!(url.starts_with("http://hydra.test/oauth2/auth?"), "{url}");
    let query = query_of(&url);
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["redirect_uri"], "http://bff.test/callback");
    assert_eq!(query["scope"], "openid offline_access");
    assert_eq!(query["code_challenge_method"], "S256");
    for secret in ["state", "nonce", "code_challenge"] {
        assert!(query[secret].len() >= 43, "{secret}: {}", query[secret]);
    }
    assert!(!url.contains("client_secret") && !url.contains("code_verifier"));
}

#[tokio::test]
async fn login_sets_a_short_lived_http_only_cookie_that_holds_no_session() {
    let bff = Bff::start().await;

    let response = bff.start_login("http://app.test/").await;

    let cookie = set_cookie(&response, "wa_login").expect("login cookie");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    assert!(cookie.contains("Max-Age=600"), "{cookie}");
    assert!(set_cookie(&response, "wa_session").is_none());
}

#[tokio::test]
async fn every_login_gets_its_own_state_nonce_and_challenge() {
    let bff = Bff::start().await;

    let first = query_of(&location(&bff.start_login("http://app.test/").await));
    let second = query_of(&location(&bff.start_login("http://app.test/").await));

    for field in ["state", "nonce", "code_challenge"] {
        assert_ne!(first[field], second[field], "{field}");
    }
}

#[tokio::test]
async fn login_only_accepts_an_allowlisted_redirect_uri_exactly() {
    let bff = Bff::start().await;

    for accepted in ["http://app.test/", "http://app.test/dashboard"] {
        let response = bff.start_login(accepted).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{accepted}");
    }
    for rejected in [
        "http://evil.test/",
        "http://app.test",
        "http://app.test/dashboard/",
        "http://app.test/dashboard?x=1",
        "http://app.test/#frag",
        "http://app.test.evil.test/",
        "http://evil-app.test/",
        "http://app.test@evil.test/",
        "http://app.test:password@evil.test/",
        "http://evil.test/@app.test/",
        "http://evil.test/?http://app.test/",
        "http://evil.test#@app.test/",
        "http://app.test\\@evil.test/",
        "http://app.test%2f@evil.test/",
        "http://APP.test/",
        "HTTP://app.test/",
        "http://app.test:80/",
        "http://app.test/%2e%2e/",
        " http://app.test/",
        "http://app.test/ ",
        "http://app.test/\n",
        "//evil.test/",
        "/dashboard",
        "https://app.test/",
        "javascript:alert(1)",
        "data:text/html,x",
        "",
    ] {
        let response = bff.start_login(rejected).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{rejected:?}");
        assert!(response.headers().get("location").is_none(), "{rejected:?}");
        assert!(set_cookies(&response).is_empty(), "{rejected:?}");
    }
}

#[tokio::test]
async fn login_without_a_redirect_uri_is_a_bad_request() {
    let bff = Bff::start().await;

    let response = bff.get("/login", None).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get("location").is_none());
}

#[tokio::test]
async fn an_empty_allowlist_refuses_every_login() {
    let bff = Bff::start_with(|config| config.redirect_uri_allowlist.clear()).await;

    let response = bff.start_login("http://app.test/").await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_session_cookie_never_outlives_the_absolute_session_lifetime() {
    let bff =
        Bff::start_with(|config| config.hydra_refresh_token_ttl_secs = 40 * 24 * 60 * 60).await;

    let started = bff.start_login("http://app.test/dashboard").await;
    let authorize_url = location(&started);
    let state = query_of(&authorize_url)["state"].clone();
    let code = bff.hydra.grant(&authorize_url, SUB, None);
    let response = bff
        .get(
            &format!("/callback?code={code}&state={state}"),
            Some(&cookie_pair(&started, "wa_login")),
        )
        .await;

    let session = set_cookie(&response, "wa_session").expect("session cookie");
    assert!(session.contains("Max-Age=2592000"), "{session}");
}

#[tokio::test]
async fn callback_trades_the_code_for_a_session_and_redirects_without_tokens_in_the_url() {
    let bff = Bff::start().await;

    let started = bff.start_login("http://app.test/dashboard").await;
    let authorize_url = location(&started);
    let state = query_of(&authorize_url)["state"].clone();
    let code = bff.hydra.grant(&authorize_url, SUB, Some("sid-1"));
    let response = bff
        .get(
            &format!("/callback?code={code}&state={state}"),
            Some(&cookie_pair(&started, "wa_login")),
        )
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let to = location(&response);
    assert_eq!(to, "http://app.test/dashboard");
    assert!(!to.contains("token") && !to.contains(&code));
    let session = set_cookie(&response, "wa_session").expect("session cookie");
    assert!(session.contains("HttpOnly"), "{session}");
    assert!(session.contains("Path=/"), "{session}");
    assert!(session.contains("SameSite=Lax"), "{session}");
    assert!(session.contains("Max-Age=3600"), "{session}");
    assert!(!session.contains("Secure"), "plain http bff: {session}");
    let cleared = set_cookie(&response, "wa_login").expect("login cookie cleared");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
}

#[tokio::test]
async fn cookies_are_host_prefixed_and_secure_when_bff_is_served_over_https() {
    let bff = Bff::start_with(|config| config.bff_url = "https://bff.test".into()).await;

    let started = bff.start_login("http://app.test/").await;
    let login = set_cookie(&started, "__Host-wa_login").expect("prefixed login cookie");
    assert!(set_cookie(&started, "wa_login").is_none());
    let url = location(&started);
    let state = query_of(&url)["state"].clone();
    let code = bff.hydra.grant(&url, SUB, None);
    let response = bff
        .get(
            &format!("/callback?code={code}&state={state}"),
            Some(&cookie_pair(&started, "__Host-wa_login")),
        )
        .await;

    for cookie in [
        login,
        set_cookie(&response, "__Host-wa_login").expect("login cookie cleared"),
        set_cookie(&response, "__Host-wa_session").expect("prefixed session cookie"),
    ] {
        // What `__Host-` requires of the browser to accept it.
        assert!(cookie.contains("; Secure"), "{cookie}");
        assert!(cookie.contains("; Path=/;"), "{cookie}");
        assert!(!cookie.contains("Domain"), "{cookie}");
    }
    assert!(set_cookie(&response, "wa_session").is_none());
}

#[tokio::test]
async fn a_callback_without_the_prefixed_login_cookie_is_refused_over_https() {
    let bff = Bff::start_with(|config| config.bff_url = "https://bff.test".into()).await;
    let started = bff.start_login("http://app.test/").await;
    let url = location(&started);
    let state = query_of(&url)["state"].clone();
    let code = bff.hydra.grant(&url, SUB, None);
    let unprefixed = cookie_pair(&started, "__Host-wa_login").replace("__Host-", "");

    let response = bff
        .get(
            &format!("/callback?code={code}&state={state}"),
            Some(&unprefixed),
        )
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn two_login_cookies_are_no_login_in_progress() {
    let bff = Bff::start().await;
    let started = bff.start_login("http://app.test/").await;
    let url = location(&started);
    let state = query_of(&url)["state"].clone();
    let code = bff.hydra.grant(&url, SUB, None);
    let ours = cookie_pair(&started, "wa_login");

    let response = bff
        .get(
            &format!("/callback?code={code}&state={state}"),
            Some(&format!("{ours}; {ours}")),
        )
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(set_cookie(&response, "wa_session").is_none());
}

#[tokio::test]
async fn a_login_ends_the_session_the_browser_already_had() {
    let bff = Bff::start_proxied().await;
    let old = bff.login(SUB, Some("sid-1")).await;
    assert_eq!(bff.whoami(&old.cookie).await.status(), StatusCode::OK);

    let started = bff.start_login("http://app.test/").await;
    let url = location(&started);
    let state = query_of(&url)["state"].clone();
    let code = bff.hydra.grant(&url, SUB, Some("sid-2"));
    let response = bff
        .get(
            &format!("/callback?code={code}&state={state}"),
            Some(&format!(
                "{}; {}",
                cookie_pair(&started, "wa_login"),
                old.cookie
            )),
        )
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        bff.whoami(&old.cookie).await.status(),
        StatusCode::UNAUTHORIZED,
        "the session the browser logged in over lives on"
    );
    assert_eq!(bff.hydra.with(|hydra| hydra.revoked.clone()), ["refresh-1"]);
    let new = cookie_pair(&response, "wa_session");
    assert_eq!(bff.whoami(&new).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_refused_login_leaves_the_browsers_session_alone() {
    let bff = Bff::start_proxied().await;
    let old = bff.login(SUB, Some("sid-1")).await;
    let started = bff.start_login("http://app.test/").await;

    let response = bff
        .get(
            "/callback?code=whatever&state=wrong",
            Some(&format!(
                "{}; {}",
                cookie_pair(&started, "wa_login"),
                old.cookie
            )),
        )
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(bff.whoami(&old.cookie).await.status(), StatusCode::OK);
    assert!(bff.hydra.with(|hydra| hydra.revoked.is_empty()));
}

#[tokio::test]
async fn the_code_exchange_authenticates_the_client_and_proves_the_pkce_verifier() {
    let bff = Bff::start().await;

    bff.login(SUB, Some("sid-1")).await;

    bff.hydra.with(|hydra| {
        assert_eq!(hydra.requests.len(), 1);
        let request = &hydra.requests[0];
        assert_eq!(
            request.authorization.as_deref(),
            Some(
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
                )
                .as_str()
            )
        );
        assert_eq!(request.form["grant_type"], "authorization_code");
        assert_eq!(request.form["redirect_uri"], "http://bff.test/callback");
        assert!(
            !request.form.contains_key("client_secret"),
            "secret in the body"
        );
        // The stub also refuses a verifier that does not match the challenge, so a 303 above
        // means the right one was sent; this pins that it is an unguessable one.
        assert!(request.form["code_verifier"].len() >= 43);
    });
}

#[tokio::test]
async fn each_login_gets_a_new_session_id() {
    let bff = Bff::start().await;

    let first = bff.login(SUB, None).await;
    let second = bff.login(SUB, None).await;

    assert_ne!(first.cookie, second.cookie);
}

/// What `/callback` does with `query` and `cookie`, after a real `/login`.
async fn callback_after_login(
    bff: &Bff,
    query: impl FnOnce(&str, &str) -> String,
) -> (axum::response::Response, String) {
    let started = bff.start_login("http://app.test/").await;
    let url = location(&started);
    let state = query_of(&url)["state"].clone();
    let code = bff.hydra.grant(&url, SUB, Some("sid-1"));
    let response = bff
        .get(
            &format!("/callback?{}", query(&code, &state)),
            Some(&cookie_pair(&started, "wa_login")),
        )
        .await;
    (response, code)
}

fn assert_refused(response: &axum::response::Response, status: StatusCode) {
    assert_eq!(response.status(), status);
    assert!(
        set_cookie(response, "wa_session").is_none(),
        "a session was started"
    );
    assert!(response.headers().get("location").is_none());
}

#[tokio::test]
async fn callback_refuses_a_state_that_is_not_the_one_the_browser_started() {
    let bff = Bff::start().await;

    for query in [
        |code: &str, _: &str| format!("code={code}&state=not-the-state"),
        |code: &str, _: &str| format!("code={code}&state="),
        |code: &str, _: &str| format!("code={code}"),
        |code: &str, state: &str| format!("code={code}&state={state}x"),
        |code: &str, state: &str| format!("code={code}&state={}", state.to_uppercase()),
    ] {
        let (response, _) = callback_after_login(&bff, query).await;
        assert_refused(&response, StatusCode::BAD_REQUEST);
    }
    assert!(
        bff.hydra.with(|hydra| hydra.requests.is_empty()),
        "the code must not be redeemed for a request whose state is wrong"
    );
}

#[tokio::test]
async fn callback_refuses_the_state_of_another_login_started_elsewhere() {
    let bff = Bff::start().await;
    let ours = bff.start_login("http://app.test/").await;
    let attackers = bff.start_login("http://app.test/").await;
    let attackers_url = location(&attackers);
    let code = bff.hydra.grant(&attackers_url, SUB, None);
    let attackers_state = query_of(&attackers_url)["state"].clone();

    let response = bff
        .get(
            &format!("/callback?code={code}&state={attackers_state}"),
            Some(&cookie_pair(&ours, "wa_login")),
        )
        .await;

    assert_refused(&response, StatusCode::BAD_REQUEST);
    assert!(bff.hydra.with(|hydra| hydra.requests.is_empty()));
}

#[tokio::test]
async fn callback_without_a_login_cookie_or_with_a_broken_one_is_refused() {
    let bff = Bff::start().await;
    let started = bff.start_login("http://app.test/").await;
    let url = location(&started);
    let state = query_of(&url)["state"].clone();
    let code = bff.hydra.grant(&url, SUB, None);
    let uri = format!("/callback?code={code}&state={state}");

    for cookie in [
        None,
        Some("wa_login="),
        Some("wa_login=garbage"),
        Some("wa_login=e30"),
        Some("wa_session=something"),
    ] {
        let response = bff.get(&uri, cookie).await;
        assert_refused(&response, StatusCode::BAD_REQUEST);
    }
    assert!(bff.hydra.with(|hydra| hydra.requests.is_empty()));
}

#[tokio::test]
async fn callback_relays_a_refusal_from_hydra_without_redeeming_anything() {
    let bff = Bff::start().await;

    let (response, _) = callback_after_login(&bff, |_, state| {
        format!("error=access_denied&error_description=nope&state={state}")
    })
    .await;

    assert_refused(&response, StatusCode::BAD_REQUEST);
    assert!(bff.hydra.with(|hydra| hydra.requests.is_empty()));
}

#[tokio::test]
async fn callback_without_a_code_is_refused() {
    let bff = Bff::start().await;

    let (response, _) = callback_after_login(&bff, |_, state| format!("state={state}")).await;

    assert_refused(&response, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_code_can_only_start_one_session() {
    let bff = Bff::start().await;
    let started = bff.start_login("http://app.test/").await;
    let url = location(&started);
    let state = query_of(&url)["state"].clone();
    let code = bff.hydra.grant(&url, SUB, None);
    let uri = format!("/callback?code={code}&state={state}");
    let cookie = cookie_pair(&started, "wa_login");

    let first = bff.get(&uri, Some(&cookie)).await;
    let replay = bff.get(&uri, Some(&cookie)).await;

    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    assert_refused(&replay, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_failing_token_endpoint_is_a_bad_gateway_and_starts_no_session() {
    let bff = Bff::start().await;
    bff.hydra
        .with(|hydra| hydra.code_status = Some((500, "server_error")));

    let (response, _) =
        callback_after_login(&bff, |code, state| format!("code={code}&state={state}")).await;

    assert_refused(&response, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_token_endpoint_error_is_a_refused_sign_in_or_a_bad_gateway_by_its_oauth_error() {
    for (status, error, expected) in [
        (400, "invalid_grant", StatusCode::BAD_REQUEST),
        (401, "token_inactive", StatusCode::BAD_REQUEST),
        (403, "access_denied", StatusCode::BAD_REQUEST),
        (401, "invalid_client", StatusCode::BAD_GATEWAY),
        (400, "unauthorized_client", StatusCode::BAD_GATEWAY),
        (400, "server_error", StatusCode::BAD_GATEWAY),
    ] {
        let bff = Bff::start().await;
        bff.hydra
            .with(|hydra| hydra.code_status = Some((status, error)));

        let (response, _) =
            callback_after_login(&bff, |code, state| format!("code={code}&state={state}")).await;

        assert_refused(&response, expected);
    }
}

#[tokio::test]
async fn an_unreachable_hydra_is_a_bad_gateway() {
    let bff =
        Bff::start_with(|config| config.hydra_internal_url = "http://127.0.0.1:1".into()).await;
    let started = bff.start_login("http://app.test/").await;
    let url = location(&started);
    let state = query_of(&url)["state"].clone();

    let response = bff
        .get(
            &format!("/callback?code=whatever&state={state}"),
            Some(&cookie_pair(&started, "wa_login")),
        )
        .await;

    assert_refused(&response, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn an_id_token_that_does_not_verify_starts_no_session() {
    type Tamper = fn(&mut HydraState);
    let cases: [(&str, Tamper); 5] = [
        ("another nonce", |h| {
            h.nonce_override = Some("not-the-nonce".into())
        }),
        ("another audience", |h| {
            h.aud_override = Some(serde_json::json!(["someone-else"]))
        }),
        ("another issuer", |h| {
            h.iss_override = Some("http://evil.test".into())
        }),
        ("another key", |h| h.sign_with_other_key = true),
        ("no refresh token", |h| h.no_refresh_token = true),
    ];
    for (name, tamper) in cases {
        let bff = Bff::start().await;
        bff.hydra.with(tamper);

        let (response, _) =
            callback_after_login(&bff, |code, state| format!("code={code}&state={state}")).await;

        assert_refused(&response, StatusCode::BAD_GATEWAY);
        assert!(
            bff.hydra.with(|hydra| hydra.issued) > 0,
            "{name}: no token was issued to refuse"
        );
    }
}

#[tokio::test]
async fn a_tampered_login_cookie_cannot_redirect_the_browser_off_the_allowlist() {
    let bff = Bff::start().await;
    let (state, verifier, nonce) = (
        "a-state",
        "a-verifier-a-verifier-a-verifier-a-verifier",
        "a-nonce",
    );
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let cookie = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "state": state, "verifier": verifier, "nonce": nonce,
            "redirect_uri": "http://evil.test/",
        })
        .to_string(),
    );
    // A login Hydra would accept, as the attacker started it.
    let code = bff.hydra.grant(
        &format!(
            "http://hydra.test/oauth2/auth?nonce={nonce}&code_challenge={challenge}&redirect_uri=http://bff.test/callback"
        ),
        SUB,
        None,
    );

    let response = bff
        .get(
            &format!("/callback?code={code}&state={state}"),
            Some(&format!("wa_login={cookie}")),
        )
        .await;

    assert_refused(&response, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_and_callback_share_the_auth_rate_limit_but_health_is_exempt() {
    let bff = Bff::start_with(|config| config.rate_limit_max_attempts = 2).await;

    let first = bff.start_login("http://app.test/").await;
    let second = bff.get("/callback", None).await;
    let third = bff.start_login("http://app.test/").await;
    let health = bff.get("/health", None).await;

    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(health.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_user_logging_in_past_the_session_cap_ends_the_oldest_session_at_hydra() {
    let bff = Bff::start_proxied().await;
    let oldest = bff.login(SUB, None).await;
    let mut newest = oldest.cookie.clone();
    for _ in 0..19 {
        newest = bff.login(SUB, None).await.cookie;
    }
    assert_eq!(bff.whoami(&oldest.cookie).await.status(), StatusCode::OK);
    assert!(bff.hydra.with(|hydra| hydra.revoked.is_empty()));

    bff.login(SUB, None).await;

    assert_eq!(
        bff.whoami(&oldest.cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(bff.whoami(&newest).await.status(), StatusCode::OK);
    assert_eq!(bff.hydra.with(|hydra| hydra.revoked.clone()), ["refresh-1"]);
}
