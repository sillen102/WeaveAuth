//! `GET /logged-out`: where Hydra sends the browser once it has ended its session, on to the
//! app's own destination.

mod support;

use axum::http::StatusCode;
use support::*;

async fn logged_out(bff: &Bff, query: &str) -> axum::response::Response {
    bff.get(&format!("/logged-out{query}"), None).await
}

fn encoded(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[tokio::test]
async fn it_sends_the_browser_on_to_the_allowlisted_destination_in_state() {
    let bff = Bff::start().await;

    for destination in ["http://app.test/", "http://app.test/dashboard"] {
        let response = logged_out(&bff, &format!("?state={}", encoded(destination))).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{destination}");
        assert_eq!(location(&response), destination);
    }
}

#[tokio::test]
async fn it_never_sends_the_browser_anywhere_off_the_allowlist() {
    let bff = Bff::start().await;

    for rejected in [
        "http://evil.test/",
        "http://app.test",
        "http://app.test@evil.test/",
        "http://app.test.evil.test/",
        "http://evil.test/?http://app.test/",
        "//evil.test/",
        "javascript:alert(1)",
        "",
    ] {
        let response = logged_out(&bff, &format!("?state={}", encoded(rejected))).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{rejected:?}");
        assert!(response.headers().get("location").is_none(), "{rejected:?}");
    }
}

#[tokio::test]
async fn without_a_usable_state_it_falls_back_to_the_default_destination() {
    let bff = Bff::start_with(|config| {
        config.default_redirect_uri = Some("http://app.test/home".into());
    })
    .await;

    for query in [
        String::new(),
        "?state=".to_string(),
        format!("?state={}", encoded("http://evil.test/")),
    ] {
        let response = logged_out(&bff, &query).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{query}");
        assert_eq!(location(&response), "http://app.test/home", "{query}");
    }
}

#[tokio::test]
async fn without_a_usable_state_and_no_default_it_is_a_bad_request() {
    let bff = Bff::start().await;

    let response = logged_out(&bff, "").await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_whole_logout_ends_up_at_the_apps_destination() {
    let bff = Bff::start_proxied().await;
    let session = bff.login(uuid::Uuid::new_v4(), Some("sid-1")).await;

    let logout = bff
        .logout(
            Some("http://app.test"),
            Some(&session.cookie),
            "?redirect_uri=http%3A%2F%2Fapp.test%2Fdashboard",
        )
        .await;
    // What Hydra does: sends the browser to post_logout_redirect_uri with the state it got.
    let query = query_of(&location(&logout));
    let back = bff
        .get(
            &format!("/logged-out?state={}", encoded(&query["state"])),
            None,
        )
        .await;

    assert_eq!(location(&back), "http://app.test/dashboard");
}

#[tokio::test]
async fn it_shares_the_auth_rate_limit() {
    let bff = Bff::start_with(|config| config.rate_limit_max_attempts = 1).await;

    let first = logged_out(&bff, "").await;
    let second = logged_out(&bff, "").await;

    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}
