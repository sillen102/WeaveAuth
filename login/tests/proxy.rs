//! The proxy to Kratos' public API: what goes through, and the limits in front of it.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::*;
use weaveauth_login::{Config, app};

async fn setup() -> (axum::Router, std::sync::Arc<StubState>) {
    let (url, state) = stub().await;
    (app(config(&url)).unwrap(), state)
}

const SESSION_COOKIE: &str = "ory_kratos_session=abc; Path=/; HttpOnly";

fn login_body(identifier: &str) -> String {
    let encoded: String = url::form_urlencoded::byte_serialize(identifier.as_bytes()).collect();
    format!("method=password&identifier={encoded}&password=hunter2&csrf_token=t")
}

#[tokio::test]
async fn cookies_go_to_kratos_and_set_cookies_come_back() {
    let (app, state) = setup().await;

    let reply = get_with_cookie(
        &app,
        "/self-service/login/browser?login_challenge=c",
        "csrf_token_abc=xyz",
    )
    .await;

    assert_eq!(reply.status, 303);
    assert_eq!(reply.header("location"), "/login?flow=started");
    let seen = &state.requests("/self-service/login/browser")[0];
    assert_eq!(
        seen.path_and_query,
        "/self-service/login/browser?login_challenge=c"
    );
    assert_eq!(seen.cookie(), Some("csrf_token_abc=xyz"));
    assert_eq!(
        reply.set_cookies(),
        vec!["csrf_token_abc=xyz; Path=/; HttpOnly; SameSite=Lax".to_string()]
    );
}

#[tokio::test]
async fn several_set_cookie_headers_all_reach_the_browser() {
    let (app, _) = setup().await;

    let reply = get(&app, "/self-service/logout?token=tok").await;

    assert_eq!(
        reply.set_cookies(),
        vec!["ory_kratos_session=; Max-Age=0; Path=/".to_string()]
    );
}

#[tokio::test]
async fn well_known_scripts_are_proxied_with_their_type_and_only_safe_headers() {
    let (app, _) = setup().await;

    let reply = get(&app, "/.well-known/ory/webauthn.js").await;

    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, "/* webauthn */");
    assert_eq!(reply.header("content-type"), "text/javascript");
    assert_eq!(reply.header("x-content-type-options"), "nosniff");
    assert!(reply.headers.get("x-kratos-secret-header").is_none());
}

#[tokio::test]
async fn a_post_body_and_content_type_are_forwarded() {
    let (app, state) = setup().await;

    let reply = post_form(
        &app,
        "/self-service/registration?flow=f1",
        "a=1&b=%26",
        "127.0.0.1",
    )
    .await;

    assert_eq!(reply.status, 404, "the stub only knows the login post");
    let seen = &state.requests("/self-service/registration")[0];
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.body, "a=1&b=%26");
    assert_eq!(
        seen.headers.get("content-type").unwrap(),
        "application/x-www-form-urlencoded"
    );
}

#[tokio::test]
async fn other_headers_do_not_reach_kratos() {
    let (app, state) = setup().await;

    send(
        &app,
        Request::get("/self-service/login/browser")
            .header("authorization", "Bearer secret")
            .header("x-forwarded-for", "1.2.3.4")
            .header("x-session-token", "tok")
            .header("cookie", "a=b")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1",
    )
    .await;

    let seen = &state.requests("/self-service/login/browser")[0];
    assert!(seen.headers.get("authorization").is_none());
    assert!(seen.headers.get("x-forwarded-for").is_none());
    assert!(seen.headers.get("x-session-token").is_none());
    assert_eq!(seen.cookie(), Some("a=b"));
}

#[tokio::test]
async fn only_kratos_browser_paths_are_proxied() {
    let (app, state) = setup().await;

    for path in [
        "/admin/identities",
        "/sessions/whoami",
        "/self-service",
        "/.well-known/jwks.json",
        "/self-service/../admin/identities",
        "/self-service/%2e%2e/admin/identities",
        "/self-service/login/%2E%2E/%2E%2E/admin",
        "/.well-known/ory/../../admin/identities",
    ] {
        let reply = get(&app, path).await;
        assert_eq!(reply.status, 404, "{path}");
    }
    assert!(state.all().is_empty(), "{:?}", state.all());
}

#[tokio::test]
async fn other_methods_are_not_proxied() {
    let (app, state) = setup().await;

    for method in ["PUT", "DELETE", "PATCH"] {
        let reply = send(
            &app,
            Request::builder()
                .method(method)
                .uri("/self-service/login?flow=f1")
                .body(Body::empty())
                .unwrap(),
            "127.0.0.1",
        )
        .await;
        assert_eq!(reply.status, 405, "{method}");
    }
    assert!(state.all().is_empty());
}

#[tokio::test]
async fn an_unreachable_kratos_gives_a_generic_502() {
    let app = app(config("http://127.0.0.1:1")).unwrap();

    let reply = get(&app, "/self-service/login/browser").await;

    assert_eq!(reply.status, 502);
    assert!(!reply.body.contains("127.0.0.1"));
    assert!(!reply.body.to_lowercase().contains("refused"));
}

#[tokio::test]
async fn submissions_are_limited_per_client_address() {
    let (url, state) = stub().await;
    let app = app(Config {
        rate_limit_max_attempts: 2,
        ..config(&url)
    })
    .unwrap();

    for _ in 0..2 {
        assert_eq!(
            post_form(
                &app,
                "/self-service/registration?flow=f",
                "a=1",
                "198.51.100.1"
            )
            .await
            .status,
            404
        );
    }
    let limited = post_form(
        &app,
        "/self-service/registration?flow=f",
        "a=1",
        "198.51.100.1",
    )
    .await;
    let other = post_form(
        &app,
        "/self-service/registration?flow=f",
        "a=1",
        "198.51.100.2",
    )
    .await;

    assert_eq!(limited.status, 429);
    assert_eq!(other.status, 404);
    assert_eq!(state.count("POST", "/self-service/registration"), 3);
}

#[tokio::test]
async fn other_requests_have_their_own_larger_bucket() {
    let (url, _) = stub().await;
    let app = app(Config {
        rate_limit_max_attempts: 1,
        rate_limit_proxy_max_attempts: 3,
        ..config(&url)
    })
    .unwrap();

    for _ in 0..3 {
        let reply = get(&app, "/.well-known/ory/webauthn.js").await;
        assert_eq!(reply.status, 200);
    }
    assert_eq!(get(&app, "/.well-known/ory/webauthn.js").await.status, 429);
    // Submissions draw from the other bucket.
    assert_ne!(
        post_form(
            &app,
            "/self-service/registration?flow=f",
            "a=1",
            "127.0.0.1"
        )
        .await
        .status,
        429
    );
}

#[tokio::test]
async fn pages_are_limited_too() {
    let (url, _) = stub().await;
    let app = app(Config {
        rate_limit_proxy_max_attempts: 2,
        ..config(&url)
    })
    .unwrap();

    assert_eq!(get(&app, "/login?flow=f1").await.status, 200);
    assert_eq!(get(&app, "/login?flow=f1").await.status, 200);
    assert_eq!(get(&app, "/login?flow=f1").await.status, 429);
}

#[tokio::test]
async fn behind_a_trusted_proxy_clients_are_keyed_on_x_forwarded_for() {
    let (url, _) = stub().await;
    let app = app(Config {
        rate_limit_max_attempts: 1,
        trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()],
        ..config(&url)
    })
    .unwrap();
    let post = |ip: &'static str, forwarded: &'static str| {
        let app = app.clone();
        async move {
            send(
                &app,
                Request::post("/self-service/registration?flow=f")
                    .header("x-forwarded-for", forwarded)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("a=1"))
                    .unwrap(),
                ip,
            )
            .await
            .status
        }
    };

    assert_eq!(post("10.0.0.2", "198.51.100.1").await, 404);
    assert_eq!(post("10.0.0.2", "198.51.100.1").await, 429);
    assert_eq!(post("10.0.0.2", "198.51.100.2").await, 404);
    // An untrusted peer's header is ignored: both land on its own address.
    assert_eq!(post("203.0.113.9", "198.51.100.3").await, 404);
    assert_eq!(post("203.0.113.9", "198.51.100.4").await, 429);
}

#[tokio::test]
async fn failed_logins_for_one_identifier_are_throttled_across_addresses() {
    let (app, state) = setup().await;

    // Five free failures, each from another address and with the identifier spelled differently.
    for (n, identifier) in [
        "victim@example.com",
        "VICTIM@example.com",
        "  victim@example.com ",
        "Victim@Example.com",
        "victim@example.COM",
    ]
    .iter()
    .enumerate()
    {
        let reply = post_form(
            &app,
            "/self-service/login?flow=f1",
            &login_body(identifier),
            &format!("198.51.100.{n}"),
        )
        .await;
        assert_eq!(reply.status, 303, "attempt {n}");
    }
    assert_eq!(state.count("POST", "/self-service/login"), 5);

    let throttled = post_form(
        &app,
        "/self-service/login?flow=f1",
        &login_body("victim@example.com"),
        "203.0.113.77",
    )
    .await;

    assert_eq!(throttled.status, 429);
    let wait: u64 = throttled.header("retry-after").parse().unwrap();
    assert!((1..=30).contains(&wait), "{wait}");
    assert_eq!(
        state.count("POST", "/self-service/login"),
        5,
        "not forwarded"
    );
    assert!(throttled.headers.get("content-security-policy").is_some());
}

#[tokio::test]
async fn other_identifiers_are_unaffected_and_unknown_ones_are_treated_alike() {
    let (app, state) = setup().await;
    let mut bodies = Vec::new();
    for identifier in ["known@example.com", "nobody-ever@example.com"] {
        for _ in 0..5 {
            post_form(
                &app,
                "/self-service/login?flow=f1",
                &login_body(identifier),
                "127.0.0.1",
            )
            .await;
        }
        let throttled = post_form(
            &app,
            "/self-service/login?flow=f1",
            &login_body(identifier),
            "127.0.0.1",
        )
        .await;
        assert_eq!(throttled.status, 429, "{identifier}");
        // Each page has its own nonce; nothing else may differ.
        bodies.push(throttled.body.replace(&throttled.csp_nonce(), ""));
    }
    assert_eq!(
        bodies[0], bodies[1],
        "the response must not tell the two apart"
    );

    let fresh = post_form(
        &app,
        "/self-service/login?flow=f1",
        &login_body("someone-else@example.com"),
        "127.0.0.1",
    )
    .await;

    assert_eq!(fresh.status, 303);
    assert_eq!(state.count("POST", "/self-service/login"), 11);
}

#[tokio::test]
async fn a_successful_login_clears_the_failures() {
    let (app, state) = setup().await;
    let body = login_body("me@example.com");
    let post = || post_form(&app, "/self-service/login?flow=f1", &body, "127.0.0.1");
    for _ in 0..4 {
        post().await;
    }
    *state.login_post.lock().unwrap() = (
        axum::http::StatusCode::SEE_OTHER,
        Some("http://login.test/oauth2/auth?client_id=x&login_verifier=v".into()),
    );
    *state.login_post_cookie.lock().unwrap() = Some(SESSION_COOKIE.into());
    assert_eq!(post().await.status, 303);
    *state.login_post.lock().unwrap() = (
        axum::http::StatusCode::SEE_OTHER,
        Some("http://login.test/login?flow=f2".into()),
    );
    *state.login_post_cookie.lock().unwrap() = None;

    for n in 0..5 {
        assert_eq!(post().await.status, 303, "attempt {n} after the success");
    }
    assert_eq!(post().await.status, 429);
}

#[tokio::test]
async fn attempts_kratos_rejected_before_checking_a_password_do_not_count() {
    let (app, state) = setup().await;
    // A csrf failure sends the browser to the error page; it says nothing about the password.
    *state.login_post.lock().unwrap() = (
        axum::http::StatusCode::SEE_OTHER,
        Some("http://login.test/error?id=e1".into()),
    );
    for _ in 0..12 {
        let reply = post_form(
            &app,
            "/self-service/login?flow=f1",
            &login_body("victim@example.com"),
            "127.0.0.1",
        )
        .await;
        assert_eq!(reply.status, 303);
    }
    for refused in [
        axum::http::StatusCode::FORBIDDEN,
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        *state.login_post.lock().unwrap() = (refused, None);
        for _ in 0..12 {
            let reply = post_form(
                &app,
                "/self-service/login?flow=f1",
                &login_body("victim@example.com"),
                "127.0.0.1",
            )
            .await;
            assert_eq!(reply.status, refused);
        }
    }

    assert_eq!(state.count("POST", "/self-service/login"), 48);
}

#[tokio::test]
async fn json_submissions_that_fail_are_throttled_like_form_ones() {
    let (app, state) = setup().await;
    *state.login_post.lock().unwrap() = (axum::http::StatusCode::BAD_REQUEST, None);
    let post = || {
        send(
            &app,
            Request::post("/self-service/login?flow=f1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"method":"password","identifier":"Json@Example.com","password":"x","csrf_token":"t"}"#))
                .unwrap(),
            "127.0.0.1",
        )
    };

    for _ in 0..5 {
        assert_eq!(post().await.status, 400);
    }
    assert_eq!(post().await.status, 429);
    // The same identifier submitted as a form is the same key.
    let form = post_form(
        &app,
        "/self-service/login?flow=f1",
        &login_body("json@example.com"),
        "127.0.0.1",
    )
    .await;
    assert_eq!(form.status, 429);
}

#[tokio::test]
async fn login_posts_in_other_encodings_are_refused() {
    let (app, state) = setup().await;

    let reply = send(
        &app,
        Request::post("/self-service/login?flow=f1")
            .header("content-type", "multipart/form-data; boundary=x")
            .body(Body::from("--x--"))
            .unwrap(),
        "127.0.0.1",
    )
    .await;

    assert_eq!(reply.status, 415);
    assert_eq!(state.count("POST", "/self-service/login"), 0);
}

#[tokio::test]
async fn parallel_attempts_cannot_overshoot_the_free_failures() {
    let (app, state) = setup().await;

    let mut tasks = Vec::new();
    for _ in 0..20 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            post_form(
                &app,
                "/self-service/login?flow=f1",
                &login_body("race@example.com"),
                "127.0.0.1",
            )
            .await
            .status
        }));
    }
    let mut forwarded = 0;
    for task in tasks {
        if task.await.unwrap() != 429 {
            forwarded += 1;
        }
    }

    assert_eq!(forwarded, 5);
    assert_eq!(state.count("POST", "/self-service/login"), 5);
}

#[tokio::test]
async fn other_methods_and_posts_without_an_identifier_are_not_throttled() {
    let (app, state) = setup().await;

    for _ in 0..12 {
        post_form(
            &app,
            "/self-service/login?flow=f1",
            "method=oidc&provider=google&csrf_token=t",
            "127.0.0.1",
        )
        .await;
        post_form(
            &app,
            "/self-service/login?flow=f1",
            "method=passkey&identifier=a%40b.c",
            "127.0.0.1",
        )
        .await;
    }

    assert_eq!(state.count("POST", "/self-service/login"), 24);
}

#[tokio::test]
async fn attempts_that_never_reached_kratos_do_not_count() {
    let app = app(config("http://127.0.0.1:1")).unwrap();

    for n in 0..8 {
        let reply = post_form(
            &app,
            "/self-service/login?flow=f1",
            &login_body("victim@example.com"),
            "127.0.0.1",
        )
        .await;
        assert_eq!(reply.status, 502, "attempt {n}");
    }
}

#[tokio::test]
async fn a_login_post_that_repeats_the_identifier_or_method_is_refused() {
    let (app, state) = setup().await;
    let form =
        |body: &'static str| post_form(&app, "/self-service/login?flow=f1", body, "127.0.0.1");
    let json = |body: &'static str| {
        send(
            &app,
            Request::post("/self-service/login?flow=f1")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
            "127.0.0.1",
        )
    };

    for reply in [
        form("method=password&identifier=other%40example.com&identifier=victim%40example.com&password=x")
            .await,
        form("method=oidc&method=password&identifier=victim%40example.com&password=x").await,
        json(r#"{"method":"password","identifier":"a@example.com","identifier":"victim@example.com"}"#)
            .await,
        json(r#"{"method":"oidc","method":"password","identifier":"victim@example.com"}"#).await,
    ] {
        assert_eq!(reply.status, 400);
    }
    assert_eq!(state.count("POST", "/self-service/login"), 0);

    let single = form("method=password&identifier=victim%40example.com&password=x").await;
    assert_eq!(single.status, 303);
    assert_eq!(state.count("POST", "/self-service/login"), 1);
}

#[tokio::test]
async fn kratos_api_flows_are_not_proxied() {
    let (app, state) = setup().await;

    for path in [
        "/self-service/login/api",
        "/self-service/registration/api",
        "/self-service/recovery/api/",
        "/self-service/settings/api",
        "/self-service/login/%61pi",
    ] {
        let reply = get(&app, path).await;
        assert_eq!(reply.status, 404, "{path}");
    }
    let reply = post_form(&app, "/self-service/registration/api", "a=1", "127.0.0.1").await;
    assert_eq!(reply.status, 404);
    assert!(state.all().is_empty(), "{:?}", state.all());

    let browser = get(&app, "/self-service/login/browser").await;
    assert_eq!(browser.status, 303);
}

#[tokio::test]
async fn a_422_redirect_instruction_is_a_success_not_a_failed_guess() {
    let (app, state) = setup().await;
    *state.login_post.lock().unwrap() = (axum::http::StatusCode::UNPROCESSABLE_ENTITY, None);
    *state.login_post_cookie.lock().unwrap() = Some(SESSION_COOKIE.into());

    for _ in 0..12 {
        let reply = post_form(
            &app,
            "/self-service/login?flow=f1",
            &login_body("victim@example.com"),
            "127.0.0.1",
        )
        .await;
        assert_eq!(reply.status, 422);
    }
}

#[tokio::test]
async fn kratos_is_told_the_client_address_the_rate_limiter_resolved() {
    let (url, state) = stub().await;
    let app = app(Config {
        trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()],
        ..config(&url)
    })
    .unwrap();
    let get_from = |ip: &'static str, forwarded: &'static str| {
        let app = app.clone();
        async move {
            send(
                &app,
                Request::get("/self-service/login/browser")
                    .header("x-forwarded-for", forwarded)
                    .header("true-client-ip", "6.6.6.6")
                    .body(Body::empty())
                    .unwrap(),
                ip,
            )
            .await;
        }
    };

    get_from("10.0.0.2", "198.51.100.1").await;
    get_from("203.0.113.9", "198.51.100.3").await;

    let seen = state.requests("/self-service/login/browser");
    let ips: Vec<_> = seen
        .iter()
        .map(|seen| {
            seen.headers
                .get("true-client-ip")
                .unwrap()
                .to_str()
                .unwrap()
        })
        .collect();
    assert_eq!(ips, ["198.51.100.1", "203.0.113.9"]);
    assert!(
        seen.iter()
            .all(|seen| seen.headers.get("x-forwarded-for").is_none())
    );
}

fn json_post<'a>(
    app: &'a axum::Router,
    body: &'static str,
) -> impl std::future::Future<Output = Reply> + 'a {
    send(
        app,
        Request::post("/self-service/login?flow=f1")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap(),
        "127.0.0.1",
    )
}

#[tokio::test]
async fn a_json_login_body_serde_rejects_is_refused_not_let_past_the_throttle() {
    let (app, state) = setup().await;

    for body in [
        // Go's decoder turns a lone surrogate into U+FFFD; serde refuses it.
        r#"{"method":"password","identifier":"victim@example.com","pad":"\ud800"}"#,
        r#"{"method":"password","identifier":"victim@example.com"} trailing"#,
        "not json",
    ] {
        assert_eq!(json_post(&app, body).await.status, 400, "{body}");
    }
    assert_eq!(state.count("POST", "/self-service/login"), 0);
}

#[tokio::test]
async fn a_percent_encoded_or_doubled_slash_path_does_not_dodge_the_throttle() {
    let (app, state) = setup().await;

    for path in [
        "/self-service/%6cogin?flow=f1",
        "/self-service//login?flow=f1",
        "/self-service/login%2f?flow=f1",
    ] {
        let reply = post_form(&app, path, &login_body("victim@example.com"), "127.0.0.1").await;
        assert_eq!(reply.status, 404, "{path}");
    }
    assert!(state.all().is_empty(), "{:?}", state.all());
}

#[tokio::test]
async fn json_keys_kratos_could_read_differently_are_refused() {
    let (app, state) = setup().await;

    for body in [
        r#"{"identifier":"junk@example.com","IDENTIFIER":"victim@example.com","password":"x"}"#,
        r#"{"method":"passkey","METHOD":"password","identifier":"victim@example.com"}"#,
        r#"{"identifier":"a@example.com","password_identifier":"victim@example.com"}"#,
        r#"{"method":"password","identifier":5,"password":"x"}"#,
        r#"{"method":"password","Password_Identifier":"victim@example.com"}"#,
        // A non-ASCII "ſ" that Go's case folding reads as "s".
        r#"{"method":"password","paſsword_identifier":"victim@example.com","password":"x"}"#,
    ] {
        assert_eq!(json_post(&app, body).await.status, 400, "{body}");
    }
    assert_eq!(state.count("POST", "/self-service/login"), 0);
}

#[tokio::test]
async fn the_deprecated_password_identifier_is_throttled_like_identifier() {
    let (app, state) = setup().await;
    *state.login_post.lock().unwrap() = (axum::http::StatusCode::BAD_REQUEST, None);

    for _ in 0..5 {
        let reply = json_post(
            &app,
            r#"{"method":"password","password_identifier":"Legacy@Example.com","password":"x"}"#,
        )
        .await;
        assert_eq!(reply.status, 400);
    }
    let form = post_form(
        &app,
        "/self-service/login?flow=f1",
        &login_body("legacy@example.com"),
        "127.0.0.1",
    )
    .await;

    assert_eq!(form.status, 429);
    assert_eq!(state.count("POST", "/self-service/login"), 5);
}

#[tokio::test]
async fn a_redirect_without_a_session_cookie_is_not_a_success() {
    let (app, state) = setup().await;
    // Kratos sends a browser that already has a session onward without checking the password.
    *state.login_post.lock().unwrap() = (
        axum::http::StatusCode::SEE_OTHER,
        Some("http://login.test/oauth2/auth?login_verifier=v".into()),
    );
    let body = login_body("victim@example.com");
    for _ in 0..5 {
        post_form(&app, "/self-service/login?flow=f1", &body, "127.0.0.1").await;
    }

    let throttled = post_form(&app, "/self-service/login?flow=f1", &body, "127.0.0.1").await;

    assert_eq!(throttled.status, 429);
}

#[tokio::test]
async fn an_empty_session_cookie_is_not_a_success() {
    let (app, state) = setup().await;
    *state.login_post.lock().unwrap() = (
        axum::http::StatusCode::SEE_OTHER,
        Some("http://login.test/oauth2/auth?login_verifier=v".into()),
    );
    *state.login_post_cookie.lock().unwrap() = Some("ory_kratos_session=; Max-Age=0".into());
    let body = login_body("victim@example.com");
    for _ in 0..5 {
        post_form(&app, "/self-service/login?flow=f1", &body, "127.0.0.1").await;
    }

    let throttled = post_form(&app, "/self-service/login?flow=f1", &body, "127.0.0.1").await;

    assert_eq!(throttled.status, 429);
}

#[tokio::test]
async fn a_form_password_identifier_is_throttled_like_identifier() {
    let (app, state) = setup().await;
    *state.login_post.lock().unwrap() = (axum::http::StatusCode::BAD_REQUEST, None);
    let alias = "method=password&password_identifier=Victim%40Example.com&password=x";

    for _ in 0..5 {
        let reply = post_form(&app, "/self-service/login?flow=f1", alias, "127.0.0.1").await;
        assert_eq!(reply.status, 400);
    }
    let throttled = post_form(
        &app,
        "/self-service/login?flow=f1",
        &login_body("victim@example.com"),
        "127.0.0.1",
    )
    .await;

    assert_eq!(throttled.status, 429);
    assert_eq!(state.count("POST", "/self-service/login"), 5);
}

#[tokio::test]
async fn a_form_with_identifier_and_password_identifier_is_refused() {
    let (app, state) = setup().await;

    let reply = post_form(
        &app,
        "/self-service/login?flow=f1",
        "method=password&identifier=a%40example.com&password_identifier=victim%40example.com&password=x",
        "127.0.0.1",
    )
    .await;

    assert_eq!(reply.status, 400);
    assert_eq!(state.count("POST", "/self-service/login"), 0);
}

/// Five failed posts for one identifier, whatever Kratos answers with, then the sixth.
async fn sixth_attempt_after_answer(
    status: axum::http::StatusCode,
    location: Option<&str>,
    cookie: Option<&str>,
) -> u16 {
    let (app, state) = setup().await;
    *state.login_post.lock().unwrap() = (status, location.map(Into::into));
    *state.login_post_cookie.lock().unwrap() = cookie.map(Into::into);
    let body = login_body("victim@example.com");
    for _ in 0..5 {
        post_form(&app, "/self-service/login?flow=f1", &body, "127.0.0.1").await;
    }
    post_form(&app, "/self-service/login?flow=f1", &body, "127.0.0.1")
        .await
        .status
        .as_u16()
}

#[tokio::test]
async fn a_422_without_a_session_cookie_is_not_a_success() {
    let status = axum::http::StatusCode::UNPROCESSABLE_ENTITY;
    assert_eq!(sixth_attempt_after_answer(status, None, None).await, 429);
}

#[tokio::test]
async fn a_200_without_a_session_cookie_is_not_a_success() {
    let status = axum::http::StatusCode::OK;
    assert_eq!(sixth_attempt_after_answer(status, None, None).await, 429);
}

#[tokio::test]
async fn a_redirect_elsewhere_without_a_session_cookie_is_not_a_success() {
    let status = axum::http::StatusCode::SEE_OTHER;
    let to = Some("https://other.test/x");
    assert_eq!(sixth_attempt_after_answer(status, to, None).await, 429);
}

#[tokio::test]
async fn a_redirect_with_only_another_cookie_is_not_a_success() {
    let status = axum::http::StatusCode::SEE_OTHER;
    let to = Some("/oauth2/auth");
    let cookie = Some("csrf_token_abc=x; Path=/");
    assert_eq!(sixth_attempt_after_answer(status, to, cookie).await, 429);
}

#[tokio::test]
async fn a_configured_session_cookie_name_decides_what_a_success_is() {
    let (url, state) = stub().await;
    let config = Config {
        kratos_session_cookie: "custom_session".into(),
        ..config(&url)
    };
    let app = app(config).unwrap();
    *state.login_post.lock().unwrap() = (axum::http::StatusCode::SEE_OTHER, Some("/x".into()));
    *state.login_post_cookie.lock().unwrap() = Some("custom_session=abc; Path=/".into());
    let body = login_body("victim@example.com");

    for _ in 0..8 {
        let reply = post_form(&app, "/self-service/login?flow=f1", &body, "127.0.0.1").await;
        assert_eq!(reply.status, 303);
    }
}

#[tokio::test]
async fn a_login_post_on_a_case_or_slash_variant_of_the_path_is_refused() {
    let (app, state) = setup().await;

    for path in [
        "/self-service/LOGIN?flow=f1",
        "/self-service/Login/?flow=f1",
        "/self-service/login/?flow=f1",
    ] {
        let reply = post_form(&app, path, &login_body("victim@example.com"), "127.0.0.1").await;
        assert_eq!(reply.status, 404, "{path}");
    }
    assert!(state.all().is_empty(), "{:?}", state.all());
}

#[tokio::test]
async fn proxied_answers_get_hardening_headers_and_no_store_by_default() {
    let (app, _) = setup().await;

    let flow = get(&app, "/self-service/login/browser").await;
    let script = get(&app, "/.well-known/ory/webauthn.js").await;
    let static_file = get(&app, "/static/style.css").await;

    assert_eq!(flow.header("cache-control"), "no-store");
    assert!(
        flow.header("content-security-policy")
            .contains("default-src 'none'")
    );
    assert_eq!(script.header("cache-control"), "public, max-age=60");
    assert!(script.header("content-security-policy").contains("sandbox"));
    assert_eq!(static_file.header("x-content-type-options"), "nosniff");
    assert_eq!(static_file.header("cache-control"), "no-cache");
}
