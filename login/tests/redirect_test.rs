use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use weaveauth_login::{Config, app};

fn test_config() -> Config {
    Config {
        port: 8081,
        bff_url: "http://bff.test".into(),
        own_origin: "http://login.test".into(),
        email_link_default_redirect_uri: None,
        bff_internal_url: None,
    }
}

/// A bff stand-in serving `/oidc/providers` with `status`; returns its URL
/// and how many times the list was fetched.
async fn counting_stub_bff(
    status: StatusCode,
) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = fetches.clone();
    let router = axum::Router::new().route(
        "/oidc/providers",
        axum::routing::get(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                (
                    status,
                    axum::Json(serde_json::json!({"providers": [
                        {"key": "google", "display_name": "Google"},
                        {"key": "linkedin", "display_name": "LinkedIn"},
                    ]})),
                )
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), fetches)
}

async fn stub_bff() -> String {
    counting_stub_bff(StatusCode::OK).await.0
}

async fn config_with_stub_bff() -> Config {
    Config {
        bff_url: stub_bff().await,
        ..test_config()
    }
}

async fn body_string(resp: axum::response::Response) -> String {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

#[tokio::test]
async fn serves_the_embedded_shell_at_root() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("id=\"page\""));
    assert!(body.contains("src=\"/htmx.min.js\""));
    assert!(body.contains("login.html"));
    assert!(!body.contains("<script src=\"/config.js\">"));
}

#[tokio::test]
async fn serves_the_embedded_shell_at_index_html_too() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/index.html").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("id=\"page\""));
}

#[tokio::test]
async fn login_page_has_no_script_tags_and_bakes_in_bff_url() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/login.html?redirect_uri=http%3A%2F%2Fadmin.test%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(!body.contains("<script"));
    assert!(body.contains("id=\"login-form\""));
    assert!(body.contains("id=\"register-link\""));
    assert!(body.contains("id=\"google-login-link\""));
    assert!(body.contains("action=\"http://bff.test/login\""));
    // redirect_uri is untrusted (attacker-controllable query param), so it's
    // rendered through Tera's default HTML-escaping. Tera doesn't escape `/`,
    // but does escape `&`, `<`, `>`, `"` and `'`, which is sufficient to keep
    // it safely quoted inside this attribute value.
    assert!(body.contains("value=\"http://admin.test/\""));
    assert!(body.contains(
        "href=\"http://bff.test/oidc/google/login?redirect_uri=http%3A%2F%2Fadmin.test%2F"
    ));
}

#[tokio::test]
async fn login_page_falls_back_to_its_own_origin_when_redirect_uri_is_absent() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/login.html").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("value=\"http://login.test/\""));
}

#[tokio::test]
async fn login_page_ignores_host_and_x_forwarded_proto_headers() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/login.html")
                .header("host", "attacker.test")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("value=\"http://login.test/\""));
    assert!(!body.contains("attacker.test"));
}

#[tokio::test]
async fn login_page_shows_the_generic_error_message() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/login.html?error=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_string(resp).await;
    assert!(body.contains("Incorrect email or password."));
}

#[tokio::test]
async fn login_page_shows_the_link_failed_error_message() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/login.html?error=link_failed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_string(resp).await;
    assert!(body.contains("please sign in again"), "got {body}");
    assert!(!body.contains("Incorrect email or password."));
}

#[tokio::test]
async fn login_page_explains_a_declined_permission() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/login.html?error=consent_required")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_string(resp).await;
    assert!(body.contains("needs a permission you didn't grant"));
    assert!(!body.contains("Incorrect email or password."));
}

#[tokio::test]
async fn login_page_renders_the_confirm_link_form_when_email_is_present() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get(
                "/login.html?email=squatter%40example.com&redirect_uri=http%3A%2F%2Fadmin.test%2F",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();

    let body = body_string(resp).await;
    assert!(!body.contains("<script"));
    assert!(body.contains("id=\"confirm-link-form\""));
    assert!(body.contains("squatter@example.com"));
    assert!(body.contains("action=\"http://bff.test/oidc/confirm-link\""));
    assert!(!body.contains("id=\"login-form\""));
}

#[tokio::test]
async fn confirm_link_page_offers_the_password_and_each_linked_provider() {
    let body = get_body(
        test_config(),
        "/login.html?email=alice%40example.com&has_password=true&linked_providers=google%2Clinkedin&redirect_uri=http%3A%2F%2Fadmin.test%2F",
    )
    .await;

    assert!(body.contains("id=\"confirm-link-form\""));
    let next = "next=http%3A%2F%2Flogin.test%2Flogin.html%3Fredirect_uri%3Dhttp%253A%252F%252Fadmin.test%252F";
    for provider in ["google", "linkedin"] {
        let href = format!(
            "href=\"http://bff.test/oidc/{provider}/login?redirect_uri=http%3A%2F%2Fadmin.test%2F&{next}&confirm_link=true\""
        );
        assert!(body.contains(&href), "missing {href} in {body}");
    }
}

#[tokio::test]
async fn confirm_link_page_leaves_out_the_password_form_for_an_account_without_one() {
    let body = get_body(
        test_config(),
        "/login.html?email=alice%40example.com&has_password=false&linked_providers=google",
    )
    .await;

    assert!(!body.contains("id=\"confirm-link-form\""));
    assert!(body.contains("http://bff.test/oidc/google/login?"));
}

#[tokio::test]
async fn confirm_link_page_says_so_when_there_is_no_way_to_confirm() {
    let body = get_body(
        test_config(),
        "/login.html?email=alice%40example.com&has_password=false",
    )
    .await;

    assert!(body.contains("id=\"no-link-option\""));
    assert!(!body.contains("id=\"confirm-link-form\""));
}

#[tokio::test]
async fn confirm_link_page_only_offers_providers_bff_lists() {
    let config = config_with_stub_bff().await;
    let bff = config.bff_url.clone();
    let body = get_body(
        config,
        "/login.html?email=alice%40example.com&has_password=false&linked_providers=..%2F..%2Fx%2Cgoogle%2Cunknown",
    )
    .await;

    assert!(
        body.contains(&format!("{bff}/oidc/google/login?")),
        "got {body}"
    );
    assert!(!body.contains("/oidc/.."), "got {body}");
    assert!(!body.contains("unknown"), "got {body}");
}

#[tokio::test]
async fn confirm_link_page_names_providers_from_bff_not_the_url() {
    let body = get_body(
        config_with_stub_bff().await,
        "/login.html?email=alice%40example.com&provider=linkedin&has_password=false&linked_providers=linkedin%2Cgoogle",
    )
    .await;

    assert!(body.contains("link your LinkedIn sign-in"), "got {body}");
    assert!(body.contains("Continue with LinkedIn"), "got {body}");
    assert!(body.contains("Continue with Google"), "got {body}");
}

#[tokio::test]
async fn confirm_link_page_shows_no_text_for_an_unknown_provider() {
    let body = get_body(
        config_with_stub_bff().await,
        "/login.html?email=alice%40example.com&provider=Call%20support%20now&has_password=true",
    )
    .await;

    assert!(body.contains("link this sign-in"), "got {body}");
    assert!(!body.contains("Call support now"), "got {body}");
}

#[tokio::test]
async fn confirm_link_page_falls_back_to_plain_keys_when_bff_is_unreachable() {
    let config = Config {
        bff_url: "http://127.0.0.1:9".into(),
        ..test_config()
    };
    let body = get_body(
        config,
        "/login.html?email=alice%40example.com&provider=Call%20support%20now&has_password=false&linked_providers=google%2C..%2Fx",
    )
    .await;

    assert!(body.contains("Continue with google"), "got {body}");
    assert!(!body.contains("/oidc/../"), "got {body}");
    assert!(!body.contains("Call support now"), "got {body}");
}

#[tokio::test]
async fn provider_names_are_fetched_once_and_reused_across_renders() {
    let (bff, fetches) = counting_stub_bff(StatusCode::OK).await;
    let app = app(Config {
        bff_url: bff,
        ..test_config()
    });
    let path = "/login.html?email=alice%40example.com&provider=linkedin&has_password=true";

    for _ in 0..3 {
        let resp = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            body_string(resp)
                .await
                .contains("link your LinkedIn sign-in")
        );
    }

    assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failed_provider_lookup_is_not_retried_on_every_render() {
    let (bff, fetches) = counting_stub_bff(StatusCode::INTERNAL_SERVER_ERROR).await;
    let app = app(Config {
        bff_url: bff,
        ..test_config()
    });
    let path = "/login.html?email=alice%40example.com&has_password=false&linked_providers=google";

    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(body_string(resp).await.contains("Continue with google"));
    }

    assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn provider_names_come_from_the_internal_bff_url_when_set() {
    let config = Config {
        bff_internal_url: Some(stub_bff().await),
        ..test_config()
    };
    let body = get_body(
        config,
        "/login.html?email=alice%40example.com&has_password=false&linked_providers=linkedin",
    )
    .await;

    assert!(body.contains("Continue with LinkedIn"), "got {body}");
    // Links still go to the public URL.
    assert!(
        body.contains("http://bff.test/oidc/linkedin/login?"),
        "got {body}"
    );
}

#[tokio::test]
async fn serves_vendored_htmx() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/htmx.min.js").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn register_page_has_no_script_tags_and_bakes_in_bff_url() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/register.html?redirect_uri=http%3A%2F%2Fadmin.test%2F")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(!body.contains("<script"));
    assert!(body.contains("id=\"register-form\""));
    assert!(body.contains("id=\"google-login-link\""));
    assert!(body.contains("action=\"http://bff.test/register\""));
}

#[tokio::test]
async fn register_page_shows_the_taken_email_error_message() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/register.html?error=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_string(resp).await;
    assert!(body.contains("That email is already taken."));
}

#[tokio::test]
async fn register_page_explains_a_declined_permission() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/register.html?error=consent_required")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_string(resp).await;
    assert!(body.contains("needs a permission you didn't grant"));
    assert!(!body.contains("That email is already taken."));
}

#[tokio::test]
async fn serves_static_stylesheet() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/style.css").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_path_is_not_found() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn verify_email_page_has_a_code_form_and_a_resend_form_posting_to_bff() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get("/verify-email.html?redirect_uri=http%3A%2F%2Fadmin.test%2F%22%3E%3Cb%3E")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(!body.contains("<script"));
    assert!(body.contains("id=\"verify-form\""));
    assert!(body.contains("action=\"http://bff.test/verify-email\""));
    assert!(body.contains("name=\"code\""));
    // The code is all the user types: no password field, the session cookie carries the rest.
    assert!(!body.contains("type=\"password\""));
    assert!(body.contains("id=\"resend-form\""));
    assert!(body.contains("action=\"http://bff.test/verify-email/resend\""));
    // redirect_uri is attacker-controllable: it must not break out of its attribute.
    assert!(!body.contains("<b>"));
    assert!(body.contains("name=\"redirect_uri\" value=\"http://admin.test/&quot;&gt;&lt;b&gt;\""));
}

#[tokio::test]
async fn verify_email_page_reports_each_outcome() {
    for (status, marker, forms) in [
        ("invalid", "id=\"verify-invalid\"", true),
        ("sent", "id=\"verify-sent\"", true),
        ("cooling_down", "id=\"verify-cooling-down\"", true),
        ("locked", "id=\"verify-locked\"", false),
        (
            "locked_until_reset",
            "id=\"verify-locked-until-reset\"",
            false,
        ),
        ("code_used_up", "id=\"verify-code-used-up\"", true),
        ("session_expired", "id=\"verify-session-expired\"", false),
        ("", "id=\"verify-intro\"", true),
    ] {
        let resp = app(test_config())
            .oneshot(
                Request::get(format!("/verify-email.html?status={status}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = body_string(resp).await;
        assert!(body.contains(marker), "{status}: {body}");
        assert_eq!(body.contains("id=\"verify-form\""), forms, "{status}");
        // Signing in again can't lift a hard lock, so that page has no
        // sign-in link; a password reset can, so it links there instead.
        assert_eq!(
            body.contains("id=\"login-link\""),
            !forms && status != "locked_until_reset",
            "{status}: a page without forms offers signing in again, except when locked for good"
        );
        assert_eq!(
            body.contains("id=\"forgot-password-link\""),
            status == "locked_until_reset",
            "{status}"
        );
    }
}

#[tokio::test]
async fn verify_email_page_shows_a_lockout_in_minutes_and_the_code_validity() {
    for (query, expected) in [
        (
            "status=locked&retry_after=3600",
            "sign in again in 60 minutes",
        ),
        ("status=cooling_down&retry_after=300", "in 5 minutes."),
        ("status=sent&expires_in=900", "valid for 15 minutes"),
    ] {
        let resp = app(test_config())
            .oneshot(
                Request::get(format!("/verify-email.html?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = body_string(resp).await;
        assert!(body.contains(expected), "{query}: {body}");
    }
}

#[tokio::test]
async fn a_short_cooldown_gets_a_countdown_and_a_long_one_does_not() {
    for (retry_after, countdown) in [(42, true), (119, true), (120, false), (3600, false)] {
        let resp = app(test_config())
            .oneshot(
                Request::get(format!(
                    "/verify-email.html?status=cooling_down&retry_after={retry_after}"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();

        let body = body_string(resp).await;
        assert_eq!(
            body.contains(&format!("data-countdown=\"{retry_after}\"")),
            countdown,
            "{retry_after}: {body}"
        );
        // The only script is the same-origin file, and only with a countdown.
        assert_eq!(
            body.contains("<script src=\"/countdown.js\" defer></script>"),
            countdown,
            "{retry_after}"
        );
        assert_eq!(body.matches("<script").count(), usize::from(countdown));
        // Without the script the page still reads right.
        if countdown {
            assert!(
                body.contains(&format!(
                    "in <span class=\"countdown-number\">{retry_after}</span>"
                )),
                "{body}"
            );
            assert!(body.contains("class=\"countdown-ready\" hidden"), "{body}");
        }
    }
}

#[tokio::test]
async fn the_countdown_script_is_served() {
    let resp = app(test_config())
        .oneshot(Request::get("/countdown.js").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("data-countdown"));
}

#[tokio::test]
async fn pages_render_with_defaults_when_the_query_string_is_malformed() {
    for path in ["/login.html", "/register.html", "/verify-email.html"] {
        let resp = app(test_config())
            .oneshot(
                Request::get(format!("{path}?error=a&error=b"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK, "{path}");
    }
}

async fn get_body(config: Config, path: &str) -> String {
    let resp = app(config)
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    body_string(resp).await
}

#[tokio::test]
async fn verify_email_page_defaults_redirect_uri_to_the_configured_one() {
    let config = Config {
        email_link_default_redirect_uri: Some("http://app.test/home".into()),
        ..test_config()
    };

    let body = get_body(config.clone(), "/verify-email.html").await;
    assert!(body.contains("name=\"redirect_uri\" value=\"http://app.test/home\""));

    // An explicit redirect_uri still wins.
    let body = get_body(
        config,
        "/verify-email.html?redirect_uri=http%3A%2F%2Fadmin.test%2F",
    )
    .await;
    assert!(body.contains("name=\"redirect_uri\" value=\"http://admin.test/\""));
}

#[tokio::test]
async fn the_email_link_default_redirect_uri_does_not_apply_to_other_pages() {
    let config = Config {
        email_link_default_redirect_uri: Some("http://app.test/home".into()),
        ..test_config()
    };

    let body = get_body(config, "/login.html").await;
    assert!(body.contains("name=\"redirect_uri\" value=\"http://login.test/\""));
}

#[tokio::test]
async fn forgot_password_page_posts_the_email_to_bff_and_reports_each_status() {
    for (status, marker) in [
        ("", "id=\"forgot-intro\""),
        ("sent", "id=\"forgot-sent\""),
        ("invalid_token", "id=\"forgot-invalid-token\""),
    ] {
        let body = get_body(
            test_config(),
            &format!("/forgot-password.html?status={status}"),
        )
        .await;

        assert!(body.contains(marker), "{status}: {body}");
        assert!(
            body.contains("action=\"http://bff.test/password-reset/request\""),
            "{status}: {body}"
        );
    }
}

#[tokio::test]
async fn reset_password_page_posts_the_token_and_new_password_to_bff() {
    let body = get_body(test_config(), "/reset-password.html").await;

    assert!(
        body.contains("action=\"http://bff.test/password-reset/confirm\""),
        "{body}"
    );
    assert!(body.contains("name=\"token\""), "{body}");
    assert!(body.contains("name=\"new_password\""), "{body}");
    assert!(body.contains("minlength=\"8\""), "{body}");
    assert!(body.contains("maxlength=\"1024\""), "{body}");
    // The token arrives in the fragment, which only a script can read.
    assert!(body.contains("src=\"/reset-password.js\""), "{body}");
    assert!(body.contains("id=\"reset-intro\""), "{body}");

    let body = get_body(test_config(), "/reset-password.html?status=weak_password").await;
    assert!(body.contains("id=\"reset-weak-password\""), "{body}");
    // Covers too long as well as too short.
    assert!(!body.contains("too short"), "{body}");
}

#[tokio::test]
async fn reset_password_page_is_neither_cached_nor_named_in_a_referer() {
    let resp = app(test_config())
        .oneshot(
            Request::get("/reset-password.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    // Not `no-referrer`: under it the browser sends `Origin: null` on the
    // form's cross-origin POST, and bff's origin check refuses it.
    assert_eq!(resp.headers()["referrer-policy"], "strict-origin");
    assert_eq!(resp.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn reset_password_script_is_served() {
    let resp = app(test_config())
        .oneshot(
            Request::get("/reset-password.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let script = body_string(resp).await;
    assert!(script.contains("location.hash"), "{script}");
    // Survives a reload and a rejected password, which both drop the fragment.
    assert!(script.contains("sessionStorage"), "{script}");
}

#[tokio::test]
async fn login_page_links_to_forgot_password_and_confirms_a_reset() {
    let body = get_body(test_config(), "/login.html").await;
    assert!(body.contains("id=\"forgot-password-link\""), "{body}");
    assert!(!body.contains("id=\"login-password-reset\""), "{body}");

    let body = get_body(test_config(), "/login.html?status=password_reset").await;
    assert!(body.contains("id=\"login-password-reset\""), "{body}");
}

// The owner of a squatted address confirms the link with a password they
// don't know yet: the way out has to be right there.
#[tokio::test]
async fn confirm_link_page_offers_a_password_reset_next_to_the_password_form() {
    let body = get_body(
        test_config(),
        "/login.html?email=alice%40example.com&has_password=true",
    )
    .await;

    assert!(body.contains("id=\"forgot-password-link\""), "{body}");
}

// The reset link carries no redirect_uri, so the login page reached after a
// reset uses the same default as the verification page.
#[tokio::test]
async fn login_page_after_a_reset_defaults_redirect_uri_to_the_configured_one() {
    let config = Config {
        email_link_default_redirect_uri: Some("http://app.test/home".into()),
        ..test_config()
    };

    let body = get_body(config.clone(), "/login.html?status=password_reset").await;
    assert!(
        body.contains("name=\"redirect_uri\" value=\"http://app.test/home\""),
        "{body}"
    );

    let body = get_body(config, "/login.html").await;
    assert!(
        body.contains("name=\"redirect_uri\" value=\"http://login.test/\""),
        "{body}"
    );
}

// A finished or dead reset leaves no token behind in the tab.
#[tokio::test]
async fn the_pages_a_reset_ends_on_clear_the_stored_token() {
    const CLEAR: &str = "sessionStorage.removeItem(\"wa_reset_token\")";
    for (path, clears) in [
        ("/login.html?status=password_reset", true),
        ("/forgot-password.html?status=invalid_token", true),
        ("/login.html", false),
        ("/forgot-password.html?status=sent", false),
    ] {
        let body = get_body(test_config(), path).await;
        assert_eq!(body.contains(CLEAR), clears, "{path}: {body}");
    }
}

// The token only arrives through the script, so without one the form stays
// hidden behind a pointer back to the email.
#[tokio::test]
async fn reset_password_page_shows_the_form_only_once_the_script_has_a_token() {
    let body = get_body(test_config(), "/reset-password.html").await;
    // Hidden until the script finds no token, so a normal load doesn't flash it.
    assert!(body.contains("id=\"reset-no-token\" hidden"), "{body}");
    assert!(body.contains("<noscript>"), "{body}");
    assert!(body.contains("id=\"reset-form\" hidden"), "{body}");

    let resp = app(test_config())
        .oneshot(
            Request::get("/reset-password.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let script = body_string(resp).await;
    assert!(script.contains("reset-no-token"), "{script}");
    assert!(script.contains("reset-weak-password"), "{script}");
    assert!(script.contains("reset-intro"), "{script}");
    assert!(script.contains("reset-form"), "{script}");
}

#[tokio::test]
async fn forgot_password_page_defaults_redirect_uri_to_the_configured_one() {
    let config = Config {
        email_link_default_redirect_uri: Some("http://app.test/home".into()),
        ..test_config()
    };

    let body = get_body(config, "/forgot-password.html?status=invalid_token").await;
    assert!(
        body.contains("login.html?redirect_uri=http%3A%2F%2Fapp.test%2Fhome"),
        "{body}"
    );
}
