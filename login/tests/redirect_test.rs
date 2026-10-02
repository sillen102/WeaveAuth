use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use weaveauth_login::{Config, app};

fn test_config() -> Config {
    Config {
        port: 8081,
        bff_url: "http://bff.test".into(),
        own_origin: "http://login.test".into(),
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
    assert!(body.contains("please try Sign in with Google again"));
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
    }
}
