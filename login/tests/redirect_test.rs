use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use weaveauth_login::{app, Config};

fn test_config() -> Config {
    Config {
        port: 8081,
        bff_url: "http://bff.test".into(),
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
        .oneshot(
            Request::get("/login.html")
                .header("host", "login.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("value=\"http://login.test/\""));
}

#[tokio::test]
async fn login_page_shows_the_generic_error_message() {
    let app = app(test_config());

    let resp = app
        .oneshot(Request::get("/login.html?error=1").body(Body::empty()).unwrap())
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
async fn login_page_renders_the_confirm_link_form_when_a_pending_link_token_is_present() {
    let app = app(test_config());

    let resp = app
        .oneshot(
            Request::get(
                "/login.html?pending_link_token=tok-123&email=squatter%40example.com&redirect_uri=http%3A%2F%2Fadmin.test%2F",
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
    assert!(body.contains("value=\"tok-123\""));
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
        .oneshot(Request::get("/register.html?error=1").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = body_string(resp).await;
    assert!(body.contains("That email is already taken."));
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
