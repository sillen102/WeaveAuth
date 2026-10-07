//! The server-rendered pages: starting flows, rendering Kratos' nodes, the CSP.

mod common;

use common::*;
use serde_json::json;
use weaveauth_login::{Config, app, app_with_pages, app_with_templates};

async fn setup() -> (axum::Router, std::sync::Arc<StubState>) {
    let (url, state) = stub().await;
    (app(config(&url)).unwrap(), state)
}

#[tokio::test]
async fn login_with_a_challenge_starts_a_kratos_flow_through_this_host() {
    let (app, _) = setup().await;

    let reply = get(&app, "/login?login_challenge=chal%201").await;

    assert_eq!(reply.status, 303);
    assert_eq!(
        reply.header("location"),
        "/self-service/login/browser?login_challenge=chal+1"
    );
}

#[tokio::test]
async fn return_to_is_passed_through_when_starting_a_flow() {
    let (app, _) = setup().await;

    let reply = get(
        &app,
        "/login?login_challenge=c&return_to=https%3A%2F%2Fapp.test%2Fa%3Fb%3D1",
    )
    .await;

    assert_eq!(
        reply.header("location"),
        "/self-service/login/browser?login_challenge=c&return_to=https%3A%2F%2Fapp.test%2Fa%3Fb%3D1"
    );
}

#[tokio::test]
async fn registration_with_a_challenge_starts_a_registration_flow() {
    let (app, _) = setup().await;

    let reply = get(&app, "/registration?login_challenge=c").await;

    assert_eq!(reply.status, 303);
    assert_eq!(
        reply.header("location"),
        "/self-service/registration/browser?login_challenge=c"
    );
}

#[tokio::test]
async fn recovery_verification_and_settings_start_their_own_flows() {
    let (app, _) = setup().await;

    for page in ["recovery", "verification", "settings"] {
        let reply = get(
            &app,
            &format!("/{page}?return_to=https%3A%2F%2Fapp.test%2F"),
        )
        .await;
        assert_eq!(reply.status, 303, "{page}");
        assert_eq!(
            reply.header("location"),
            format!("/self-service/{page}/browser?return_to=https%3A%2F%2Fapp.test%2F"),
            "{page}"
        );
        let bare = get(&app, &format!("/{page}")).await;
        assert_eq!(
            bare.header("location"),
            format!("/self-service/{page}/browser"),
            "{page}"
        );
    }
}

#[tokio::test]
async fn login_and_registration_without_challenge_or_flow_go_to_bff_login() {
    let (url, _) = stub().await;
    let app = app(Config {
        default_redirect_uri: Some("https://app.test/home".into()),
        ..config(&url)
    })
    .unwrap();

    for page in ["login", "registration"] {
        let reply = get(&app, &format!("/{page}")).await;
        assert_eq!(reply.status, 303, "{page}");
        assert_eq!(
            reply.header("location"),
            "http://bff.test/login?redirect_uri=https%3A%2F%2Fapp.test%2Fhome",
            "{page}"
        );
    }

    let own = get(&app, "/login?redirect_uri=https%3A%2F%2Fother.test%2F").await;
    assert_eq!(
        own.header("location"),
        "http://bff.test/login?redirect_uri=https%3A%2F%2Fother.test%2F"
    );
}

#[tokio::test]
async fn without_any_redirect_target_the_page_is_an_error_not_a_loop() {
    let (app, _) = setup().await;

    let reply = get(&app, "/login").await;

    assert_eq!(reply.status, 400);
    assert!(reply.headers.get("location").is_none());
}

#[tokio::test]
async fn a_flow_is_fetched_with_the_browsers_cookie_and_rendered() {
    let (app, state) = setup().await;

    let reply = get_with_cookie(&app, "/login?flow=f1", "csrf_token_abc=xyz; other=1").await;

    assert_eq!(reply.status, 200);
    let fetched = state.requests("/self-service/login/flows");
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].path_and_query, "/self-service/login/flows?id=f1");
    assert_eq!(fetched[0].cookie(), Some("csrf_token_abc=xyz; other=1"));
    assert!(reply.body.contains("name=\"identifier\""), "{}", reply.body);
    assert!(
        reply
            .body
            .contains("<label for=\"f-default-identifier\">Email</label>")
    );
    assert!(reply.body.contains("name=\"method\" value=\"password\""));
    assert!(reply.body.contains("name=\"provider\" value=\"google\""));
    assert!(reply.body.contains("Sign in with Google"));
}

#[tokio::test]
async fn the_csrf_token_is_rendered_as_a_hidden_field() {
    let (app, _) = setup().await;

    let reply = get(&app, "/login?flow=f1").await;

    assert!(
        reply.body.contains(&format!(
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{CSRF}\">"
        )),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn forms_submit_to_a_path_on_this_host() {
    let (app, _) = setup().await;

    let reply = get(&app, "/login?flow=f1").await;

    // Kratos' action is absolute; the browser must post through this host's proxy.
    assert!(
        reply
            .body
            .contains("action=\"/self-service/login?flow=f1\""),
        "{}",
        reply.body
    );
    assert!(!reply.body.contains("http://login.test/self-service"));
}

#[tokio::test]
async fn a_form_only_has_the_groups_asked_for_plus_hidden_defaults() {
    let (url, _) = stub().await;
    let dir = tempfile_dir("groups");
    std::fs::write(
        dir.join("login.html"),
        r#"{% extends "layout.html" %}{% block page %}[{{ form(flow=flow, groups=["oidc"]) }}]{% endblock page %}"#,
    )
    .unwrap();
    let app = app_with_pages(config(&url), &format!("{}/*.html", dir.display())).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert!(reply.body.contains("name=\"provider\""));
    assert!(reply.body.contains("name=\"csrf_token\""));
    assert!(!reply.body.contains("name=\"identifier\""));
    assert!(!reply.body.contains("name=\"password\""));
}

const OIDC_ONLY_PAGE: &str = r#"{% extends "layout.html" %}{% block page %}{{ form(flow=flow, groups=["oidc"]) }}{% endblock page %}"#;

/// A pages directory with an oidc-only login page, and a providers directory holding `logos`.
fn templates_with_logos(name: &str, logos: &[(&str, &str)]) -> (String, std::path::PathBuf) {
    let root = tempfile_dir(name);
    let pages = root.join("pages");
    let providers = root.join("providers");
    std::fs::create_dir_all(&pages).unwrap();
    std::fs::create_dir_all(&providers).unwrap();
    std::fs::write(pages.join("login.html"), OIDC_ONLY_PAGE).unwrap();
    for (file, content) in logos {
        std::fs::write(providers.join(file), content).unwrap();
    }
    (format!("{}/*.html", pages.display()), providers)
}

#[tokio::test]
async fn a_deployers_provider_logo_is_shown_and_served() {
    let (url, _) = stub().await;
    let (pages, providers) = templates_with_logos("logos", &[("google.png", "png-bytes")]);
    let app = app_with_templates(config(&url), &pages, providers).unwrap();

    let page = get(&app, "/login?flow=f1").await;
    let logo = get(&app, "/providers/google.png").await;

    assert!(
        page.body.contains("src=\"/providers/google.png\""),
        "{}",
        page.body
    );
    assert_eq!(logo.status, 200);
    assert_eq!(logo.body, "png-bytes");
    assert_eq!(logo.header("cache-control"), "public, max-age=86400");
    assert_eq!(logo.header("x-content-type-options"), "nosniff");
}

#[tokio::test]
async fn a_provider_without_a_logo_file_gets_no_image() {
    let (url, _) = stub().await;
    let (pages, providers) = templates_with_logos("nologo", &[]);
    let app = app_with_templates(config(&url), &pages, providers).unwrap();

    let page = get(&app, "/login?flow=f1").await;

    assert!(page.body.contains("Sign in with Google"));
    assert!(!page.body.contains("<img"), "{}", page.body);
}

#[tokio::test]
async fn a_logo_is_matched_on_the_provider_id_exactly() {
    let (url, _) = stub().await;
    let (pages, providers) = templates_with_logos("logocase", &[("Google.png", "x")]);
    let app = app_with_templates(config(&url), &pages, providers).unwrap();

    let page = get(&app, "/login?flow=f1").await;

    assert!(!page.body.contains("<img"), "{}", page.body);
}

#[tokio::test]
async fn two_logos_for_one_provider_stop_startup() {
    let (url, _) = stub().await;
    let (pages, providers) =
        templates_with_logos("logodup", &[("google.png", "x"), ("google.webp", "x")]);

    let result = app_with_templates(config(&url), &pages, providers);

    assert!(result.is_err());
}

#[tokio::test]
async fn files_in_the_logo_directory_are_sandboxed_and_listings_are_not_served() {
    let (url, _) = stub().await;
    let (pages, providers) = templates_with_logos(
        "logosandbox",
        &[("evil.svg", "<svg><script>1</script></svg>")],
    );
    std::fs::create_dir_all(providers.join("sub")).unwrap();
    std::fs::write(providers.join("sub/index.html"), "<script>1</script>").unwrap();
    let app = app_with_templates(config(&url), &pages, providers).unwrap();

    let svg = get(&app, "/providers/evil.svg").await;
    let index = get(&app, "/providers/sub/").await;

    assert!(svg.header("content-security-policy").contains("sandbox"));
    assert_eq!(index.status, 404, "{}", index.body);
}

#[tokio::test]
async fn a_missing_logo_is_not_cached_publicly() {
    let (url, _) = stub().await;
    let (pages, providers) = templates_with_logos("logomissing", &[]);
    let app = app_with_templates(config(&url), &pages, providers).unwrap();

    let reply = get(&app, "/providers/missing.png").await;

    assert_eq!(reply.status, 404);
    assert!(
        reply
            .headers
            .get("cache-control")
            .is_none_or(|value| !value.to_str().unwrap().contains("public"))
    );
}

#[tokio::test]
async fn a_form_with_nothing_visible_renders_nothing() {
    let (url, _) = stub().await;
    let dir = tempfile_dir("empty");
    std::fs::write(
        dir.join("login.html"),
        r#"{% extends "layout.html" %}{% block page %}[{{ form(flow=flow, groups=["totp"]) }}]{% endblock page %}"#,
    )
    .unwrap();
    let app = app_with_pages(config(&url), &format!("{}/*.html", dir.display())).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert!(reply.body.contains("[]"), "{}", reply.body);
}

#[tokio::test]
async fn script_nodes_keep_their_integrity_and_get_logins_nonce() {
    let (app, _) = setup().await;

    let reply = get(&app, "/login?flow=f1").await;

    let nonce = reply.csp_nonce();
    assert!(!nonce.is_empty());
    let script = reply
        .body
        .split("<script")
        .find(|chunk| chunk.contains("webauthn.js"))
        .unwrap_or_else(|| panic!("no webauthn script in {}", reply.body));
    let tag = script.split("</script>").next().unwrap();
    assert!(tag.contains("integrity=\"sha512-INTEGRITY\""), "{tag}");
    assert!(tag.contains(&format!("nonce=\"{nonce}\"")), "{tag}");
    assert!(!tag.contains("kratos-nonce"), "{tag}");
    assert!(
        tag.contains("src=\"/.well-known/ory/webauthn.js\""),
        "{tag}"
    );
}

#[tokio::test]
async fn the_layout_script_gets_the_same_nonce() {
    let (app, _) = setup().await;

    let reply = get(&app, "/login?flow=f1").await;

    let nonce = reply.csp_nonce();
    assert!(
        reply
            .body
            .contains(&format!("<script src=\"/ui.js\" nonce=\"{nonce}\"")),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn every_page_gets_a_fresh_nonce() {
    let (app, _) = setup().await;

    let first = get(&app, "/login?flow=f1").await.csp_nonce();
    let second = get(&app, "/login?flow=f1").await.csp_nonce();

    assert_ne!(first, second);
    assert!(first.len() >= 16);
}

#[tokio::test]
async fn the_csp_allows_only_nonced_scripts_and_does_not_pin_form_actions() {
    let (app, _) = setup().await;

    let reply = get(&app, "/login?flow=f1").await;

    let csp = reply.header("content-security-policy");
    assert!(csp.contains("script-src 'nonce-"), "{csp}");
    assert!(!csp.contains("unsafe-inline"), "{csp}");
    assert!(!csp.contains("unsafe-eval"), "{csp}");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    // Chrome applies form-action to the redirect chain after the post, which ends at the provider.
    assert!(!csp.contains("form-action"), "{csp}");
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(reply.header("x-content-type-options"), "nosniff");
}

#[tokio::test]
async fn onclick_triggers_bind_through_data_attributes_never_inline_handlers() {
    let (app, _) = setup().await;

    let reply = get(&app, "/login?flow=f1").await;

    assert!(
        reply.body.contains("name=\"passkey_login_trigger\"")
            && reply.body.contains("data-wa-trigger=\"oryPasskeyLogin\""),
        "{}",
        reply.body
    );
    assert!(!reply.body.contains("onclick"), "{}", reply.body);
    assert!(
        !reply.body.contains("__oryPasskeyLogin()"),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn a_trigger_name_outside_the_known_set_is_not_rendered() {
    let (url, state) = stub().await;
    let mut flow = login_flow();
    flow["ui"]["nodes"][7]["attributes"]["onclickTrigger"] = json!("alert(document.cookie)");
    state.flow.lock().unwrap().1 = flow;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert!(
        !reply.body.contains("alert(document.cookie)"),
        "{}",
        reply.body
    );
    assert!(!reply.body.contains("data-wa-trigger"), "{}", reply.body);
}

#[tokio::test]
async fn onload_triggers_are_bound_the_same_way() {
    let (url, state) = stub().await;
    let mut flow = login_flow();
    flow["ui"]["nodes"][6]["attributes"]["onloadTrigger"] =
        json!("oryPasskeyLoginAutocompleteInit");
    state.flow.lock().unwrap().1 = flow;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert!(
        reply
            .body
            .contains("data-wa-onload=\"oryPasskeyLoginAutocompleteInit\""),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn messages_text_is_escaped() {
    let (url, state) = stub().await;
    let mut flow = login_flow();
    flow["ui"]["messages"] = json!([
        {"id": 4000006, "text": "<script>alert(1)</script> & \"quoted\"", "type": "error"}
    ]);
    state.flow.lock().unwrap().1 = flow;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert!(
        reply
            .body
            .contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quoted&quot;"),
        "{}",
        reply.body
    );
    assert!(!reply.body.contains("<script>alert(1)"), "{}", reply.body);
}

#[tokio::test]
async fn recovered_account_message_is_replaced_with_ours() {
    let (url, state) = stub().await;
    let mut flow = settings_flow("http://kratos.test/self-service/recovery?flow=r1");
    flow["ui"]["messages"] = json!([
        {"id": 1060001, "text": "You successfully recovered your account. Please change your password or set up an alternative login method (e.g. social sign in) within the next 15.00 minutes.", "type": "success"}
    ]);
    state.flow.lock().unwrap().1 = flow;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/settings?flow=f1").await;

    assert!(
        reply.body.contains("Your account is recovered."),
        "{}",
        reply.body
    );
    assert!(!reply.body.contains("social sign in"), "{}", reply.body);
}

fn settings_flow(request_url: &str) -> serde_json::Value {
    let mut flow = login_flow();
    flow["request_url"] = json!(request_url);
    flow["ui"]["nodes"].as_array_mut().unwrap().push(json!(
        {"type": "input", "group": "profile", "attributes": {"name": "traits.first_name", "type": "text", "value": "Ann", "disabled": false, "node_type": "input"}, "messages": [], "meta": {"label": {"id": 1, "text": "First name", "type": "info"}}}
    ));
    flow
}

#[tokio::test]
async fn settings_after_recovery_offers_only_the_password() {
    let (url, state) = stub().await;
    state.flow.lock().unwrap().1 =
        settings_flow("http://kratos.test/self-service/recovery?flow=r1");
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/settings?flow=f1").await;

    assert!(reply.body.contains("name=\"password\""), "{}", reply.body);
    for hidden in ["traits.first_name", "Sign in with Google", "passkey"] {
        assert!(!reply.body.contains(hidden), "{hidden}: {}", reply.body);
    }
}

#[tokio::test]
async fn settings_after_recovery_under_a_path_prefix_offers_only_the_password() {
    let (url, state) = stub().await;
    state.flow.lock().unwrap().1 =
        settings_flow("http://kratos.test/kratos/self-service/recovery?flow=r1");
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/settings?flow=f1").await;

    assert!(!reply.body.contains("traits.first_name"), "{}", reply.body);
}

#[tokio::test]
async fn settings_outside_recovery_offers_the_profile() {
    let (url, state) = stub().await;
    state.flow.lock().unwrap().1 = settings_flow(
        "http://kratos.test/self-service/settings/browser?return_to=/self-service/recovery",
    );
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/settings?flow=f1").await;

    assert!(reply.body.contains("traits.first_name"), "{}", reply.body);
    assert!(reply.body.contains("Sign in with Google"), "{}", reply.body);
}

#[tokio::test]
async fn node_attributes_labels_and_messages_are_escaped() {
    let (url, state) = stub().await;
    let mut flow = login_flow();
    let nodes = flow["ui"]["nodes"].as_array_mut().unwrap();
    nodes[1]["attributes"]["value"] = json!("\"><img src=x onerror=alert(1)>");
    nodes[1]["attributes"]["name"] = json!("id\" autofocus onfocus=\"alert(2)");
    nodes[1]["meta"]["label"]["text"] = json!("<b>Email</b>");
    nodes[1]["messages"] = json!([{"id": 1, "text": "<i>nope</i>", "type": "error"}]);
    state.flow.lock().unwrap().1 = flow;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert!(!reply.body.contains("<img src=x"), "{}", reply.body);
    assert!(!reply.body.contains("onfocus=\"alert"), "{}", reply.body);
    assert!(!reply.body.contains("<b>Email</b>"), "{}", reply.body);
    assert!(!reply.body.contains("<i>nope</i>"), "{}", reply.body);
    assert!(
        reply.body.contains("&lt;i&gt;nope&lt;/i&gt;"),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn link_and_image_nodes_only_take_safe_urls() {
    let (url, state) = stub().await;
    let mut flow = login_flow();
    let nodes = flow["ui"]["nodes"].as_array_mut().unwrap();
    nodes.push(json!({"type": "a", "group": "default", "attributes": {"href": "javascript:alert(1)", "title": {"id": 1, "text": "bad link", "type": "info"}, "id": "l1", "node_type": "a"}, "messages": [], "meta": {}}));
    nodes.push(json!({"type": "a", "group": "default", "attributes": {"href": "https://ok.test/x?a=1&b=2", "title": {"id": 1, "text": "good link", "type": "info"}, "id": "l2", "node_type": "a"}, "messages": [], "meta": {}}));
    nodes.push(json!({"type": "img", "group": "default", "attributes": {"src": "javascript:alert(1)", "id": "i1", "width": 10, "height": 10, "node_type": "img"}, "messages": [], "meta": {}}));
    nodes.push(json!({"type": "img", "group": "default", "attributes": {"src": "data:image/png;base64,AAAA", "id": "i2", "width": 10, "height": 10, "node_type": "img"}, "messages": [], "meta": {}}));
    nodes.push(json!({"type": "img", "group": "default", "attributes": {"src": "https://img.test/x.png", "id": "i3", "width": 10, "height": 10, "node_type": "img"}, "messages": [], "meta": {}}));
    nodes.push(json!({"type": "img", "group": "default", "attributes": {"src": "/static/logo.png", "id": "i4", "width": 10, "height": 10, "node_type": "img"}, "messages": [], "meta": {}}));
    nodes.push(json!({"type": "text", "group": "default", "attributes": {"text": {"id": 1050015, "text": "<em>secret</em>", "type": "info"}, "id": "t1", "node_type": "text"}, "messages": [], "meta": {}}));
    state.flow.lock().unwrap().1 = flow;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert!(!reply.body.contains("javascript:"), "{}", reply.body);
    assert!(reply.body.contains("bad link"));
    assert!(
        reply
            .body
            .contains("<a href=\"https://ok.test/x?a=1&amp;b=2\""),
        "{}",
        reply.body
    );
    assert!(
        reply
            .body
            .contains("<img src=\"data:image/png;base64,AAAA\""),
        "{}",
        reply.body
    );
    // The page's CSP only loads images from this host and data: URIs.
    assert!(!reply.body.contains("img.test"), "{}", reply.body);
    assert!(reply.body.contains("<img src=\"/static/logo.png\""));
    assert!(
        reply.body.contains("&lt;em&gt;secret&lt;/em&gt;"),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn the_login_page_links_to_registration_keeping_the_challenge() {
    let (app, _) = setup().await;

    let reply = get(&app, "/login?flow=f1").await;

    assert!(
        reply
            .body
            .contains("href=\"/registration?login_challenge=chal-1\""),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn every_flow_page_renders_its_flow() {
    let (app, state) = setup().await;

    for page in [
        "login",
        "registration",
        "recovery",
        "verification",
        "settings",
    ] {
        let reply = get(&app, &format!("/{page}?flow=f1")).await;
        assert_eq!(reply.status, 200, "{page}: {}", reply.body);
        assert!(reply.body.contains("name=\"csrf_token\""), "{page}");
        assert_eq!(
            state.requests(&format!("/self-service/{page}/flows")).len(),
            1,
            "{page}"
        );
    }
}

#[tokio::test]
async fn an_expired_flow_starts_over() {
    let (url, state) = stub().await;
    state.flow.lock().unwrap().0 = axum::http::StatusCode::GONE;
    let app = app(Config {
        default_redirect_uri: Some("https://app.test/".into()),
        ..config(&url)
    })
    .unwrap();

    let login = get(&app, "/login?flow=old").await;
    assert_eq!(login.status, 303);
    assert!(
        login
            .header("location")
            .starts_with("http://bff.test/login")
    );

    let recovery = get(&app, "/recovery?flow=old").await;
    assert_eq!(
        recovery.header("location"),
        "/self-service/recovery/browser"
    );
}

#[tokio::test]
async fn kratos_failing_gives_a_generic_error_page() {
    let (url, state) = stub().await;
    *state.flow.lock().unwrap() = (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        json!({"error": "db password is hunter2"}),
    );
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert_eq!(reply.status, 502);
    assert!(!reply.body.contains("hunter2"));
    assert!(!reply.body.contains(&url));
    assert!(reply.headers.get("content-security-policy").is_some());
}

#[tokio::test]
async fn an_unreachable_kratos_gives_a_generic_error_page() {
    let app = app(Config {
        kratos_public_url: "http://127.0.0.1:1".into(),
        ..config("http://127.0.0.1:1")
    })
    .unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert_eq!(reply.status, 502);
    assert!(!reply.body.contains("127.0.0.1"));
    assert!(!reply.body.to_lowercase().contains("refused"));
}

#[tokio::test]
async fn the_error_page_shows_kratos_errors_by_id() {
    let (app, state) = setup().await;

    let reply = get(&app, "/error?id=e1").await;

    assert_eq!(reply.status, 200);
    assert_eq!(
        state.requests("/self-service/errors")[0].path_and_query,
        "/self-service/errors?id=e1"
    );
    assert!(
        reply.body.contains("The request was not valid."),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn the_error_page_never_shows_kratos_free_text() {
    let (app, state) = setup().await;
    *state.error.lock().unwrap() = json!({"id": "e1", "error": {"code": 400, "status": "Bad Request",
        "reason": "Requested return_to URL \"x\" is not allowed. Call 0800-SCAM", "message": "Your account is locked"}});

    let reply = get(&app, "/error?id=e1").await;

    assert_eq!(reply.status, 200);
    assert!(!reply.body.contains("0800-SCAM"), "{}", reply.body);
    assert!(!reply.body.contains("account is locked"), "{}", reply.body);
    assert!(reply.body.contains("The request was not valid."));
}

#[tokio::test]
async fn an_unknown_kratos_error_code_gets_the_generic_text() {
    let (app, state) = setup().await;
    *state.error.lock().unwrap() =
        json!({"id": "e1", "error": {"code": 418, "reason": "teapot", "message": "teapot"}});

    let reply = get(&app, "/error?id=e1").await;

    assert!(!reply.body.contains("teapot"), "{}", reply.body);
    assert!(
        reply
            .body
            .contains("Something went wrong. Please try again.")
    );
}

#[tokio::test]
async fn the_error_page_never_echoes_hydras_query_text() {
    let (app, _) = setup().await;

    let reply = get(
        &app,
        "/error?error=access_denied&error_description=Call+0800-SCAM+to+unlock",
    )
    .await;

    assert!(!reply.body.contains("0800-SCAM"), "{}", reply.body);
    assert!(!reply.body.contains("access_denied"), "{}", reply.body);
}

#[tokio::test]
async fn a_deployers_page_extends_the_layout_and_keeps_its_scripts() {
    let (url, _) = stub().await;
    let dir = tempfile_dir("override");
    std::fs::write(
        dir.join("login.html"),
        r#"{% extends "layout.html" %}{% block page %}<h1>Custom skin</h1>{{ messages(flow=flow) }}{{ form(flow=flow) }}<script>steal()</script>{% endblock page %}"#,
    )
    .unwrap();
    let app = app_with_pages(config(&url), &format!("{}/*.html", dir.display())).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    let nonce = reply.csp_nonce();
    assert!(reply.body.contains("<h1>Custom skin</h1>"));
    assert!(
        reply
            .body
            .contains(&format!("<script src=\"/ui.js\" nonce=\"{nonce}\""))
    );
    assert!(reply.body.contains("webauthn.js"));
    // The deployer's own script has no nonce, so the CSP refuses to run it.
    assert!(reply.body.contains("<script>steal()</script>"));
    assert!(
        !reply
            .body
            .contains(&format!("<script nonce=\"{nonce}\">steal"))
    );
}

#[tokio::test]
async fn a_deployer_cannot_replace_the_layout() {
    let (url, _) = stub().await;
    let dir = tempfile_dir("layout");
    std::fs::write(
        dir.join("layout.html"),
        "<html>EVIL LAYOUT {% block page %}{% endblock page %}</html>",
    )
    .unwrap();
    std::fs::write(
        dir.join("login.html"),
        r#"{% extends "layout.html" %}{% block page %}mine{% endblock page %}"#,
    )
    .unwrap();
    let app = app_with_pages(config(&url), &format!("{}/*.html", dir.display())).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert!(!reply.body.contains("EVIL LAYOUT"), "{}", reply.body);
    assert!(reply.body.contains("/ui.js"));
}

#[tokio::test]
async fn the_page_templates_contain_no_script_or_inline_handlers() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../templates/pages");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap().to_lowercase();
        assert!(!text.contains("<script"), "{}", path.display());
        assert!(!text.contains("javascript:"), "{}", path.display());
        let has_handler = text
            .split(|c: char| c.is_whitespace())
            .any(|word| word.starts_with("on") && word.contains("=\""));
        assert!(!has_handler, "{}", path.display());
        assert!(!text.contains("style=\""), "{}", path.display());
        seen += 1;
    }
    assert!(seen >= 6, "expected the six page templates, found {seen}");
}

#[tokio::test]
async fn ui_js_is_served_and_only_knows_the_kratos_triggers() {
    let (app, _) = setup().await;

    let reply = get(&app, "/ui.js").await;

    assert_eq!(reply.status, 200);
    assert!(reply.header("content-type").starts_with("text/javascript"));
    for trigger in [
        "oryWebAuthnRegistration",
        "oryWebAuthnLogin",
        "oryPasskeyLogin",
        "oryPasskeyLoginAutocompleteInit",
        "oryPasskeyRegistration",
        "oryPasskeySettingsRegistration",
    ] {
        assert!(reply.body.contains(trigger), "{trigger}");
    }
    assert!(!reply.body.contains("eval("));
}

#[tokio::test]
async fn static_files_are_served_and_the_old_shell_is_gone() {
    let (app, _) = setup().await;

    assert_eq!(get(&app, "/static/style.css").await.status, 200);
    for gone in [
        "/",
        "/index.html",
        "/htmx.min.js",
        "/static/htmx.min.js",
        "/static/countdown.js",
        "/static/reset-password.js",
        "/login.html",
    ] {
        assert_eq!(get(&app, gone).await.status, 404, "{gone}");
    }
}

pub fn tempfile_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wa-login-test-{}-{name}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn scripts_pointing_off_this_host_are_not_rendered() {
    let (url, state) = stub().await;
    let mut flow = login_flow();
    flow["ui"]["nodes"][8]["attributes"]["src"] = json!("https://evil.test/webauthn.js");
    state.flow.lock().unwrap().1 = flow;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert_eq!(reply.status, 200);
    assert!(!reply.body.contains("evil.test"), "{}", reply.body);
    assert!(!reply.body.contains("webauthn.js"), "{}", reply.body);
    assert!(reply.body.contains("name=\"csrf_token\""));
}

#[tokio::test]
async fn a_form_posting_off_this_host_is_an_error_not_a_dead_form() {
    let (url, state) = stub().await;
    let mut flow = login_flow();
    flow["ui"]["action"] = json!("https://evil.test/collect?flow=f1");
    state.flow.lock().unwrap().1 = flow;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert_eq!(reply.status, 500);
    assert!(!reply.body.contains("evil.test"), "{}", reply.body);
    assert!(!reply.body.contains("<form"), "{}", reply.body);
}

#[tokio::test]
async fn a_flow_the_browser_cannot_use_starts_over() {
    let (url, state) = stub().await;
    state.flow.lock().unwrap().0 = axum::http::StatusCode::FORBIDDEN;
    let app = app(config(&url)).unwrap();

    // A CSRF mismatch (the flow link opened in another browser) is a restart, not an outage.
    let reply = get(&app, "/recovery?flow=other-browsers").await;

    assert_eq!(reply.status, 303);
    assert_eq!(reply.header("location"), "/self-service/recovery/browser");
}

#[tokio::test]
async fn settings_without_a_session_goes_to_sign_in() {
    let (url, state) = stub().await;
    state.flow.lock().unwrap().0 = axum::http::StatusCode::UNAUTHORIZED;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/settings?flow=f1").await;

    assert_eq!(reply.status, 303);
    assert_eq!(reply.header("location"), "/login");
}

#[tokio::test]
async fn other_flow_failures_stay_an_outage() {
    let (url, state) = stub().await;
    state.flow.lock().unwrap().0 = axum::http::StatusCode::UNAUTHORIZED;
    let app = app(config(&url)).unwrap();

    // Only settings needs a session; a 401 anywhere else is Kratos misbehaving.
    let reply = get(&app, "/recovery?flow=f1").await;

    assert_eq!(reply.status, 303);
    assert_eq!(reply.header("location"), "/self-service/recovery/browser");
}

#[tokio::test]
async fn the_or_divider_is_only_there_with_social_sign_in() {
    let (url, state) = stub().await;
    let app = app(config(&url)).unwrap();

    for page in ["/login?flow=f1", "/registration?flow=f1"] {
        assert!(
            get(&app, page).await.body.contains("class=\"divider\""),
            "{page}"
        );
    }

    let mut flow = login_flow();
    flow["ui"]["nodes"]
        .as_array_mut()
        .unwrap()
        .retain(|node| node["group"] != "oidc");
    state.flow.lock().unwrap().1 = flow;
    for page in ["/login?flow=f1", "/registration?flow=f1"] {
        let reply = get(&app, page).await;
        assert!(
            !reply.body.contains("class=\"divider\""),
            "{page}: {}",
            reply.body
        );
        assert!(reply.body.contains("name=\"password\""), "{page}");
    }
}

#[tokio::test]
async fn input_ids_are_unique_across_the_forms_of_a_page() {
    let (url, state) = stub().await;
    let mut flow = login_flow();
    let nodes = flow["ui"]["nodes"].as_array_mut().unwrap();
    nodes.push(json!({"type": "input", "group": "passkey", "attributes": {"name": "identifier", "type": "text", "value": "", "disabled": false, "node_type": "input"}, "messages": [], "meta": {"label": {"id": 1, "text": "Name", "type": "info"}}}));
    state.flow.lock().unwrap().1 = flow;
    let app = app(config(&url)).unwrap();

    let reply = get(&app, "/login?flow=f1").await;

    assert!(
        reply.body.contains("id=\"f-default-identifier\""),
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains("for=\"f-default-identifier\""),
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains("id=\"f-passkey-identifier\""),
        "{}",
        reply.body
    );
    assert!(
        !reply.body.contains("id=\"f-identifier\""),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn links_must_be_https_when_this_host_is() {
    let (url, state) = stub().await;
    let mut flow = login_flow();
    flow["ui"]["action"] = json!("https://login.test/self-service/login?flow=f1");
    let nodes = flow["ui"]["nodes"].as_array_mut().unwrap();
    nodes.push(json!({"type": "a", "group": "default", "attributes": {"href": "http://plain.test/x", "title": {"id": 1, "text": "plain link", "type": "info"}, "id": "l1", "node_type": "a"}, "messages": [], "meta": {}}));
    nodes.push(json!({"type": "a", "group": "default", "attributes": {"href": "https://ok.test/x", "title": {"id": 1, "text": "secure link", "type": "info"}, "id": "l2", "node_type": "a"}, "messages": [], "meta": {}}));
    nodes.push(json!({"type": "a", "group": "default", "attributes": {"href": "/local", "title": {"id": 1, "text": "local link", "type": "info"}, "id": "l3", "node_type": "a"}, "messages": [], "meta": {}}));
    state.flow.lock().unwrap().1 = flow;
    let secure = app(Config {
        own_origin: "https://login.test".into(),
        ..config(&url)
    })
    .unwrap();
    let dev = app(config(&url)).unwrap();

    let reply = get(&secure, "/login?flow=f1").await;
    assert!(!reply.body.contains("plain.test"), "{}", reply.body);
    assert!(reply.body.contains("<a href=\"https://ok.test/x\""));
    assert!(reply.body.contains("<a href=\"/local\""));
    assert!(reply.body.contains("plain link"));

    state.flow.lock().unwrap().1["ui"]["action"] =
        json!("http://login.test/self-service/login?flow=f1");
    assert!(
        get(&dev, "/login?flow=f1")
            .await
            .body
            .contains("<a href=\"http://plain.test/x\"")
    );
}

#[tokio::test]
async fn templates_are_read_once_at_startup() {
    let (url, _) = stub().await;
    let dir = tempfile_dir("once");
    let page = dir.join("login.html");
    std::fs::write(
        &page,
        r#"{% extends "layout.html" %}{% block page %}first{% endblock page %}"#,
    )
    .unwrap();
    let app = app_with_pages(config(&url), &format!("{}/*.html", dir.display())).unwrap();
    assert!(get(&app, "/login?flow=f1").await.body.contains("first"));

    std::fs::write(
        &page,
        r#"{% extends "layout.html" %}{% block page %}second{% endblock page %}"#,
    )
    .unwrap();

    assert!(get(&app, "/login?flow=f1").await.body.contains("first"));
}

#[tokio::test]
async fn a_broken_template_stops_startup() {
    let (url, _) = stub().await;
    let dir = tempfile_dir("broken");
    std::fs::write(dir.join("login.html"), "{% block page %}").unwrap();

    let result = app_with_pages(config(&url), &format!("{}/*.html", dir.display()));

    assert!(result.is_err());
}

#[tokio::test]
async fn health_answers_without_touching_kratos() {
    let (app, state) = setup().await;

    let reply = get(&app, "/health").await;

    assert_eq!(reply.status, 200);
    assert!(state.all().is_empty());
}

fn continuation_flow() -> serde_json::Value {
    let mut flow = login_flow();
    flow["ui"]["action"] = "http://login.test/self-service/registration?flow=f1".into();
    flow["ui"]["nodes"] = serde_json::json!([
        {"type": "input", "group": "oidc", "attributes": {"name": "provider", "type": "submit", "value": "google", "disabled": false, "node_type": "input"}, "messages": [], "meta": {"label": {"id": 1040003, "text": "Continue", "type": "info"}}},
        {"type": "input", "group": "default", "attributes": {"name": "csrf_token", "type": "hidden", "value": "tok", "required": true, "disabled": false, "node_type": "input"}, "messages": [], "meta": {}},
        {"type": "input", "group": "default", "attributes": {"name": "traits.email", "type": "email", "value": "a@b.test", "required": true, "disabled": false, "node_type": "input"}, "messages": [], "meta": {"label": {"id": 1070002, "text": "Email", "type": "info"}}},
        {"type": "input", "group": "default", "attributes": {"name": "traits.last_name", "type": "text", "required": true, "disabled": false, "node_type": "input"}, "messages": [{"id": 4000002, "text": "Property last_name is missing.", "type": "error"}], "meta": {"label": {"id": 1070002, "text": "Last name", "type": "info"}}}
    ]);
    flow
}

#[tokio::test]
async fn continuing_a_social_sign_up_posts_the_traits_with_the_button() {
    let (url, state) = stub().await;
    let app = app(config(&url)).unwrap();
    state.flow.lock().unwrap().1 = continuation_flow();

    let reply = get(&app, "/registration?flow=f1").await;

    let form = reply
        .body
        .split("<form")
        .find(|form| form.contains("name=\"provider\""))
        .expect("the continue button");
    assert!(form.contains("name=\"traits.last_name\""), "{}", reply.body);
    assert!(form.contains("name=\"csrf_token\""), "{}", reply.body);
    // The provider's address is not an input: Kratos keeps it.
    assert!(!reply.body.contains("traits.email"), "{}", reply.body);
}

#[tokio::test]
async fn continuing_shows_a_prefilled_field_the_flow_complains_about() {
    let (url, state) = stub().await;
    let app = app(config(&url)).unwrap();
    let mut flow = continuation_flow();
    flow["ui"]["nodes"][2]["messages"] = serde_json::json!([
        {"id": 4000003, "text": "length must be <= 100", "type": "error"}
    ]);
    state.flow.lock().unwrap().1 = flow;

    let reply = get(&app, "/registration?flow=f1").await;

    assert!(
        reply.body.contains("name=\"traits.email\""),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn a_plain_registration_keeps_the_social_button_apart_from_the_traits() {
    let (app, _) = setup().await;

    let reply = get(&app, "/registration?flow=f1").await;

    let form = reply
        .body
        .split("<form")
        .find(|form| form.contains("name=\"provider\""))
        .expect("the social button");
    assert!(!form.contains("name=\"password\""), "{}", reply.body);
    assert!(
        reply
            .body
            .split("<form")
            .any(|form| form.contains("name=\"password\"")),
        "{}",
        reply.body
    );
}
