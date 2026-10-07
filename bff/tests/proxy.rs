//! The proxy: session cookie to bearer token, header filtering, caching rules, CORS.

mod support;

use axum::body::Body;
use axum::extract::{Path, Query};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use support::{Bff, Session, api_route, cookie_pair, location, query_of};
use uuid::Uuid;
use weaveauth_bff::config::RouteConfig;

const SUB: Uuid = Uuid::from_u128(0x5b1d3d0e_3a49_4a8f_9f43_1d1f0e0a7b11);

async fn stub_upstream() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route(
            "/whoami/{id}",
            get(
                |Path(id): Path<String>, headers: axum::http::HeaderMap| async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let has_cookie = headers.contains_key("cookie");
                    format!("id={id} auth={auth} cookie={has_cookie}")
                },
            ),
        )
        .route("/headers", get(echo_headers).post(echo_headers))
        .route(
            "/cache-control",
            get(
                |Query(query): Query<std::collections::HashMap<String, String>>| async move {
                    ([("cache-control", query["value"].clone())], "body")
                },
            ),
        )
        .route(
            "/every-header",
            get(|| async {
                (
                    [
                        ("content-type", "text/plain"),
                        ("content-disposition", "attachment"),
                        ("content-encoding", "identity"),
                        ("content-security-policy", "sandbox"),
                        ("cache-control", "private"),
                        ("x-content-type-options", "bogus"),
                        ("set-cookie", "wa_session=fixated; Path=/"),
                        ("clear-site-data", "\"cookies\""),
                        ("service-worker-allowed", "/"),
                        (
                            "strict-transport-security",
                            "max-age=63072000; includeSubDomains",
                        ),
                        ("alt-svc", "h3=\"evil.test:443\""),
                        ("x-upstream", "anything"),
                        ("location", "/elsewhere"),
                        ("vary", "accept-language"),
                        ("etag", "\"v1\""),
                        ("last-modified", "Tue, 15 Nov 1994 12:45:26 GMT"),
                        ("www-authenticate", "Bearer realm=\"api\""),
                        ("retry-after", "120"),
                    ],
                    "body",
                )
            }),
        )
        .fallback(|uri: axum::http::Uri| async move { format!("path={}", uri.path()) });
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((format!("http://{addr}"), handle))
}

async fn echo_headers(
    headers: axum::http::HeaderMap,
) -> Json<std::collections::BTreeMap<String, Vec<String>>> {
    let mut seen = std::collections::BTreeMap::<String, Vec<String>>::new();
    for (name, value) in &headers {
        seen.entry(name.to_string())
            .or_default()
            .push(value.to_str().unwrap_or("<binary>").to_string());
    }
    Json(seen)
}

/// bff with `routes` proxied, and a logged-in session.
async fn bff_with_session(routes: Vec<RouteConfig>) -> (Bff, Session) {
    let bff = Bff::start_with(|config| config.routes = routes).await;
    let session = bff.login(SUB, Some("sid-1")).await;
    (bff, session)
}

#[tokio::test]
async fn proxies_authenticated_request_swapping_cookie_for_bearer_token() -> anyhow::Result<()> {
    let (upstream, _uh) = stub_upstream().await?;
    let (bff, session) = bff_with_session(vec![api_route(upstream)]).await;

    let resp = bff.get("/api/whoami/42", Some(&session.cookie)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    assert_eq!(
        String::from_utf8(body.to_vec())?,
        "id=42 auth=Bearer access-1 cookie=false"
    );
    Ok(())
}

#[tokio::test]
async fn missing_session_cookie_is_unauthorized() -> anyhow::Result<()> {
    let (bff, _session) = bff_with_session(vec![api_route("http://unused.test".into())]).await;

    let resp = bff.get("/api/whoami/42", None).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn unknown_session_cookie_is_unauthorized() -> anyhow::Result<()> {
    let (bff, _session) = bff_with_session(vec![api_route("http://unused.test".into())]).await;

    let resp = bff
        .get("/api/whoami/42", Some("wa_session=does-not-exist"))
        .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn longest_matching_prefix_wins() -> anyhow::Result<()> {
    let (general_upstream, _gh) = stub_upstream().await?;
    let (specific_upstream, _sh) = stub_upstream().await?;
    let routes = vec![
        RouteConfig {
            path_prefix: "/api".into(),
            upstream_url: general_upstream,
        },
        RouteConfig {
            path_prefix: "/api/v2".into(),
            upstream_url: specific_upstream,
        },
    ];
    let (bff, session) = bff_with_session(routes).await;

    let resp = bff.get("/api/v2/whoami/1", Some(&session.cookie)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let body = String::from_utf8(body.to_vec())?;
    // Only reachable if the /api/v2 route (not the shorter /api one) matched --
    // both upstream stub servers use the same handler, so this just confirms we
    // got a valid response through the more specific prefix instead of a 404
    // from the general one having a different path shape once stripped.
    assert!(body.starts_with("id=1 "));
    Ok(())
}

#[tokio::test]
async fn query_string_is_forwarded_to_upstream() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let upstream_router = Router::new().route(
        "/echo",
        get(|uri: axum::http::Uri| async move { uri.query().unwrap_or("").to_string() }),
    );
    let _uh = tokio::spawn(async move {
        let _ = axum::serve(listener, upstream_router).await;
    });
    let (bff, session) = bff_with_session(vec![api_route(format!("http://{addr}"))]).await;

    let resp = bff
        .get("/api/echo?foo=bar&baz=1", Some(&session.cookie))
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    assert_eq!(String::from_utf8(body.to_vec())?, "foo=bar&baz=1");
    Ok(())
}

#[tokio::test]
async fn request_body_is_forwarded_to_upstream() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let upstream_router = Router::new().route(
        "/echo",
        axum::routing::post(|body: String| async move { body }),
    );
    let _uh = tokio::spawn(async move {
        let _ = axum::serve(listener, upstream_router).await;
    });
    let (bff, session) = bff_with_session(vec![api_route(format!("http://{addr}"))]).await;

    let resp = bff
        .send(
            Request::post("/api/echo")
                .header("cookie", &session.cookie)
                .header("origin", "http://app.test")
                .body(Body::from("hello upstream"))?,
        )
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    assert_eq!(String::from_utf8(body.to_vec())?, "hello upstream");
    Ok(())
}

#[tokio::test]
async fn unmatched_path_is_not_found() -> anyhow::Result<()> {
    let bff = Bff::start().await;

    let resp = bff.get("/no-such-route", None).await;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn health_is_exempt_from_rate_limiting() -> anyhow::Result<()> {
    // /health has no bucket at all -- infra that polls it shouldn't get
    // caught by a limit meant for auth abuse or proxy flooding.
    let bff = Bff::start_with(|config| config.rate_limit_max_attempts = 1).await;

    for _ in 0..5 {
        let resp = bff.get("/health", None).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    Ok(())
}

#[tokio::test]
async fn proxy_rate_limit_is_independent_from_the_auth_bucket() -> anyhow::Result<()> {
    // Hammering the proxy fallback shouldn't burn /login's budget, and vice
    // versa -- they're separate buckets, each sized by its own setting.
    let bff = Bff::start_with(|config| {
        config.rate_limit_max_attempts = 1;
        config.rate_limit_proxy_max_attempts = 2;
    })
    .await;

    assert_eq!(
        bff.get("/no-such-route", None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        bff.get("/no-such-route", None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        bff.get("/no-such-route", None).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // The proxy bucket being exhausted doesn't touch /login's separate one.
    let login = bff.start_login("http://app.test/").await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    Ok(())
}

/// Sends `req` (with the session cookie added) through a proxy app routing
/// `/api` to the stub upstream, returning the response.
async fn through_proxy(
    req: axum::http::request::Builder,
) -> anyhow::Result<axum::response::Response> {
    send_to_app(req, true).await
}

/// Sends `req` to an app with `/api` routed to the stub upstream, with or without the
/// session cookie.
async fn send_to_app(
    req: axum::http::request::Builder,
    with_session: bool,
) -> anyhow::Result<axum::response::Response> {
    let (upstream, _uh) = stub_upstream().await?;
    let (bff, session) = bff_with_session(vec![api_route(upstream)]).await;
    let req = if with_session {
        req.header("cookie", &session.cookie)
    } else {
        req
    };
    Ok(bff.send(req.body(Body::empty())?).await)
}

#[tokio::test]
async fn only_allowlisted_headers_and_the_bearer_token_reach_the_upstream() -> anyhow::Result<()> {
    let mut req = Request::get("/api/headers");
    for (name, value) in [
        ("content-type", "application/json"),
        ("accept", "application/json"),
        ("accept-language", "sv"),
        ("if-match", "\"v1\""),
        ("if-none-match", "\"v1\""),
        ("if-modified-since", "Tue, 15 Nov 1994 12:45:26 GMT"),
        ("if-unmodified-since", "Tue, 15 Nov 1994 12:45:26 GMT"),
        ("user-agent", "test"),
        ("x-request-id", "req-1"),
        ("x-forwarded-for", "6.6.6.6"),
        ("forwarded", "for=6.6.6.6"),
        ("x-forwarded-host", "evil.test"),
        ("x-real-ip", "6.6.6.6"),
        ("x-original-url", "/admin"),
        ("authorization", "Bearer forged"),
        ("connection", "Upgrade, authorization, content-type"),
        ("upgrade", "websocket"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("sec-websocket-version", "13"),
    ] {
        req = req.header(name, value);
    }
    let resp = through_proxy(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let seen: std::collections::BTreeMap<String, Vec<String>> = serde_json::from_slice(&body)?;

    assert_eq!(
        seen.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "accept",
            "accept-language",
            "authorization",
            "content-type",
            "host",
            "if-match",
            "if-modified-since",
            "if-none-match",
            "if-unmodified-since",
        ]
    );
    assert_eq!(seen["authorization"], ["Bearer access-1"]);
    assert_eq!(seen["content-type"], ["application/json"]);
    Ok(())
}

#[tokio::test]
async fn a_post_from_a_trusted_origin_or_bff_itself_is_forwarded() -> anyhow::Result<()> {
    for origin in ["http://app.test", "http://bff.test"] {
        let resp = through_proxy(Request::post("/api/headers").header("origin", origin)).await?;
        assert_eq!(resp.status(), StatusCode::OK, "{origin}");
    }
    Ok(())
}

#[tokio::test]
async fn a_post_from_another_origin_is_forbidden() -> anyhow::Result<()> {
    let resp =
        through_proxy(Request::post("/api/headers").header("origin", "https://evil.test")).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp =
        through_proxy(Request::post("/api/headers").header("referer", "https://evil.test/page"))
            .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn every_non_safe_method_naming_no_origin_is_forbidden() -> anyhow::Result<()> {
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let resp = through_proxy(Request::builder().method(method).uri("/api/headers")).await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method}");
    }
    Ok(())
}

#[tokio::test]
async fn safe_methods_need_no_origin() -> anyhow::Result<()> {
    for method in ["GET", "HEAD"] {
        let resp = through_proxy(Request::builder().method(method).uri("/api/headers")).await?;
        assert_eq!(resp.status(), StatusCode::OK, "{method}");
    }
    Ok(())
}

#[tokio::test]
async fn only_allowlisted_upstream_headers_reach_the_browser() -> anyhow::Result<()> {
    let resp = through_proxy(Request::get("/api/every-header")).await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let mut names: Vec<_> = resp.headers().keys().map(|name| name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            // The CORS layer's, on every response, even one without an `Origin`.
            "access-control-allow-credentials",
            "access-control-expose-headers",
            "cache-control",
            "content-disposition",
            "content-encoding",
            "content-security-policy",
            "content-type",
            "etag",
            "last-modified",
            "location",
            "retry-after",
            "vary",
            "www-authenticate",
            "x-content-type-options",
        ]
    );
    assert_eq!(resp.headers()["content-security-policy"], "sandbox");
    assert_eq!(resp.headers()["location"], "/elsewhere");
    assert!(
        resp.headers()
            .get_all("vary")
            .iter()
            .any(|value| value == "accept-language")
    );
    assert_eq!(resp.headers()["cache-control"], "private");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    assert_eq!(&body[..], b"body");
    Ok(())
}

#[tokio::test]
async fn a_proxied_response_without_caching_rules_is_not_stored() -> anyhow::Result<()> {
    let resp = through_proxy(Request::get("/api/headers")).await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    Ok(())
}

/// The `Cache-Control` the browser gets when the upstream sends `upstream`.
async fn cache_control_through_proxy(upstream: &str) -> anyhow::Result<String> {
    let uri = format!(
        "/api/cache-control?value={}",
        percent_encoding::utf8_percent_encode(upstream, percent_encoding::NON_ALPHANUMERIC)
    );
    let resp = through_proxy(Request::get(uri)).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let values: Vec<&str> = resp
        .headers()
        .get_all("cache-control")
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<_, _>>()?;
    Ok(values.join(", "))
}

#[tokio::test]
async fn a_cacheable_proxied_response_is_kept_out_of_shared_caches() -> anyhow::Result<()> {
    for upstream in [
        "max-age=60",
        "max-age=60, must-revalidate",
        "max-age=60, private=\"x-foo\"",
    ] {
        assert_eq!(
            cache_control_through_proxy(upstream).await?,
            format!("{upstream}, private")
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_upstream_that_settles_shared_caching_is_left_alone() -> anyhow::Result<()> {
    for upstream in [
        "public, max-age=60",
        "max-age=60, S-MAXAGE=30",
        "private",
        "no-store",
    ] {
        assert_eq!(cache_control_through_proxy(upstream).await?, upstream);
    }
    Ok(())
}

fn preflight(origin: &str) -> axum::http::request::Builder {
    Request::options("/api/headers")
        .header("origin", origin)
        .header("access-control-request-method", "PUT")
        .header("access-control-request-headers", "content-type,x-custom")
}

fn header<'a>(resp: &'a axum::response::Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn a_preflight_from_a_trusted_origin_is_answered_without_a_session() -> anyhow::Result<()> {
    for origin in ["http://app.test", "http://bff.test"] {
        let resp = send_to_app(preflight(origin), false).await?;

        assert!(resp.status().is_success(), "{origin}: {}", resp.status());
        assert_eq!(header(&resp, "access-control-allow-origin"), Some(origin));
        assert_eq!(
            header(&resp, "access-control-allow-credentials"),
            Some("true")
        );
        assert_eq!(header(&resp, "access-control-allow-methods"), Some("PUT"));
        assert!(header(&resp, "access-control-max-age").is_some());
    }
    Ok(())
}

#[tokio::test]
async fn a_preflight_from_another_origin_is_not_allowed() -> anyhow::Result<()> {
    let resp = send_to_app(preflight("https://evil.test"), false).await?;

    // Answered by bff: proxied, it would get 401 (no session).
    assert!(resp.status().is_success(), "{}", resp.status());
    assert_eq!(header(&resp, "access-control-allow-origin"), None);
    Ok(())
}

#[tokio::test]
async fn a_preflight_may_only_ask_for_headers_bff_forwards() -> anyhow::Result<()> {
    let resp = send_to_app(preflight("http://app.test"), false).await?;

    let allowed: Vec<_> = header(&resp, "access-control-allow-headers")
        .unwrap()
        .split(',')
        .collect();
    for forwarded in [
        "content-type",
        "accept",
        "accept-language",
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
    ] {
        assert!(allowed.contains(&forwarded), "{forwarded} in {allowed:?}");
    }
    assert!(!allowed.contains(&"x-custom"), "{allowed:?}");
    Ok(())
}

#[tokio::test]
async fn any_options_is_answered_by_bff_without_a_session_or_the_upstream() -> anyhow::Result<()> {
    for path in ["/api/headers", "/no-such-route"] {
        for with_session in [false, true] {
            let resp = send_to_app(Request::options(path), with_session).await?;

            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{path}, session: {with_session}"
            );
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
            assert!(body.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn proxied_responses_carry_cors_headers_for_a_trusted_origin_only() -> anyhow::Result<()> {
    let resp =
        through_proxy(Request::get("/api/headers").header("origin", "http://app.test")).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        header(&resp, "access-control-allow-origin"),
        Some("http://app.test")
    );
    assert_eq!(
        header(&resp, "access-control-allow-credentials"),
        Some("true")
    );

    let resp =
        through_proxy(Request::get("/api/headers").header("origin", "https://evil.test")).await?;
    assert_eq!(header(&resp, "access-control-allow-origin"), None);
    Ok(())
}

#[tokio::test]
async fn an_unauthenticated_request_still_carries_cors_headers() -> anyhow::Result<()> {
    let resp = send_to_app(
        Request::get("/api/headers").header("origin", "http://app.test"),
        false,
    )
    .await?;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        header(&resp, "access-control-allow-origin"),
        Some("http://app.test")
    );
    Ok(())
}

#[tokio::test]
async fn form_routes_get_no_cors_headers() -> anyhow::Result<()> {
    let resp = send_to_app(preflight("http://app.test").uri("/login"), false).await?;

    assert_eq!(header(&resp, "access-control-allow-origin"), None);
    Ok(())
}

#[tokio::test]
async fn a_rate_limited_proxy_response_still_carries_cors_headers() -> anyhow::Result<()> {
    let bff = Bff::start_with(|config| config.rate_limit_proxy_max_attempts = 1).await;
    let hit = || {
        bff.send(
            Request::get("/no-such-route")
                .header("origin", "http://app.test")
                .body(Body::empty())
                .unwrap(),
        )
    };

    assert_eq!(hit().await.status(), StatusCode::NOT_FOUND);
    let resp = hit().await;

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        header(&resp, "access-control-allow-origin"),
        Some("http://app.test")
    );
    Ok(())
}

async fn body_of(resp: axum::response::Response) -> anyhow::Result<String> {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    Ok(String::from_utf8(body.to_vec())?)
}

/// What the upstream's fallback saw as the path of a request to `uri` through `/api`.
async fn upstream_path(uri: &str) -> anyhow::Result<(StatusCode, String)> {
    let resp = through_proxy(Request::get(uri)).await?;
    Ok((resp.status(), body_of(resp).await?))
}

#[tokio::test]
async fn the_route_prefix_is_stripped_exactly_once() -> anyhow::Result<()> {
    assert_eq!(
        upstream_path("/api/x").await?,
        (StatusCode::OK, "path=/x".to_string())
    );
    assert_eq!(
        upstream_path("/api/api/x").await?,
        (StatusCode::OK, "path=/api/x".to_string())
    );
    assert_eq!(
        upstream_path("/api/api/api/x").await?,
        (StatusCode::OK, "path=/api/api/x".to_string())
    );
    Ok(())
}

#[tokio::test]
async fn a_prefix_matches_whole_path_segments_only() -> anyhow::Result<()> {
    for uri in ["/apix/x", "/apix", "/ap/x", "/API/x"] {
        let resp = through_proxy(Request::get(uri)).await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
    }
    for uri in ["/api", "/api/", "/api/x"] {
        let resp = through_proxy(Request::get(uri)).await?;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn a_path_that_climbs_or_hides_a_slash_is_not_found_before_the_upstream() -> anyhow::Result<()>
{
    for uri in [
        "/api/../x",
        "/api/%2e%2e/x",
        "/api/%2E%2E/x",
        "/api/.%2e/x",
        "/api/./x",
        "/api/%2e/x",
        "/api/a/../../x",
        "/api/a/%2e%2e/%2e%2e/x",
        "/api/a%2fb",
        "/api/a%2Fb",
        "/api/a%5cb",
        "/api/a%5Cb",
        "/api/..",
        "/api/..;/x",
        "/api/%2e%2e;/x",
        "/api/..;a=b/x",
        "/api/.;/x",
        "/api/..%00",
        "/api/..%00/x",
        "/api/..%20/x",
        "/api/%2e%2e%20",
        "/api/%252e%252e/x",
        "/api/%252e%252e",
        "/api/...",
        "/api/%2e%2e%2e",
        "/api/a%0ab",
        "/api/a%7fb",
    ] {
        let resp = through_proxy(Request::get(uri)).await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
    }
    // Names that merely contain dots or encoded characters are ordinary paths.
    for uri in ["/api/a..b", "/api/a%20b", "/api/a;b"] {
        let resp = through_proxy(Request::get(uri)).await?;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn a_root_route_proxies_everything_the_endpoints_do_not_take() -> anyhow::Result<()> {
    let (upstream, _uh) = stub_upstream().await?;
    let routes = vec![RouteConfig {
        path_prefix: "/".into(),
        upstream_url: upstream,
    }];
    let (bff, session) = bff_with_session(routes).await;

    let proxied = bff.get("/whoami/7", Some(&session.cookie)).await;
    assert_eq!(proxied.status(), StatusCode::OK);
    assert_eq!(
        body_of(proxied).await?,
        "id=7 auth=Bearer access-1 cookie=false"
    );
    let unauthenticated = bff.get("/whoami/7", None).await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    // bff's own endpoints still win over the root route.
    assert_eq!(
        bff.get("/login", None).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(body_of(bff.get("/health", None).await).await?, "ok");
    Ok(())
}

#[tokio::test]
async fn a_proxied_response_without_a_csp_is_sandboxed() -> anyhow::Result<()> {
    let resp = through_proxy(Request::get("/api/headers")).await?;

    assert_eq!(
        resp.headers()["content-security-policy"],
        "sandbox; frame-ancestors 'none'"
    );
    Ok(())
}

#[tokio::test]
async fn an_upstream_csp_is_not_replaced() -> anyhow::Result<()> {
    let resp = through_proxy(Request::get("/api/every-header")).await?;

    assert_eq!(resp.headers()["content-security-policy"], "sandbox");
    Ok(())
}

#[tokio::test]
async fn a_request_body_past_the_limit_is_not_forwarded_whole() -> anyhow::Result<()> {
    let (upstream, _uh) = stub_upstream().await?;
    let (bff, session) = bff_with_session(vec![api_route(upstream)]).await;
    let too_big = vec![b'x'; 10 * 1024 * 1024 + 1];

    let resp = bff
        .send(
            Request::post("/api/headers")
                .header("cookie", &session.cookie)
                .header("origin", "http://app.test")
                .body(Body::from(too_big))?,
        )
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

#[tokio::test]
async fn a_session_cookie_sent_twice_is_no_session() -> anyhow::Result<()> {
    let (upstream, _uh) = stub_upstream().await?;
    let (bff, session) = bff_with_session(vec![api_route(upstream)]).await;

    let once = bff.get("/api/whoami/1", Some(&session.cookie)).await;
    assert_eq!(once.status(), StatusCode::OK);
    let twice = bff
        .get(
            "/api/whoami/1",
            Some(&format!("{}; wa_session=planted", session.cookie)),
        )
        .await;
    assert_eq!(twice.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn over_https_only_the_host_prefixed_session_cookie_is_a_session() -> anyhow::Result<()> {
    let (upstream, _uh) = stub_upstream().await?;
    let bff = Bff::start_with(|config| {
        config.bff_url = "https://bff.test".into();
        config.routes = vec![api_route(upstream)];
    })
    .await;
    let started = bff.start_login("http://app.test/").await;
    let url = location(&started);
    let state = query_of(&url)["state"].clone();
    let code = bff.hydra.grant(&url, SUB, None);
    let callback = bff
        .get(
            &format!("/callback?code={code}&state={state}"),
            Some(&cookie_pair(&started, "__Host-wa_login")),
        )
        .await;
    let prefixed = cookie_pair(&callback, "__Host-wa_session");

    let accepted = bff.get("/api/whoami/1", Some(&prefixed)).await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let unprefixed = prefixed.replace("__Host-", "");
    let refused = bff.get("/api/whoami/1", Some(&unprefixed)).await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}
