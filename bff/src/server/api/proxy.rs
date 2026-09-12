use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::server::AppState;
use crate::storage::SessionStorage;

/// Headers that must not be blindly forwarded in either direction: they're
/// connection-scoped, or (cookie/authorization) get replaced deliberately below.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "cookie"
            | "set-cookie"
            | "authorization"
            | "content-length"
    )
}

fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == cookie_name).then(|| value.to_string())
    })
}

pub(crate) async fn proxy(State(state): State<AppState>, req: Request) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_string();
    let route = state
        .config
        .routes
        .iter()
        .filter(|r| path.starts_with(&r.path_prefix))
        .max_by_key(|r| r.path_prefix.len())
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let session_id = extract_cookie(req.headers(), &state.config.session_cookie_name)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let session = state
        .sessions
        .get_session(&session_id)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let rest = path.strip_prefix(&route.path_prefix).unwrap_or("");
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target = format!("{}{}{}", route.upstream_url, rest, query);

    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut upstream_req = state.http_client.request(method, &target);
    for (name, value) in parts.headers.iter() {
        if !is_hop_by_hop(name) {
            upstream_req = upstream_req.header(name, value);
        }
    }
    upstream_req = upstream_req
        .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token))
        .body(body_bytes);

    let upstream_resp = upstream_req
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let status = upstream_resp.status().as_u16();
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_resp.headers().iter() {
        if !is_hop_by_hop(name) {
            builder = builder.header(name, value);
        }
    }
    let resp_bytes = upstream_resp
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    Ok(builder.body(Body::from(resp_bytes)).unwrap().into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn is_hop_by_hop_flags_connection_scoped_and_replaced_headers() {
        for name in [
            "connection",
            "Connection",
            "keep-alive",
            "cookie",
            "Cookie",
            "set-cookie",
            "authorization",
            "Authorization",
            "content-length",
            "host",
        ] {
            assert!(
                is_hop_by_hop(&HeaderName::from_bytes(name.as_bytes()).unwrap()),
                "expected {name} to be hop-by-hop"
            );
        }
    }

    #[test]
    fn is_hop_by_hop_leaves_ordinary_headers_alone() {
        for name in ["content-type", "accept", "x-request-id"] {
            assert!(!is_hop_by_hop(&HeaderName::from_bytes(name.as_bytes()).unwrap()));
        }
    }

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn extract_cookie_returns_none_without_a_cookie_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_cookie(&headers, "wa_session"), None);
    }

    #[test]
    fn extract_cookie_finds_the_named_cookie_among_several() {
        let headers = headers_with_cookie("other=1; wa_session=abc123; another=2");
        assert_eq!(extract_cookie(&headers, "wa_session"), Some("abc123".to_string()));
    }

    #[test]
    fn extract_cookie_returns_none_when_name_is_absent() {
        let headers = headers_with_cookie("other=1; another=2");
        assert_eq!(extract_cookie(&headers, "wa_session"), None);
    }

    #[test]
    fn extract_cookie_handles_a_single_cookie_with_no_semicolons() {
        let headers = headers_with_cookie("wa_session=only-one");
        assert_eq!(extract_cookie(&headers, "wa_session"), Some("only-one".to_string()));
    }
}
