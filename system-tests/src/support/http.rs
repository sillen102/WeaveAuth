//! Shared HTTP test helpers for driving real, multi-hop redirect chains
//! between the real servers a test starts, without trying to actually
//! resolve the fake public hosts (`admin.test`, `login.test`, ...) those
//! chains land on.

/// Follows redirects between the real servers a test starts (bff, the fake
/// IdP -- both on `127.0.0.1`), but stops at the final hand-off to a fake
/// public host, which doesn't exist and would otherwise fail to resolve.
/// The stopped-at response's `Location` header is the answer the test
/// actually cares about (see `redirect_target`).
pub fn stop_at_real_hosts() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.url().host_str() == Some("127.0.0.1") {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// The URL a (possibly stopped-at) redirect response points to: its own
/// `Location` header if it's a redirect, otherwise the final URL reqwest
/// actually landed on.
pub fn redirect_target(resp: &reqwest::Response) -> String {
    if resp.status().is_redirection() {
        resp.headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    } else {
        resp.url().to_string()
    }
}

pub fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
