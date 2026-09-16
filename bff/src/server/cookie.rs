use axum::http::{header, HeaderMap};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

/// Encodes everything but unreserved characters, so the value can never contain
/// `;` or other characters that are meaningful in a `Cookie`/`Set-Cookie` header.
const COOKIE_VALUE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

pub(crate) fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == cookie_name).then(|| percent_decode_str(value).decode_utf8_lossy().into_owned())
    })
}

pub(crate) fn build_cookie(name: &str, value: &str, path: &str, max_age_secs: i64, secure: bool) -> String {
    let value = utf8_percent_encode(value, COOKIE_VALUE);
    let secure = if secure { "; Secure" } else { "" };
    format!("{name}={value}; HttpOnly; Path={path}; SameSite=Lax{secure}; Max-Age={max_age_secs}")
}

/// Like `build_cookie`, but `SameSite=None` instead of `Lax` -- for a cookie
/// that must survive a cross-site top-level POST (a login-page form
/// submitting to a bff on a different registrable domain), which `Lax`
/// blocks. `SameSite=None` is only valid with `Secure`; browsers reject it
/// otherwise, so this falls back to the ordinary `Lax` cookie when `secure`
/// is false (plain-http dev, where login and bff are same-site anyway).
pub(crate) fn build_cross_site_cookie(name: &str, value: &str, path: &str, max_age_secs: i64, secure: bool) -> String {
    if !secure {
        return build_cookie(name, value, path, max_age_secs, secure);
    }
    let value = utf8_percent_encode(value, COOKIE_VALUE);
    format!("{name}={value}; HttpOnly; Path={path}; SameSite=None; Secure; Max-Age={max_age_secs}")
}

/// A `Set-Cookie` value that immediately expires the named cookie.
pub(crate) fn clear_cookie(name: &str, path: &str, secure: bool) -> String {
    build_cookie(name, "", path, 0, secure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_cookie(value: &str) -> anyhow::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(value)?);
        Ok(headers)
    }

    #[test]
    fn extract_cookie_returns_none_without_a_cookie_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_cookie(&headers, "wa_session"), None);
    }

    #[test]
    fn extract_cookie_finds_the_named_cookie_among_several() -> anyhow::Result<()> {
        let headers = headers_with_cookie("other=1; wa_session=abc123; another=2")?;
        assert_eq!(extract_cookie(&headers, "wa_session"), Some("abc123".to_string()));
        Ok(())
    }

    #[test]
    fn extract_cookie_returns_none_when_name_is_absent() -> anyhow::Result<()> {
        let headers = headers_with_cookie("other=1; another=2")?;
        assert_eq!(extract_cookie(&headers, "wa_session"), None);
        Ok(())
    }

    #[test]
    fn extract_cookie_handles_a_single_cookie_with_no_semicolons() -> anyhow::Result<()> {
        let headers = headers_with_cookie("wa_session=only-one")?;
        assert_eq!(extract_cookie(&headers, "wa_session"), Some("only-one".to_string()));
        Ok(())
    }

    #[test]
    fn build_cookie_percent_encodes_special_characters() {
        let set_cookie = build_cookie("next", "/x;Domain=evil.com;Max-Age=999999", "/", 60, false);
        assert_eq!(
            set_cookie,
            "next=%2Fx%3BDomain%3Devil.com%3BMax-Age%3D999999; HttpOnly; Path=/; SameSite=Lax; Max-Age=60"
        );
    }

    #[test]
    fn build_cookie_adds_secure_flag_when_requested() {
        let set_cookie = build_cookie("wa_session", "abc", "/", 60, true);
        assert_eq!(set_cookie, "wa_session=abc; HttpOnly; Path=/; SameSite=Lax; Secure; Max-Age=60");
    }

    #[test]
    fn build_cross_site_cookie_uses_samesite_none_when_secure() {
        let set_cookie = build_cross_site_cookie("wa_pending", "tok", "/oidc", 300, true);
        assert_eq!(set_cookie, "wa_pending=tok; HttpOnly; Path=/oidc; SameSite=None; Secure; Max-Age=300");
    }

    #[test]
    fn build_cross_site_cookie_falls_back_to_lax_without_secure() {
        // SameSite=None is invalid without Secure -- browsers reject it. Plain
        // http (dev) keeps the ordinary Lax cookie instead.
        let set_cookie = build_cross_site_cookie("wa_pending", "tok", "/oidc", 300, false);
        assert_eq!(set_cookie, "wa_pending=tok; HttpOnly; Path=/oidc; SameSite=Lax; Max-Age=300");
    }

    #[test]
    fn build_cookie_and_extract_cookie_roundtrip_a_value_with_semicolons() -> anyhow::Result<()> {
        let malicious = "/x;Domain=evil.com;Max-Age=999999";
        let set_cookie = build_cookie("next", malicious, "/", 60, false);
        let value = set_cookie.split(';').next().unwrap().split_once('=').unwrap().1;
        let headers = headers_with_cookie(&format!("next={value}"))?;
        assert_eq!(extract_cookie(&headers, "next"), Some(malicious.to_string()));
        Ok(())
    }
}