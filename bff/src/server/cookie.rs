use axum::http::{header, HeaderMap};

pub(crate) fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == cookie_name).then(|| value.to_string())
    })
}

pub(crate) fn build_cookie(name: &str, value: &str, path: &str, max_age_secs: i64) -> String {
    format!("{name}={value}; HttpOnly; Path={path}; SameSite=Lax; Max-Age={max_age_secs}")
}

/// A `Set-Cookie` value that immediately expires the named cookie.
pub(crate) fn clear_cookie(name: &str, path: &str) -> String {
    build_cookie(name, "", path, 0)
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
}