use axum::http::{HeaderMap, StatusCode};

/// Rejects a request unless it names one of `trusted_origins` as its origin.
///
/// `/login` and `/register` are plain cross-origin form POSTs by design (that's
/// what keeps the response's `Set-Cookie` scoped to bff's own origin without
/// needing CORS) -- but that same shape means any site can auto-submit one.
/// Without this check, a hostile page could POST the attacker's own valid
/// credentials to `/login` and hand the victim's browser a session logged in
/// as the attacker ("login CSRF"), or spam `/register`.
///
/// Checks the `Origin` header first (sent by browsers on every cross-origin
/// POST, and on same-origin POSTs in most modern browsers too), falling back
/// to the origin component of `Referer` if `Origin` is absent. Rejects if
/// neither header is present -- a legitimate browser POST always sends at
/// least one.
pub(crate) fn require_trusted_origin(
    headers: &HeaderMap,
    trusted_origins: &[String],
) -> Result<(), StatusCode> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            headers
                .get(axum::http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .and_then(|r| url::Url::parse(r).ok())
                .map(|u| u.origin().ascii_serialization())
        })
        .ok_or(StatusCode::FORBIDDEN)?;

    if trusted_origins.iter().any(|t| t == &origin) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

#[cfg(test)]
mod tests {
    use super::require_trusted_origin;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    fn trusted() -> Vec<String> {
        vec!["http://login.test".to_string()]
    }

    #[test]
    fn accepts_a_trusted_origin_header() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("http://login.test"));

        assert_eq!(require_trusted_origin(&headers, &trusted()), Ok(()));
    }

    #[test]
    fn rejects_an_untrusted_origin_header() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("http://evil.test"));

        assert_eq!(
            require_trusted_origin(&headers, &trusted()),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn falls_back_to_referer_when_origin_is_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "referer",
            HeaderValue::from_static("http://login.test/index.html?redirect_uri=x"),
        );

        assert_eq!(require_trusted_origin(&headers, &trusted()), Ok(()));
    }

    #[test]
    fn rejects_an_untrusted_referer() {
        let mut headers = HeaderMap::new();
        headers.insert("referer", HeaderValue::from_static("http://evil.test/"));

        assert_eq!(
            require_trusted_origin(&headers, &trusted()),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn rejects_when_neither_header_is_present() {
        let headers = HeaderMap::new();

        assert_eq!(
            require_trusted_origin(&headers, &trusted()),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn origin_takes_precedence_over_referer() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("http://login.test"));
        headers.insert("referer", HeaderValue::from_static("http://evil.test/"));

        assert_eq!(require_trusted_origin(&headers, &trusted()), Ok(()));
    }
}