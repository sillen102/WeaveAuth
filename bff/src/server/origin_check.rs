use crate::config::Config;
use axum::http::HeaderMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum OriginError {
    #[error("request has neither an Origin nor a usable Referer header")]
    Missing,
    #[error("the Origin header is not text")]
    Unreadable,
    #[error("request came from untrusted origin {0:?}")]
    Untrusted(String),
}

/// Rejects a request unless it names one of `trusted_origins` as its origin.
///
/// The browser attaches the session cookie to any same-site request, and any
/// site can auto-submit a form: without this check a hostile page could make
/// the victim's browser `POST /logout` or send state-changing proxied requests.
///
/// Checks the `Origin` header first (sent by browsers on every cross-origin
/// POST, and on same-origin POSTs in most modern browsers too), falling back
/// to the origin component of `Referer` if `Origin` is absent. Rejects if
/// neither header is present -- a legitimate browser POST always sends at
/// least one. A present `Origin` is the only one consulted, readable or not.
pub(crate) fn require_trusted_origin(
    headers: &HeaderMap,
    trusted_origins: &[String],
) -> Result<(), OriginError> {
    let origin = match headers.get(axum::http::header::ORIGIN) {
        Some(origin) => origin
            .to_str()
            .map_err(|_| OriginError::Unreadable)?
            .to_string(),
        None => headers
            .get(axum::http::header::REFERER)
            .and_then(|v| v.to_str().ok())
            .and_then(|r| url::Url::parse(r).ok())
            .map(|u| u.origin().ascii_serialization())
            .ok_or(OriginError::Missing)?,
    };

    if trusted_origins.iter().any(|t| t == &origin) {
        Ok(())
    } else {
        Err(OriginError::Untrusted(origin))
    }
}

/// The origins trusted to `POST /logout` and to use the proxy from a browser (see
/// [`require_trusted_origin`] and `proxy_cors`): `trusted_origins` plus bff's own, for a
/// frontend served through bff.
pub(crate) fn trusted_origins(config: &Config) -> anyhow::Result<Arc<[String]>> {
    let bff_origin = url::Url::parse(&config.bff_url)?
        .origin()
        .ascii_serialization();
    Ok(config
        .trusted_origins
        .iter()
        .cloned()
        .chain([bff_origin])
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{OriginError, require_trusted_origin, trusted_origins};
    use crate::config::Config;
    use axum::http::{HeaderMap, HeaderValue};

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
            Err(OriginError::Untrusted("http://evil.test".to_string()))
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
            Err(OriginError::Untrusted("http://evil.test".to_string()))
        );
    }

    #[test]
    fn rejects_when_neither_header_is_present() {
        let headers = HeaderMap::new();

        assert_eq!(
            require_trusted_origin(&headers, &trusted()),
            Err(OriginError::Missing)
        );
    }

    #[test]
    fn origin_takes_precedence_over_referer() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("http://login.test"));
        headers.insert("referer", HeaderValue::from_static("http://evil.test/"));

        assert_eq!(require_trusted_origin(&headers, &trusted()), Ok(()));
    }

    #[test]
    fn an_origin_that_is_not_text_is_refused_even_with_a_trusted_referer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "origin",
            HeaderValue::from_bytes(b"http://login.test\xff").unwrap(),
        );
        headers.insert("referer", HeaderValue::from_static("http://login.test/"));

        assert_eq!(
            require_trusted_origin(&headers, &trusted()),
            Err(OriginError::Unreadable)
        );
    }

    #[test]
    fn trusted_origins_gain_bffs_own() {
        let config = Config {
            bff_url: "https://bff.test".into(),
            trusted_origins: vec!["https://app.test".into(), "http://localhost:3000".into()],
            ..Config::default()
        };

        assert_eq!(
            trusted_origins(&config).unwrap().to_vec(),
            [
                "https://app.test",
                "http://localhost:3000",
                "https://bff.test"
            ]
        );
    }
}
