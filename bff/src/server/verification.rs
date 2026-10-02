//! The restricted "verification session" an unverified account is handed
//! instead of (or next to) a real session -- see `docs/flows/verify-email.md`.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::config::Config;
use crate::server::cookie::{build_cross_site_cookie, clear_cookie};

pub(crate) const VERIFY_COOKIE: &str = "wa_verify_session";

/// Only `/verify-email` and `/verify-email/resend` ever receive it, so it
/// can't be used on any proxied route.
pub(crate) const VERIFY_COOKIE_PATH: &str = "/verify-email";

/// Backend's `/oauth/login` response. A verified account gets `login_session`;
/// an unverified one also gets `verification_session`, and only that when
/// backend requires verification.
#[derive(Deserialize)]
pub(crate) struct BackendLoginResponse {
    pub(crate) login_session: Option<String>,
    verification_session: Option<String>,
    verification_session_ttl_secs: Option<i64>,
}

impl BackendLoginResponse {
    /// The verification session, with the lifetime backend gave it. A session
    /// without a lifetime is an error rather than being ignored: the cookie
    /// must live exactly as long as the session, bff doesn't guess, and
    /// silently dropping it would surface as an unrelated failure (typically
    /// two services of different versions).
    pub(crate) fn verification(&self) -> Result<Option<VerificationSession>, &'static str> {
        let Some(token) = self.verification_session.clone() else {
            return Ok(None);
        };
        let ttl_secs = self
            .verification_session_ttl_secs
            .ok_or("login response has a verification session without its lifetime")?;
        Ok(Some(VerificationSession { token, ttl_secs }))
    }
}

pub(crate) struct VerificationSession {
    pub(crate) token: String,
    pub(crate) ttl_secs: i64,
}

/// Cross-site capable like the pending-link cookie: the form that sends it
/// lives on login's origin.
pub(crate) fn verification_cookie(config: &Config, session: &VerificationSession) -> String {
    build_cross_site_cookie(
        VERIFY_COOKIE,
        &session.token,
        VERIFY_COOKIE_PATH,
        session.ttl_secs,
        config.secure_cookies(),
    )
}

pub(crate) fn clear_verification_cookie(config: &Config) -> String {
    clear_cookie(VERIFY_COOKIE, VERIFY_COOKIE_PATH, config.secure_cookies())
}

/// Adds the verification cookie to a response that logs the user in, when
/// backend also handed out a verification session (verification is optional).
pub(crate) fn with_optional_verification_cookie(
    mut response: Response,
    config: &Config,
    session: Option<&VerificationSession>,
) -> Response {
    if let Some(session) = session
        && let Ok(value) = verification_cookie(config, session).parse()
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// The login page's `verify-email.html`, next to wherever `next` (the login
/// page the form came from, already checked by `is_safe_redirect_target`)
/// points, remembering where the user was headed.
pub(crate) fn verify_page_location(next: &str, redirect_uri: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_uri", redirect_uri)
        .finish();
    match url::Url::parse(next) {
        Ok(mut page) => {
            page.set_path("/verify-email.html");
            page.set_query(Some(&query));
            page.set_fragment(None);
            page.to_string()
        }
        Err(_) => format!("/verify-email.html?{query}"),
    }
}

/// 303 to the verification page, with the verification cookie set and no
/// session cookie: the user is logged in as far as backend is concerned, but
/// bff gives them nothing to present to the proxy.
pub(crate) fn redirect_to_verification(
    config: &Config,
    next: &str,
    redirect_uri: &str,
    session: &VerificationSession,
) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, verify_page_location(next, redirect_uri)),
            (header::SET_COOKIE, verification_cookie(config, session)),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(session: Option<&str>, ttl: Option<i64>) -> BackendLoginResponse {
        BackendLoginResponse {
            login_session: None,
            verification_session: session.map(str::to_string),
            verification_session_ttl_secs: ttl,
        }
    }

    #[test]
    fn the_cookie_lives_as_long_as_backend_says_the_session_does() {
        let session = response(Some("tok"), Some(4321))
            .verification()
            .unwrap()
            .unwrap();

        let cookie = verification_cookie(&Config::default(), &session);

        assert!(cookie.starts_with("wa_verify_session=tok;"), "{cookie}");
        assert!(cookie.contains("Max-Age=4321"), "{cookie}");
    }

    #[test]
    fn a_session_without_a_lifetime_is_an_error_and_no_session_is_none() {
        let error = response(Some("tok"), None).verification().err().unwrap();
        assert!(error.contains("without its lifetime"), "{error}");
        assert!(response(None, Some(60)).verification().unwrap().is_none());
    }

    #[test]
    fn the_verify_page_sits_next_to_the_login_page_and_remembers_the_destination() {
        assert_eq!(
            verify_page_location(
                "http://login.test/login.html?redirect_uri=x",
                "http://admin.test/a?b=1"
            ),
            "http://login.test/verify-email.html?redirect_uri=http%3A%2F%2Fadmin.test%2Fa%3Fb%3D1"
        );
    }

    #[test]
    fn a_relative_next_gives_a_relative_verify_page() {
        assert_eq!(
            verify_page_location("/login.html", "http://admin.test/"),
            "/verify-email.html?redirect_uri=http%3A%2F%2Fadmin.test%2F"
        );
    }
}
