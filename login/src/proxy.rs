//! The only way a browser reaches Kratos: `/self-service/*` and `/.well-known/ory/*`, forwarded
//! to Kratos' public API with cookies both ways. Submissions to the login flow also pass the
//! per-identifier throttle.

use crate::AppState;
use crate::throttle::{Admission, Key, Outcome};
use crate::upstream::UpstreamError;
use axum::Extension;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, OriginalUri, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Request headers Kratos gets: the cookies and what its CSRF check and content negotiation read.
const FORWARDED_REQUEST_HEADERS: [HeaderName; 7] = [
    header::COOKIE,
    header::CONTENT_TYPE,
    header::ACCEPT,
    header::ACCEPT_LANGUAGE,
    header::USER_AGENT,
    header::ORIGIN,
    header::REFERER,
];

/// Response headers the browser gets. Kratos' own `Content-Security-Policy` and the like are
/// not among them: these are all JSON, redirects and the WebAuthn script, which get login's own.
const FORWARDED_RESPONSE_HEADERS: [HeaderName; 5] = [
    header::CONTENT_TYPE,
    header::CACHE_CONTROL,
    header::LOCATION,
    header::RETRY_AFTER,
    header::CONTENT_DISPOSITION,
];

/// Set from the client address the rate limiter resolved; Kratos reads it for session devices.
const CLIENT_IP_HEADER: HeaderName = HeaderName::from_static("true-client-ip");

const LOGIN_SUBMIT_PATH: &str = "/self-service/login";

pub(crate) async fn proxy(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_clean_path(uri.path())
        || is_native_api_path(uri.path())
        || (method == Method::POST && is_login_submit_variant(uri.path()))
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    let attempt = if method == Method::POST && uri.path() == LOGIN_SUBMIT_PATH {
        match login_attempt(&state, &headers, &body) {
            Ok(attempt) => attempt,
            Err(Refusal::UnsupportedEncoding) => {
                return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
            }
            Err(Refusal::Ambiguous) => return StatusCode::BAD_REQUEST.into_response(),
            Err(Refusal::Wait(wait)) => {
                tracing::warn!(
                    wait_secs = wait.as_secs(),
                    "login throttled for an identifier"
                );
                return state.throttled_page(wait);
            }
        }
    } else {
        None
    };

    let url = match state.kratos.url(uri.path(), uri.query()) {
        Ok(url) => url,
        Err(error) => {
            tracing::error!(%error, "could not build the Kratos URL for a proxied request");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let client_ip = peer.map(|Extension(ConnectInfo(peer))| {
        common::rate_limit::client_ip_of(peer.ip(), &headers, &state.config.trusted_proxies)
    });
    let forwarded = forward(&state, method, &url, &headers, client_ip, body).await;

    match forwarded {
        Ok(answer) => {
            if let Some(key) = attempt {
                state.throttle.settle(key, outcome(&state, &answer));
            }
            into_response(answer)
        }
        Err(error) => {
            if let Some(key) = attempt {
                state.throttle.settle(key, Outcome::NotAnAttempt);
            }
            tracing::error!(%error, "could not proxy a request to Kratos");
            (StatusCode::BAD_GATEWAY, "Bad gateway").into_response()
        }
    }
}

/// `..` segments would let a request climb out of Kratos' browser paths
/// to its other public endpoints.
fn is_clean_path(path: &str) -> bool {
    // Kratos' browser paths never need encoding; Kratos decodes the path, so `%6cogin` would be
    // the login submit while this proxy's comparisons see something else.
    !path.contains('%')
        && !path.contains("//")
        && !path
            .split('/')
            .any(|segment| segment == ".." || segment == "." || segment.contains('\\'))
}

/// Kratos' native-client flows (`/self-service/*/api`): no CSRF protection and no browser behind
/// them, which login never serves.
fn is_native_api_path(path: &str) -> bool {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .is_some_and(|last| last == "api")
}

/// A path Kratos may route to the login submit that isn't exactly [`LOGIN_SUBMIT_PATH`] (other
/// case, trailing slash), and so would skip the throttle.
fn is_login_submit_variant(path: &str) -> bool {
    path != LOGIN_SUBMIT_PATH
        && path
            .trim_end_matches('/')
            .eq_ignore_ascii_case(LOGIN_SUBMIT_PATH)
}

/// Why a login submission isn't forwarded.
enum Refusal {
    UnsupportedEncoding,
    /// A body or key the throttle can't read the way Kratos does (unparseable JSON, a repeated or
    /// differently-cased `identifier`/`method`, a non-string identifier): it could count another
    /// identifier than the one Kratos checks.
    Ambiguous,
    Wait(Duration),
}

/// The throttle's side of a login submission: `Ok(None)` when it carries no password attempt,
/// `Ok(Some(key))` when it was admitted.
fn login_attempt(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Option<Key>, Refusal> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let fields = if content_type.starts_with("application/x-www-form-urlencoded") {
        LoginFields::from_form(body)
    } else if content_type.starts_with("application/json") {
        LoginFields::from_json(body)?
    } else {
        // Kratos accepts other encodings too; a body the throttle can't read is not let past it.
        return Err(Refusal::UnsupportedEncoding);
    };
    if fields.repeated {
        return Err(Refusal::Ambiguous);
    }
    let Some(identifier) = fields.throttled_identifier() else {
        return Ok(None);
    };
    let key = Key::of(identifier);
    match state.throttle.admit(key, Instant::now()) {
        Admission::Admitted => Ok(Some(key)),
        Admission::Wait(wait) => Err(Refusal::Wait(wait)),
    }
}

#[derive(Default)]
struct LoginFields {
    method: Option<String>,
    identifier: Option<String>,
    repeated: bool,
}

impl LoginFields {
    fn from_form(body: &[u8]) -> Self {
        let mut fields = Self::default();
        for (name, value) in url::form_urlencoded::parse(body) {
            match name.as_ref() {
                "method" => fields.set_method(value.into_owned()),
                "identifier" | "password_identifier" => fields.set_identifier(value.into_owned()),
                _ => {}
            }
        }
        fields
    }

    /// Kratos' JSON decoder (Go) accepts what serde refuses, so an unreadable body is refused
    /// rather than let past the throttle.
    fn from_json(body: &[u8]) -> Result<Self, Refusal> {
        serde_json::from_slice(body).map_err(|_| Refusal::Ambiguous)
    }

    fn set_method(&mut self, value: String) {
        self.repeated |= self.method.is_some();
        self.method = Some(value);
    }

    fn set_identifier(&mut self, value: String) {
        self.repeated |= self.identifier.is_some();
        self.identifier = Some(value);
    }

    /// Only a password submission has a secret to guess.
    fn throttled_identifier(&self) -> Option<&str> {
        let is_password = matches!(self.method.as_deref(), Some("password") | None);
        self.identifier
            .as_deref()
            .filter(|identifier| is_password && !identifier.trim().is_empty())
    }
}

/// A JSON object read for `method` and `identifier` (`password_identifier` is its deprecated
/// alias); a repeated key is noted, not resolved. Go matches keys case-insensitively and folds
/// some non-ASCII characters (`ſ` to `s`), so a key that is one of these only by that matching,
/// or any non-ASCII key, is an error, and so is a value that isn't a string.
impl<'de> serde::Deserialize<'de> for LoginFields {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        const KEYS: [&str; 3] = ["method", "identifier", "password_identifier"];

        struct Fields;

        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = LoginFields;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<LoginFields, A::Error> {
                let mut fields = LoginFields::default();
                while let Some(name) = map.next_key::<String>()? {
                    let value: serde_json::Value = map.next_value()?;
                    if KEYS.contains(&name.as_str()) {
                        let Some(text) = value.as_str() else {
                            return Err(A::Error::custom("not a string"));
                        };
                        if name == "method" {
                            fields.set_method(text.to_string());
                        } else {
                            fields.set_identifier(text.to_string());
                        }
                    } else if !name.is_ascii()
                        || KEYS.iter().any(|key| key.eq_ignore_ascii_case(&name))
                    {
                        return Err(A::Error::custom("a key Kratos may read differently"));
                    }
                }
                Ok(fields)
            }
        }

        deserializer.deserialize_map(Fields)
    }
}

/// Kratos' answer, read in full (flow pages and JSON are small).
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn forward(
    state: &AppState,
    method: Method,
    url: &url::Url,
    headers: &HeaderMap,
    client_ip: Option<IpAddr>,
    body: Bytes,
) -> Result<Answer, UpstreamError> {
    let mut request = state.http.request(method, url.clone());
    for name in &FORWARDED_REQUEST_HEADERS {
        for value in headers.get_all(name) {
            request = request.header(name, value);
        }
    }
    if let Some(ip) = client_ip
        && let Ok(value) = HeaderValue::from_str(&ip.to_string())
    {
        request = request.header(CLIENT_IP_HEADER, value);
    }
    let response = request
        .body(body)
        .send()
        .await
        .map_err(|error| UpstreamError::request("kratos", url, error))?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|error| UpstreamError::request("kratos", url, error))?;
    Ok(Answer {
        status,
        headers,
        body,
    })
}

/// What an admitted login submission's answer says about the attempt. Success is an answer that
/// isn't one of login's own pages and sets a Kratos session: a browser that already has a session
/// is sent onward without its password being checked, so the redirect alone proves nothing. A
/// refusal before any check (CSRF, rate limit, Kratos down) is given back; anything else is a
/// failed guess, JSON answers included, so the encoding can't be used to dodge the count.
fn outcome(state: &AppState, answer: &Answer) -> Outcome {
    let status = answer.status;
    let signed_in = || {
        if sets_session(&answer.headers, &state.config.kratos_session_cookie) {
            Outcome::Succeeded
        } else {
            Outcome::Failed
        }
    };
    // Kratos' "go here next" answer to a submission made with `Accept: application/json`, once the
    // credentials checked out.
    if status == StatusCode::UNPROCESSABLE_ENTITY {
        return signed_in();
    }
    if status == StatusCode::FORBIDDEN
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        return Outcome::NotAnAttempt;
    }
    if status.is_success() {
        return signed_in();
    }
    if !status.is_redirection() {
        return Outcome::Failed;
    }
    let target = answer
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|location| {
            url::Url::options()
                .base_url(Some(&state.own_origin))
                .parse(location)
                .ok()
        });
    match target {
        Some(target) if target.origin() == state.own_origin.origin() => match target.path() {
            "/error" => Outcome::NotAnAttempt,
            path if is_ui_path(path) => Outcome::Failed,
            _ => signed_in(),
        },
        Some(_) => signed_in(),
        None => Outcome::Failed,
    }
}

/// Whether the answer sets a non-empty Kratos session cookie called `cookie`.
fn sets_session(headers: &HeaderMap, cookie: &str) -> bool {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|set_cookie| set_cookie.split(';').next()?.split_once('='))
        .any(|(name, value)| name.trim() == cookie && !value.trim().is_empty())
}

/// Login's own pages and Kratos' flow starts: where a failed submission is sent back to.
fn is_ui_path(path: &str) -> bool {
    matches!(
        path,
        "/login" | "/registration" | "/recovery" | "/verification" | "/settings"
    ) || path.starts_with("/self-service/")
}

fn into_response(answer: Answer) -> Response {
    let mut headers = HeaderMap::new();
    for name in &FORWARDED_RESPONSE_HEADERS {
        for value in answer.headers.get_all(name) {
            headers.append(name.clone(), value.clone());
        }
    }
    // Several, one per cookie: never merged.
    for value in answer.headers.get_all(header::SET_COOKIE) {
        headers.append(header::SET_COOKIE, value.clone());
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; sandbox"),
    );
    // Flow JSON carries CSRF tokens; Kratos' own caching choice (the WebAuthn script) is kept.
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    let mut reply = Response::new(axum::body::Body::from(answer.body));
    *reply.status_mut() = answer.status;
    *reply.headers_mut() = headers;
    reply
}
