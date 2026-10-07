//! Bff's side of Hydra: the OAuth2 client calls (token, refresh, revocation), the URLs the
//! browser is sent to, and the verification of what Hydra signs (the JWKS cache, the id_token
//! and the back-channel logout token).

mod id_token;
mod jwks;
mod logout_token;

pub(crate) use id_token::IdTokenError;
pub(crate) use jwks::JwksError;
pub(crate) use logout_token::LogoutTokenError;

use crate::config::Config;
use chrono::Duration;
use jwks::JwksCache;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::time::Duration as StdDuration;
use thiserror::Error;

/// How long a call to Hydra may take before it counts as unreachable.
const REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(10);

/// The shortest time between two fetches of the JWKS (see [`JwksCache`]).
const JWKS_MIN_REFRESH: StdDuration = StdDuration::from_secs(10);

/// The largest `expires_in` accepted from Hydra; a response outside `1..=` this is unreadable
/// and no date arithmetic on it can overflow.
const MAX_EXPIRES_IN_SECS: i64 = 86_400;

/// Why a call to Hydra's token or revocation endpoint failed.
#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum HydraError {
    #[error("request to {endpoint} failed: {cause}")]
    Unreachable {
        endpoint: &'static str,
        cause: String,
    },
    /// Hydra refused the grant (OAuth `error` `invalid_grant`, `token_inactive` or
    /// `access_denied`): the token is dead.
    #[error("{endpoint} rejected the request with {status}")]
    Rejected { endpoint: &'static str, status: u16 },
    /// Hydra refused bff itself (`invalid_client`, `unauthorized_client`): bff's credentials
    /// are wrong, which says nothing about the token.
    #[error("{endpoint} refused bff's client credentials with {status}")]
    Misconfigured { endpoint: &'static str, status: u16 },
    #[error("{endpoint} answered {status}")]
    Unavailable { endpoint: &'static str, status: u16 },
    #[error("{endpoint} response unreadable: {cause}")]
    Unreadable {
        endpoint: &'static str,
        cause: String,
    },
}

/// What Hydra's token endpoint handed out.
pub(crate) struct TokenSet {
    pub(crate) access_token: SecretString,
    /// `None` when Hydra did not rotate or issue one.
    pub(crate) refresh_token: Option<SecretString>,
    /// `None` on a refresh that returned no new id_token.
    pub(crate) id_token: Option<SecretString>,
    pub(crate) expires_in: Duration,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: SecretString,
    #[serde(default)]
    refresh_token: Option<SecretString>,
    #[serde(default)]
    id_token: Option<SecretString>,
    expires_in: Option<i64>,
}

pub(crate) struct Hydra {
    http: reqwest::Client,
    public_url: String,
    internal_url: String,
    client_id: String,
    client_secret: SecretString,
    audience: String,
    redirect_uri: String,
    logged_out_url: String,
    refresh_ttl: Duration,
    jwks: JwksCache,
}

impl Hydra {
    pub(crate) fn new(config: &Config) -> anyhow::Result<Self> {
        // No auto-follow: a redirect from the token endpoint is never one to trust with the
        // client secret.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            jwks: JwksCache::new(
                format!("{}/.well-known/jwks.json", config.hydra_internal_url),
                http.clone(),
                JWKS_MIN_REFRESH,
            ),
            http,
            public_url: config.hydra_public_url.clone(),
            internal_url: config.hydra_internal_url.clone(),
            client_id: config.bff_client_id.clone(),
            client_secret: config.bff_client_secret.clone(),
            audience: config.hydra_audience.clone(),
            redirect_uri: config.callback_url(),
            logged_out_url: config.logged_out_url(),
            refresh_ttl: Duration::seconds(config.hydra_refresh_token_ttl_secs),
        })
    }

    /// How long a refresh token Hydra just issued stays redeemable.
    pub(crate) fn refresh_ttl(&self) -> Duration {
        self.refresh_ttl
    }

    /// Where the browser starts a login: Hydra's authorization endpoint, asking for a code
    /// that comes back to bff's `/callback`.
    pub(crate) fn authorize_url(&self, state: &str, nonce: &str, code_challenge: &str) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", "openid offline_access")
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        if !self.audience.is_empty() {
            query.append_pair("audience", &self.audience);
        }
        let query = query.finish();
        format!("{}/oauth2/auth?{query}", self.public_url)
    }

    /// Where the browser goes to end its Hydra login session. Hydra only skips its
    /// confirmation page when it gets the `id_token_hint`, and only sends the browser on to
    /// bff's own `/logged-out`, with `state` handed back unchanged.
    pub(crate) fn logout_url(&self, id_token_hint: Option<&str>, state: Option<&str>) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(hint) = id_token_hint {
            query.append_pair("id_token_hint", hint);
        }
        query.append_pair("post_logout_redirect_uri", &self.logged_out_url);
        if let Some(state) = state {
            query.append_pair("state", state);
        }
        format!(
            "{}/oauth2/sessions/logout?{}",
            self.public_url,
            query.finish()
        )
    }

    /// Redeems an authorization code, proving the PKCE `code_verifier`.
    pub(crate) async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenSet, HydraError> {
        self.token_request(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("code_verifier", code_verifier),
        ])
        .await
    }

    /// Redeems a refresh token. Hydra rotates it, so the old one is dead once this succeeds.
    pub(crate) async fn refresh(&self, refresh_token: &str) -> Result<TokenSet, HydraError> {
        self.token_request(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .await
    }

    /// Revokes a refresh token, and the access tokens of its grant with it.
    pub(crate) async fn revoke(&self, refresh_token: &str) -> Result<(), HydraError> {
        const ENDPOINT: &str = "revocation endpoint";
        let response = self
            .client_request("/oauth2/revoke")
            .form(&[
                ("token", refresh_token),
                ("token_type_hint", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|error| unreachable(ENDPOINT, error))?;
        check_response(ENDPOINT, response).await.map(drop)
    }

    async fn token_request(&self, form: &[(&str, &str)]) -> Result<TokenSet, HydraError> {
        const ENDPOINT: &str = "token endpoint";
        let response = self
            .client_request("/oauth2/token")
            .form(form)
            .send()
            .await
            .map_err(|error| unreachable(ENDPOINT, error))?;
        let response = check_response(ENDPOINT, response).await?;
        let token: TokenResponse =
            response
                .json()
                .await
                .map_err(|error| HydraError::Unreadable {
                    endpoint: ENDPOINT,
                    cause: common::error::cause_chain(&error.without_url()),
                })?;
        let expires_in = token
            .expires_in
            .filter(|seconds| (1..=MAX_EXPIRES_IN_SECS).contains(seconds))
            .ok_or(HydraError::Unreadable {
                endpoint: ENDPOINT,
                cause: "no usable expires_in".to_string(),
            })?;
        Ok(TokenSet {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            id_token: token.id_token,
            expires_in: Duration::seconds(expires_in),
        })
    }

    /// A POST to one of Hydra's public endpoints on the internal URL, authenticated as
    /// `client_secret_basic`: RFC 6749 2.3.1 has the id and secret form-encoded before they
    /// are base64'd, which `basic_auth` does not do.
    fn client_request(&self, path: &str) -> reqwest::RequestBuilder {
        let encode = |value: &str| {
            url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
        };
        self.http
            .post(format!("{}{path}", self.internal_url))
            .basic_auth(
                encode(&self.client_id),
                Some(encode(self.client_secret.expose_secret())),
            )
    }
}

fn unreachable(endpoint: &'static str, error: reqwest::Error) -> HydraError {
    HydraError::Unreachable {
        endpoint,
        cause: common::error::cause_chain(&error.without_url()),
    }
}

/// Passes a 2xx response through; classifies any other by the OAuth `error` of a 4xx body,
/// since the status alone does not tell a dead token from bad client credentials.
async fn check_response(
    endpoint: &'static str,
    response: reqwest::Response,
) -> Result<reqwest::Response, HydraError> {
    let status = response.status().as_u16();
    if response.status().is_success() {
        return Ok(response);
    }
    let error = if (400..500).contains(&status) {
        #[derive(Deserialize)]
        struct OAuthError {
            error: String,
        }
        response
            .json::<OAuthError>()
            .await
            .ok()
            .map(|body| body.error)
    } else {
        None
    };
    Err(match error.as_deref() {
        Some("invalid_grant" | "token_inactive" | "access_denied") => {
            HydraError::Rejected { endpoint, status }
        }
        Some("invalid_client" | "unauthorized_client") => {
            HydraError::Misconfigured { endpoint, status }
        }
        _ => HydraError::Unavailable { endpoint, status },
    })
}

/// Part `index` of a compact JWS (0 the header, 1 the payload), decoded without verifying anything.
fn unverified_part(token: &str, index: usize) -> Option<serde_json::Value> {
    use base64::Engine;
    let part = token.split('.').nth(index)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The `kid` of a JWS, to know which of Hydra's keys to ask for before verifying it.
fn jws_kid(token: &str) -> Option<String> {
    unverified_part(token, 0)?
        .get("kid")?
        .as_str()
        .map(str::to_string)
}

/// Whether two issuers differ at most by a trailing `/`, which Hydra's `iss` may or may
/// not carry compared with how the deployer wrote its URL.
fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use base64::Engine;
    use std::sync::{Arc, Mutex};

    fn config(internal_url: &str) -> Config {
        Config {
            bff_url: "https://bff.test/base/".into(),
            hydra_public_url: "https://login.test".into(),
            hydra_internal_url: internal_url.into(),
            bff_client_id: "client id".into(),
            bff_client_secret: "s3cr3t+/%&".to_string().into(),
            hydra_refresh_token_ttl_secs: 3600,
            ..Config::default()
        }
    }

    #[test]
    fn the_authorize_url_asks_for_a_code_with_pkce_and_the_callback() {
        let hydra = Hydra::new(&config("http://hydra:4444")).unwrap();

        let url = url::Url::parse(&hydra.authorize_url("st&ate", "non ce", "chal")).unwrap();

        assert_eq!(url.origin().ascii_serialization(), "https://login.test");
        assert_eq!(url.path(), "/oauth2/auth");
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let expected = [
            ("response_type", "code"),
            ("client_id", "client id"),
            ("redirect_uri", "https://bff.test/base/callback"),
            ("scope", "openid offline_access"),
            ("state", "st&ate"),
            ("nonce", "non ce"),
            ("code_challenge", "chal"),
            ("code_challenge_method", "S256"),
            ("audience", "weaveauth"),
        ];
        assert_eq!(query.len(), expected.len());
        for (key, value) in expected {
            assert_eq!(query.get(key).map(String::as_str), Some(value), "{key}");
        }
    }

    #[test]
    fn no_audience_is_asked_for_when_none_is_configured() {
        let mut config = config("http://hydra:4444");
        config.hydra_audience = String::new();
        let hydra = Hydra::new(&config).unwrap();

        assert!(!hydra.authorize_url("s", "n", "c").contains("audience"));
    }

    #[test]
    fn the_logout_url_carries_the_hint_the_state_and_bffs_own_return_address() {
        let hydra = Hydra::new(&config("http://hydra:4444")).unwrap();

        let full =
            url::Url::parse(&hydra.logout_url(Some("id.tok.en"), Some("https://app.test/?a=b&c")))
                .unwrap();
        let bare = url::Url::parse(&hydra.logout_url(None, None)).unwrap();

        assert_eq!(full.path(), "/oauth2/sessions/logout");
        let query: std::collections::HashMap<_, _> = full.query_pairs().into_owned().collect();
        assert_eq!(query["id_token_hint"], "id.tok.en");
        assert_eq!(query["state"], "https://app.test/?a=b&c");
        assert_eq!(
            query["post_logout_redirect_uri"],
            "https://bff.test/base/logged-out"
        );
        let query: std::collections::HashMap<_, _> = bare.query_pairs().into_owned().collect();
        assert_eq!(query.len(), 1);
        assert!(query.contains_key("post_logout_redirect_uri"));
    }

    /// A Hydra that records the `Authorization` header and form of each token request.
    async fn recording_hydra() -> (String, Arc<Mutex<Vec<(String, String)>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let router = Router::new().route(
            "/oauth2/token",
            post(move |headers: HeaderMap, body: String| {
                let recorder = recorder.clone();
                async move {
                    let auth = headers["authorization"].to_str().unwrap().to_string();
                    recorder.lock().unwrap().push((auth, body));
                    axum::Json(serde_json::json!({
                        "access_token": "at", "refresh_token": "rt", "id_token": "it", "expires_in": 900
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await });
        (url, seen)
    }

    #[tokio::test]
    async fn the_client_authenticates_with_form_encoded_basic_credentials() {
        let (url, seen) = recording_hydra().await;
        let hydra = Hydra::new(&config(&url)).unwrap();

        let tokens = hydra
            .exchange_code("the-code", "the-verifier")
            .await
            .unwrap();

        let (auth, body) = seen.lock().unwrap().remove(0);
        let encoded = auth.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            "client+id:s3cr3t%2B%2F%25%26"
        );
        let form: std::collections::HashMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "the-code");
        assert_eq!(form["code_verifier"], "the-verifier");
        assert_eq!(form["redirect_uri"], "https://bff.test/base/callback");
        assert!(!form.contains_key("client_secret"));
        assert_eq!(tokens.expires_in, Duration::seconds(900));
        assert_eq!(tokens.refresh_token.unwrap().expose_secret(), "rt");
    }

    #[tokio::test]
    async fn a_token_endpoint_error_is_told_apart_by_its_oauth_error() {
        for (status, body, expected) in [
            (400, r#"{"error":"invalid_grant"}"#, "rejected"),
            (401, r#"{"error":"token_inactive"}"#, "rejected"),
            (403, r#"{"error":"access_denied"}"#, "rejected"),
            (401, r#"{"error":"invalid_client"}"#, "misconfigured"),
            (400, r#"{"error":"unauthorized_client"}"#, "misconfigured"),
            (400, r#"{"error":"server_error"}"#, "unavailable"),
            (401, "", "unavailable"),
            (400, "not json", "unavailable"),
            (500, r#"{"error":"invalid_grant"}"#, "unavailable"),
            (404, "", "unavailable"),
            (429, "", "unavailable"),
        ] {
            let router =
                Router::new().route(
                    "/oauth2/token",
                    post(move || async move {
                        (axum::http::StatusCode::from_u16(status).unwrap(), body)
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, router).await });
            let hydra = Hydra::new(&config(&url)).unwrap();

            let error = hydra.refresh("rt").await.err().unwrap();

            let actual = match error {
                HydraError::Rejected { .. } => "rejected",
                HydraError::Misconfigured { .. } => "misconfigured",
                HydraError::Unavailable { .. } => "unavailable",
                _ => "other",
            };
            assert_eq!(actual, expected, "{status} {body}");
        }
    }

    #[tokio::test]
    async fn an_expires_in_out_of_range_is_unreadable() {
        for expires_in in [-86_401_i64, -1, 0, 86_401, i64::MAX, i64::MIN] {
            let router = Router::new().route(
                "/oauth2/token",
                post(move || async move {
                    axum::Json(
                        serde_json::json!({ "access_token": "at", "expires_in": expires_in }),
                    )
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, router).await });
            let hydra = Hydra::new(&config(&url)).unwrap();

            let error = hydra.refresh("rt").await.err().unwrap();

            assert!(
                matches!(error, HydraError::Unreadable { .. }),
                "{expires_in}"
            );
        }
    }

    #[tokio::test]
    async fn an_unreachable_hydra_is_unreachable() {
        let hydra = Hydra::new(&config("http://127.0.0.1:1")).unwrap();

        let error = hydra.refresh("rt").await.err().unwrap();

        assert!(matches!(error, HydraError::Unreachable { .. }), "{error}");
        assert!(!error.to_string().contains("rt"));
    }

    #[test]
    fn issuers_differing_by_a_trailing_slash_are_the_same() {
        assert!(same_issuer("https://login.test", "https://login.test/"));
        assert!(same_issuer("https://login.test/", "https://login.test"));
        assert!(!same_issuer(
            "https://login.test",
            "https://login.test.evil"
        ));
        assert!(!same_issuer("https://login.test/x", "https://login.test"));
    }
}
