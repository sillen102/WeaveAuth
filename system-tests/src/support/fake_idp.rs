//! A fake third-party OIDC provider, standing in for a real one (Google,
//! etc) in tests -- backed by a `wiremock::MockServer` speaking just enough
//! of the protocol for backend's real `openidconnect`-based client to
//! discover it, redirect to it, and exchange a code for a signed id_token.
//!
//! `/authorize` behaves like an instantly-consenting user: rather than
//! serving a real consent page, it immediately redirects back to the
//! caller's `redirect_uri` with a code, which is enough to drive the whole
//! flow with a plain `reqwest` client instead of a browser.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Serialize;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

pub const CLIENT_ID: &str = "e2e-test-client";
pub const CLIENT_SECRET: &str = "e2e-test-client-secret";

pub struct FakeIdp {
    pub issuer: String,
    _server: MockServer,
}

/// The provider's own subject identifier for the (single) test user this
/// fake IdP ever authenticates as.
const SUBJECT: &str = "fake-idp-subject";

/// Starts the fake IdP. Every login through it claims `email`, tagged
/// `email_verified` as given -- callers exercise both the happy path
/// (verified) and the password-confirmation branch (unverified) by starting
/// a fresh instance with different values.
pub async fn start(email: &str, email_verified: bool) -> anyhow::Result<FakeIdp> {
    let server = MockServer::start().await;
    let issuer = server.uri();

    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })))
        .mount(&server)
        .await;

    let signing_key = SigningKey::generate()?;
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(signing_key.jwk_set()))
        .mount(&server)
        .await;

    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/authorize"))
        .respond_with(consent_redirect)
        .mount(&server)
        .await;

    let issuer_for_token = issuer.clone();
    let email = email.to_string();
    Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/token"))
        .respond_with(move |req: &Request| {
            token_response(req, &issuer_for_token, &signing_key, &email, email_verified)
        })
        .mount(&server)
        .await;

    Ok(FakeIdp { issuer, _server: server })
}

/// Reads `redirect_uri`/`state`/`nonce` off the `/authorize` request and
/// immediately redirects back with a code -- the nonce rides along *as* the
/// code (this fake IdP is the only party that ever reads it back), so
/// `/token` can echo it into the id_token without needing any state of its
/// own between the two calls.
fn consent_redirect(req: &Request) -> ResponseTemplate {
    let query: std::collections::HashMap<String, String> = req.url.query_pairs().into_owned().collect();
    let (Some(redirect_uri), Some(state), Some(nonce)) =
        (query.get("redirect_uri"), query.get("state"), query.get("nonce"))
    else {
        return ResponseTemplate::new(400);
    };
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let location = format!(
        "{redirect_uri}{sep}code={}&state={}",
        url::form_urlencoded::byte_serialize(nonce.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>(),
    );
    ResponseTemplate::new(303).insert_header("location", location.as_str())
}

fn token_response(
    req: &Request,
    issuer: &str,
    signing_key: &SigningKey,
    email: &str,
    email_verified: bool,
) -> ResponseTemplate {
    let body: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(&req.body).into_owned().collect();
    let Some(nonce) = body.get("code") else {
        return ResponseTemplate::new(400);
    };

    #[derive(Serialize)]
    struct IdTokenClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
        nonce: &'a str,
        email: &'a str,
        email_verified: bool,
    }

    let now = chrono::Utc::now();
    let claims = IdTokenClaims {
        iss: issuer,
        sub: SUBJECT,
        aud: CLIENT_ID,
        exp: (now + chrono::Duration::hours(1)).timestamp(),
        iat: now.timestamp(),
        nonce,
        email,
        email_verified,
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(signing_key.kid.clone());
    let id_token = jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key).expect("signing test id_token");

    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "access_token": "fake-idp-access-token",
        "token_type": "Bearer",
        "id_token": id_token,
    }))
}

/// Minimal RS256 signing key + matching published JWK, mirroring backend's
/// own `crypto::JwtKeys` (kept private to `backend`, so duplicated here
/// rather than reused across the crate boundary).
struct SigningKey {
    encoding_key: jsonwebtoken::EncodingKey,
    kid: String,
    n: String,
    e: String,
}

impl SigningKey {
    fn generate() -> anyhow::Result<Self> {
        let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)?;
        let public_key = private_key.to_public_key();
        let pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())?;
        Ok(Self {
            encoding_key,
            kid: uuid::Uuid::new_v4().to_string(),
            n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        })
    }

    fn jwk_set(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": self.kid,
                "n": self.n,
                "e": self.e,
            }]
        })
    }
}
