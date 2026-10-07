//! A fake OpenID Connect provider (Google's stand-in) that Kratos signs users in with as a
//! generic provider. Several issuers share one server, each asserting one fixed identity;
//! `/authorize` consents instantly, so a plain HTTP client can drive the whole flow.

use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

pub const CLIENT_ID: &str = "kratos";

/// Throwaway key, only ever trusted by the Kratos of a system test.
const KEY_PEM: &str = include_str!("../../fixtures/idp_key.pem");
const KEY_N: &str = "tEKf-nMS_hzObIURgfaFCrWxX-qXwPRBt1psVgcPTVLm7aAXgRT_hd24tZKbMyPq3nhhXnSGTIW9HdbpFeJseCSYVj-fGGEL60IzsNb9yJUs31wZtlCAXp-C2wLWTCX5-h7rs_S8_LYfAT9NOcED8HpUBsyPWzGlJ0pm77OII8rS1vhIIOYsRnvrA9xHohjca4ocHj0G6W6WVZgLPnYA94w9vVT82zE6fQrXz_kPjPR9PqfkAr-r7ZvMQ3L-tgWfH9mIto5FJur7uqzpfFQd1oaiQQ_2sZbN8GoeaPZfdFBfQpoxv5DqptKiUcQNkSLcqES7ZAZ83TYeYEk9uABm_w";
const KID: &str = "system-test-idp";

/// One issuer: `/{id}/...` asserts this identity.
pub struct Identity {
    pub id: &'static str,
    pub sub: &'static str,
    pub email: &'static str,
    pub email_verified: bool,
    pub name: &'static str,
    /// Google sends none; the identity must still sign up without a registration form.
    pub phone_number: Option<&'static str>,
    /// Single-name Google accounts have none, which leaves a required trait unmapped.
    pub family_name: Option<&'static str>,
}

/// Each test uses its own issuer, so identities never meet across tests.
pub const IDENTITIES: &[Identity] = &[
    Identity {
        id: "verified",
        sub: "idp-sub-verified",
        email: "idp-user@example.test",
        email_verified: true,
        name: "IdP User",
        phone_number: Some("+46701234567"),
        family_name: Some("User"),
    },
    Identity {
        id: "unverified",
        sub: "idp-sub-unverified",
        email: "idp-unverified@example.test",
        email_verified: false,
        name: "IdP Unverified",
        phone_number: Some("+46701234567"),
        family_name: Some("User"),
    },
    Identity {
        id: "link",
        sub: "idp-sub-link",
        email: "pw-user@example.test",
        email_verified: true,
        name: "Linked User",
        phone_number: Some("+46701234567"),
        family_name: Some("User"),
    },
    Identity {
        id: "recover",
        sub: "recover-sub",
        email: "recover-user@example.test",
        email_verified: true,
        name: "Recovered User",
        phone_number: Some("+46701234567"),
        family_name: Some("User"),
    },
    Identity {
        id: "nophone",
        sub: "idp-sub-nophone",
        email: "idp-nophone@example.test",
        email_verified: true,
        name: "No Phone",
        phone_number: None,
        family_name: Some("User"),
    },
    Identity {
        id: "nolast",
        sub: "idp-sub-nolast",
        email: "idp-nolast@example.test",
        email_verified: true,
        name: "Madonna",
        phone_number: Some("+46701234567"),
        family_name: None,
    },
    Identity {
        id: "tamper",
        sub: "idp-sub-tamper",
        email: "idp-tamper@example.test",
        email_verified: true,
        name: "Tamper",
        phone_number: Some("+46701234567"),
        family_name: None,
    },
];

#[derive(Clone)]
struct Idp {
    /// `http://host.docker.internal:PORT`: how Kratos and the browser both reach this server.
    base: Arc<str>,
}

pub fn router(base: &str) -> Router {
    Router::new()
        .route("/{id}/.well-known/openid-configuration", get(discovery))
        .route("/{id}/jwks", get(jwks))
        .route("/{id}/authorize", get(authorize))
        .route("/{id}/token", post(token))
        .with_state(Idp { base: base.into() })
}

fn identity(id: &str) -> Option<&'static Identity> {
    IDENTITIES.iter().find(|i| i.id == id)
}

async fn discovery(State(idp): State<Idp>, Path(id): Path<String>) -> impl IntoResponse {
    if identity(&id).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let issuer = format!("{}/{id}", idp.base);
    axum::Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
    .into_response()
}

async fn jwks() -> impl IntoResponse {
    axum::Json(json!({"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": KEY_N, "e": "AQAB",
    }]}))
}

/// The nonce (when Kratos sends one) rides along as the code, so `/token` needs no state
/// between the two calls.
async fn authorize(Query(query): Query<HashMap<String, String>>) -> impl IntoResponse {
    let (Some(redirect_uri), Some(state)) = (query.get("redirect_uri"), query.get("state")) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let nonce = query.get("nonce").map_or("", String::as_str);
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let encode = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    Redirect::to(&format!(
        "{redirect_uri}{sep}code={}&state={}",
        encode(&format!("c{}", URL_SAFE_NO_PAD.encode(nonce))),
        encode(state)
    ))
    .into_response()
}

async fn token(
    State(idp): State<Idp>,
    Path(id): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (Some(identity), Some(code)) = (identity(&id), form.get("code")) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(nonce) = code
        .strip_prefix('c')
        .and_then(|code| URL_SAFE_NO_PAD.decode(code).ok())
        .and_then(|n| String::from_utf8(n).ok())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": format!("{}/{id}", idp.base), "sub": identity.sub, "aud": CLIENT_ID,
        "iat": now, "exp": now + 3600,
        "email": identity.email, "email_verified": identity.email_verified, "name": identity.name,
        "given_name": "Idp",
    });
    let mut claims = claims;
    if let Some(family_name) = identity.family_name {
        claims["family_name"] = json!(family_name);
    }
    if let Some(phone) = identity.phone_number {
        claims["phone_number"] = json!(phone);
    }
    if !nonce.is_empty() {
        claims["nonce"] = json!(nonce);
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(KID.to_string());
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(KEY_PEM.as_bytes()).expect("idp key");
    let id_token = jsonwebtoken::encode(&header, &claims, &key).expect("sign id_token");
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({
            "access_token": "fake-idp-access-token", "token_type": "Bearer", "id_token": id_token,
        })),
    )
        .into_response()
}

/// The Kratos config file that registers the providers (`fake`, `fakeu`, `fakelink`, `fakerecover`, `fakenophone`, `fakenolast`, `faketamper`).
pub fn kratos_providers(base: &str) -> String {
    let provider = |id: &str, issuer: &str| {
        format!(
            "          - {{id: {id}, provider: generic, label: Fake {id}, client_id: {CLIENT_ID}, \
             client_secret: s, issuer_url: \"{base}/{issuer}\", \
             mapper_url: \"file:///etc/kratos/oidc/generic.jsonnet\", scope: [openid, email, profile]}}\n"
        )
    };
    format!(
        "selfservice:\n  methods:\n    oidc:\n      config:\n        providers:\n{}{}{}{}{}{}{}",
        provider("fake", "verified"),
        provider("fakeu", "unverified"),
        provider("fakelink", "link"),
        provider("fakerecover", "recover"),
        provider("fakenophone", "nophone"),
        provider("fakenolast", "nolast"),
        provider("faketamper", "tamper"),
    )
}
