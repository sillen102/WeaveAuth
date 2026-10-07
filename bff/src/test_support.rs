//! A stand-in for Hydra's signing keys, shared by the unit tests that verify what Hydra signs.

use crate::config::Config;
use axum::Router;
use axum::routing::get;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use sha2::{Digest, Sha256};

pub(crate) const KID: &str = "test-kid";
pub(crate) const ISSUER: &str = "https://login.test";
pub(crate) const CLIENT_ID: &str = "weaveauth-bff";

const KEY: &str = include_str!("../tests/fixtures/hydra_key.pem");
const OTHER_KEY: &str = include_str!("../tests/fixtures/other_key.pem");
const JWK: &str = include_str!("../tests/fixtures/hydra_jwk.json");

pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// `claims` as a JWT signed by Hydra's key.
pub(crate) fn sign(claims: &serde_json::Value) -> String {
    sign_with(KEY, KID, claims)
}

/// `claims` as a JWT signed by a key Hydra does not publish, under Hydra's `kid`.
pub(crate) fn sign_with_other_key(claims: &serde_json::Value) -> String {
    sign_with(OTHER_KEY, KID, claims)
}

pub(crate) fn sign_under_kid(kid: &str, claims: &serde_json::Value) -> String {
    sign_with(KEY, kid, claims)
}

/// Signed by Hydra's key, but with an algorithm bff does not accept.
pub(crate) fn sign_rs384(claims: &serde_json::Value) -> String {
    sign_alg(Algorithm::RS384, KEY, KID, claims)
}

/// Signed by Hydra's key, with the header's `typ` set to `typ` (or absent).
pub(crate) fn sign_with_typ(typ: Option<&str>, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());
    header.typ = typ.map(str::to_string);
    let key = EncodingKey::from_rsa_pem(KEY.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, claims, &key).unwrap()
}

fn sign_with(pem: &str, kid: &str, claims: &serde_json::Value) -> String {
    sign_alg(Algorithm::RS256, pem, kid, claims)
}

fn sign_alg(alg: Algorithm, pem: &str, kid: &str, claims: &serde_json::Value) -> String {
    let mut header = Header::new(alg);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, claims, &key).unwrap()
}

/// A JWS whose header says `alg: none`, with no signature.
pub(crate) fn unsigned(claims: &serde_json::Value) -> String {
    unsigned_as("none", claims)
}

/// A JWS whose header names `alg` and Hydra's `kid`, with no signature.
pub(crate) fn unsigned_as(alg: &str, claims: &serde_json::Value) -> String {
    let encode = |value: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    };
    format!(
        "{}.{}.",
        encode(&serde_json::json!({"alg": alg, "kid": KID})),
        encode(claims)
    )
}

pub(crate) fn jwks() -> serde_json::Value {
    let mut jwk: serde_json::Value = serde_json::from_str(JWK).unwrap();
    jwk["kid"] = KID.into();
    serde_json::json!({ "keys": [jwk] })
}

/// `at_hash` of an access token (OIDC Core 3.1.3.6): the left half of its SHA-256.
pub(crate) fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

/// Serves Hydra's JWKS; returns the base URL.
pub(crate) async fn serve_jwks() -> String {
    let router = Router::new().route(
        "/.well-known/jwks.json",
        get(|| async { axum::Json(jwks()) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await });
    url
}

pub(crate) fn config(hydra_internal_url: &str) -> Config {
    Config {
        bff_url: "https://bff.test".into(),
        hydra_public_url: ISSUER.into(),
        hydra_internal_url: hydra_internal_url.into(),
        bff_client_id: CLIENT_ID.into(),
        bff_client_secret: "client-secret".to_string().into(),
        ..Config::default()
    }
}
