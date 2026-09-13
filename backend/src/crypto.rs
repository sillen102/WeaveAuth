use std::sync::LazyLock;

use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::EncodingKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Serialize;

/// Shared, lazily-built Argon2 instance -- constructing one just fills in
/// algorithm/version/params (no expensive setup), but there's no reason for
/// every hash/verify call site to build its own copy.
pub(crate) static ARGON2: LazyLock<Argon2<'static>> = LazyLock::new(Argon2::default);

/// One JSON Web Key, as served at `/.well-known/jwks.json` (RFC 7517).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Jwk {
    kty: &'static str,
    #[serde(rename = "use")]
    use_: &'static str,
    alg: &'static str,
    kid: String,
    n: String,
    e: String,
}

#[derive(Clone)]
pub(crate) struct JwtKeys {
    pub(crate) encoding_key: EncodingKey,
    pub(crate) kid: String,
    jwk: Jwk,
}

impl JwtKeys {
    pub(crate) fn generate() -> anyhow::Result<Self> {
        let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)?;
        let public_key = private_key.to_public_key();

        let pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())?;

        let kid = uuid::Uuid::new_v4().to_string();
        let jwk = Jwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: kid.clone(),
            n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        };

        Ok(Self {
            encoding_key,
            kid,
            jwk,
        })
    }

    pub(crate) fn jwk_set(&self) -> serde_json::Value {
        serde_json::json!({ "keys": [self.jwk] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, Header, Validation};
    use serde::Deserialize;

    #[derive(Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: i64,
    }

    /// The published JWKS must actually verify a token signed by this same
    /// keypair -- the property the JWKS endpoint exists to serve.
    #[test]
    fn published_jwk_verifies_a_token_signed_by_the_same_key() {
        let keys = JwtKeys::generate().expect("keygen");

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(keys.kid.clone());
        let claims = Claims {
            sub: "user-1".into(),
            exp: chrono::Utc::now().timestamp() + 3600,
        };
        let token = encode(&header, &claims, &keys.encoding_key).expect("signing");

        let jwk_set = keys.jwk_set();
        let jwk = &jwk_set["keys"][0];
        assert_eq!(jwk["kid"], keys.kid);

        let decoding_key = DecodingKey::from_rsa_components(
            jwk["n"].as_str().expect("n is a string"),
            jwk["e"].as_str().expect("e is a string"),
        )
        .expect("valid RSA components");
        let decoded = decode::<Claims>(&token, &decoding_key, &Validation::new(Algorithm::RS256))
            .expect("verifies against the published jwk");

        assert_eq!(decoded.claims.sub, "user-1");
    }
}
