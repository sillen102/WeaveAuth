use std::sync::LazyLock;

use argon2::password_hash::phc::PasswordHash as Argon2PasswordHash;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::EncodingKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::model::user::PasswordHash;

/// Shared, lazily-built Argon2 instance -- constructing one just fills in
/// algorithm/version/params (no expensive setup), but there's no reason for
/// every hash/verify call site to build its own copy.
pub(crate) static ARGON2: LazyLock<Argon2<'static>> = LazyLock::new(Argon2::default);

/// Hashes `password` with argon2, off the tokio worker thread (argon2 is
/// deliberately CPU-heavy, synchronous work).
pub(crate) async fn hash_password(password: SecretString) -> anyhow::Result<String> {
    let result = tokio::task::spawn_blocking(move || {
        ARGON2.hash_password(password.expose_secret().as_bytes()).map(|h| h.to_string())
    })
    .await?
    .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"));

    if let Err(e) = &result {
        tracing::warn!(error = %e, "argon2 hashing failed");
    }

    result
}

/// A wrong password is an expected outcome, not an error -- kept out of
/// `PasswordVerifyError` so callers aren't tempted to treat it as one.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub(crate) enum PasswordVerifyOutcome {
    Verified,
    NotVerified,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PasswordVerifyError {
    /// Stored hash didn't parse, its bcrypt cost was rejected, or the
    /// verification task panicked.
    #[error("password verification errored: {0}")]
    Error(#[from] anyhow::Error),
}

/// Verifies `password` against a stored, scheme-tagged hash. `max_bcrypt_cost`
/// caps how expensive a `Bcrypt` hash's own cost factor is allowed to be (see
/// `Config::max_bcrypt_cost`) -- an imported hash claiming an inflated cost
/// could otherwise tie up a blocking-pool thread for a very long time. Note:
/// unlike argon2 logins, bcrypt verification time still varies with the
/// hash's cost, so it isn't covered by the dummy-hash timing guard callers
/// use for unknown emails -- the cap bounds that leak but doesn't close it.
pub(crate) async fn verify_password(
    hash: PasswordHash,
    password: SecretString,
    max_bcrypt_cost: u32,
) -> Result<PasswordVerifyOutcome, PasswordVerifyError> {
    let result = tokio::task::spawn_blocking(move || match hash {
        PasswordHash::Argon2(s) => match Argon2PasswordHash::new(s.expose_secret()) {
            Ok(parsed) if ARGON2.verify_password(password.expose_secret().as_bytes(), &parsed).is_ok() => {
                Ok(PasswordVerifyOutcome::Verified)
            }
            Ok(_) => Ok(PasswordVerifyOutcome::NotVerified),
            Err(e) => Err(anyhow::anyhow!("stored argon2 hash didn't parse: {e}").into()),
        },
        PasswordHash::Bcrypt(s) => match bcrypt_cost(s.expose_secret()) {
            Some(cost) if cost <= max_bcrypt_cost => match bcrypt::verify(password.expose_secret(), s.expose_secret()) {
                Ok(true) => Ok(PasswordVerifyOutcome::Verified),
                Ok(false) => Ok(PasswordVerifyOutcome::NotVerified),
                Err(e) => Err(anyhow::anyhow!("bcrypt verification failed: {e}").into()),
            },
            Some(cost) => Err(anyhow::anyhow!("bcrypt cost {cost} exceeds the allowed maximum").into()),
            None => Err(anyhow::anyhow!("stored bcrypt hash didn't parse").into()),
        },
    })
    .await
    .unwrap_or_else(|e| Err(anyhow::Error::from(e).into()));

    if let Err(PasswordVerifyError::Error(e)) = &result {
        tracing::warn!(error = %e, "password verification errored");
    }

    result
}

/// Reads the cost factor out of a `$2b$NN$...`-shaped bcrypt hash, without
/// running the (expensive) verification itself.
fn bcrypt_cost(hash: &str) -> Option<u32> {
    hash.get(4..6)?.parse().ok()
}

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

    #[tokio::test]
    async fn verify_password_rejects_bcrypt_hashes_above_the_cost_cap() {
        let max_cost = 12;
        let inflated = format!("$2b${}$abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx", max_cost + 1);

        let result = verify_password(PasswordHash::Bcrypt(inflated.into()), "whatever".into(), max_cost).await;

        assert!(result.is_err());
    }
}
