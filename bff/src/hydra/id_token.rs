use super::{Hydra, JwksError, jws_kid, same_issuer, unverified_part};
use openidconnect::core::{CoreIdToken, CoreIdTokenVerifier};
use openidconnect::{AccessToken, AccessTokenHash, ClientId, IssuerUrl, Nonce};
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum IdTokenError {
    #[error("id_token is not a JWT: {0}")]
    Malformed(String),
    #[error(transparent)]
    Keys(#[from] JwksError),
    #[error("id_token issuer {0:?} is not Hydra's")]
    WrongIssuer(String),
    #[error("id_token failed verification: {0}")]
    Verification(String),
    #[error("id_token's at_hash does not match the access token")]
    AccessTokenHashMismatch,
    #[error("id_token's at_hash could not be checked: {0}")]
    AccessTokenHashUnchecked(String),
    #[error("id_token's subject is not a user id")]
    SubjectNotAUuid,
}

/// What a verified id_token says about who logged in.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedIdToken {
    pub(crate) user_id: Uuid,
    /// Hydra's login session id.
    pub(crate) sid: Option<String>,
}

impl Hydra {
    /// Verifies the id_token a code exchange returned: its signature against Hydra's JWKS,
    /// issuer, audience (this client), expiry, the `nonce` sent with the login and, when
    /// there is one, the `at_hash` binding it to `access_token`.
    pub(crate) async fn verify_id_token(
        &self,
        raw: &str,
        access_token: &str,
        nonce: &str,
    ) -> Result<VerifiedIdToken, IdTokenError> {
        let id_token = CoreIdToken::from_str(raw)
            .map_err(|error| IdTokenError::Malformed(error.to_string()))?;
        let keys = self.jwks.keys_for(jws_kid(raw).as_deref()).await?;

        // Hydra's `iss` may differ from the configured URL by a trailing `/`. The verifier
        // compares it exactly, so it is given the token's own, once it is the configured one.
        let payload = unverified_part(raw, 1);
        let issuer = payload
            .as_ref()
            .and_then(|claims| claims.get("iss")?.as_str())
            .unwrap_or_default()
            .to_string();
        if !same_issuer(&issuer, &self.public_url) {
            return Err(IdTokenError::WrongIssuer(issuer));
        }
        let issuer_url =
            IssuerUrl::new(issuer.clone()).map_err(|_| IdTokenError::WrongIssuer(issuer))?;

        // Allows RS256 only, by openidconnect's default, as `verify_logout_token` does.
        let verifier = CoreIdTokenVerifier::new_public_client(
            ClientId::new(self.client_id.clone()),
            issuer_url,
            keys.openid.clone(),
        );
        let claims = id_token
            .claims(&verifier, &Nonce::new(nonce.to_string()))
            .map_err(|error| IdTokenError::Verification(error.to_string()))?;

        if let Some(expected) = claims.access_token_hash() {
            let unchecked = |error: &dyn std::fmt::Display| {
                IdTokenError::AccessTokenHashUnchecked(error.to_string())
            };
            let alg = id_token.signing_alg().map_err(|error| unchecked(&error))?;
            let key = id_token
                .signing_key(&verifier)
                .map_err(|error| unchecked(&error))?;
            let access_token = AccessToken::new(access_token.to_string());
            let actual = AccessTokenHash::from_token(&access_token, alg, key)
                .map_err(|error| unchecked(&error))?;
            if actual != *expected {
                return Err(IdTokenError::AccessTokenHashMismatch);
            }
        }

        let user_id = Uuid::parse_str(claims.subject().as_str())
            .map_err(|_| IdTokenError::SubjectNotAUuid)?;
        // `sid` is not a claim `openidconnect` models; the token is verified by now.
        let sid = payload
            .as_ref()
            .and_then(|claims| claims.get("sid")?.as_str())
            .map(str::to_string);
        Ok(VerifiedIdToken { user_id, sid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{self as ts, CLIENT_ID, ISSUER};
    use serde_json::{Value, json};

    const SUB: &str = "5b1d3d0e-3a49-4a8f-9f43-1d1f0e0a7b11";
    const NONCE: &str = "the-nonce";
    const ACCESS_TOKEN: &str = "the-access-token";

    fn valid() -> Value {
        json!({
            "iss": ISSUER,
            "aud": [CLIENT_ID],
            "sub": SUB,
            "sid": "sid-1",
            "iat": ts::now(),
            "exp": ts::now() + 3600,
            "nonce": NONCE,
            "at_hash": ts::at_hash(ACCESS_TOKEN),
        })
    }

    fn with(change: impl FnOnce(&mut Value)) -> Value {
        let mut claims = valid();
        change(&mut claims);
        claims
    }

    async fn verify(token: &str) -> Result<VerifiedIdToken, IdTokenError> {
        let hydra = Hydra::new(&ts::config(&ts::serve_jwks().await)).unwrap();
        hydra.verify_id_token(token, ACCESS_TOKEN, NONCE).await
    }

    #[tokio::test]
    async fn a_valid_id_token_yields_the_user_and_the_session() {
        let verified = verify(&ts::sign(&valid())).await.unwrap();

        assert_eq!(
            verified,
            VerifiedIdToken {
                user_id: Uuid::parse_str(SUB).unwrap(),
                sid: Some("sid-1".into())
            }
        );
    }

    #[tokio::test]
    async fn the_sid_and_the_at_hash_are_optional_and_the_issuer_may_carry_a_slash() {
        let token = ts::sign(&with(|claims| {
            let claims = claims.as_object_mut().unwrap();
            claims.remove("sid");
            claims.remove("at_hash");
        }));
        let slash = ts::sign(&with(|claims| claims["iss"] = format!("{ISSUER}/").into()));

        assert_eq!(verify(&token).await.unwrap().sid, None);
        assert!(verify(&slash).await.is_ok());
    }

    #[tokio::test]
    async fn a_token_signed_by_another_key_or_unsigned_is_refused() {
        for token in [ts::sign_with_other_key(&valid()), ts::unsigned(&valid())] {
            let error = verify(&token).await.unwrap_err();
            assert!(matches!(error, IdTokenError::Verification(_)), "{error}");
        }
    }

    #[tokio::test]
    async fn an_algorithm_other_than_rs256_is_refused_whoever_signed_it() {
        for token in [ts::sign_rs384(&valid()), ts::unsigned_as("ES256", &valid())] {
            let error = verify(&token).await.unwrap_err();
            assert!(matches!(error, IdTokenError::Verification(_)), "{error}");
        }
    }

    #[tokio::test]
    async fn a_token_from_another_issuer_is_refused() {
        for issuer in ["https://evil.test", "https://login.test.evil.test"] {
            let token = ts::sign(&with(|claims| claims["iss"] = issuer.into()));
            let error = verify(&token).await.unwrap_err();
            assert_eq!(error, IdTokenError::WrongIssuer(issuer.into()));
        }
        let no_issuer = ts::sign(&with(|claims| {
            claims.as_object_mut().unwrap().remove("iss");
        }));
        assert!(verify(&no_issuer).await.is_err());
    }

    #[tokio::test]
    async fn a_token_for_another_client_is_refused() {
        for aud in [json!(["another-client"]), json!("another-client")] {
            let token = ts::sign(&with(|claims| claims["aud"] = aud.clone()));
            let error = verify(&token).await.unwrap_err();
            assert!(
                matches!(error, IdTokenError::Verification(_)),
                "{aud}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn a_token_with_another_nonce_or_none_is_refused() {
        let other = ts::sign(&with(|claims| claims["nonce"] = "another".into()));
        let none = ts::sign(&with(|claims| {
            claims.as_object_mut().unwrap().remove("nonce");
        }));

        for token in [other, none] {
            let error = verify(&token).await.unwrap_err();
            assert!(matches!(error, IdTokenError::Verification(_)), "{error}");
        }
    }

    #[tokio::test]
    async fn an_expired_token_is_refused() {
        let token = ts::sign(&with(|claims| claims["exp"] = (ts::now() - 3600).into()));

        let error = verify(&token).await.unwrap_err();

        assert!(matches!(error, IdTokenError::Verification(_)), "{error}");
    }

    #[tokio::test]
    async fn a_token_bound_to_another_access_token_is_refused() {
        let token = ts::sign(&with(|claims| {
            claims["at_hash"] = ts::at_hash("stolen").into()
        }));

        assert_eq!(
            verify(&token).await.unwrap_err(),
            IdTokenError::AccessTokenHashMismatch
        );
    }

    #[tokio::test]
    async fn a_subject_that_is_not_a_user_id_is_refused() {
        let token = ts::sign(&with(|claims| claims["sub"] = "alice".into()));

        assert_eq!(
            verify(&token).await.unwrap_err(),
            IdTokenError::SubjectNotAUuid
        );
    }

    #[tokio::test]
    async fn a_token_naming_an_unknown_key_or_no_jwt_at_all_is_refused() {
        let unknown = ts::sign_under_kid("rotated-away", &valid());

        assert!(matches!(
            verify(&unknown).await.unwrap_err(),
            IdTokenError::Keys(JwksError::UnknownKey(_))
        ));
        assert!(matches!(
            verify("not-a-jwt").await.unwrap_err(),
            IdTokenError::Malformed(_)
        ));
    }
}
