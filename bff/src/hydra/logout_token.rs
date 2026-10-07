use super::{Hydra, JwksError};
use crate::model::session::SessionSelector;
use chrono::{DateTime, Duration, TimeZone, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use thiserror::Error;
use uuid::Uuid;

/// The member of a logout token's `events` claim that marks it as one.
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// How old a logout token's `iat` may be. Hydra sends one the moment it logs a user out.
const MAX_AGE: Duration = Duration::minutes(10);

/// Clock skew allowed on `iat` (and on `exp`, when there is one).
const LEEWAY: Duration = Duration::seconds(60);

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum LogoutTokenError {
    #[error("logout token is not a JWT: {0}")]
    Malformed(String),
    #[error("logout token names no key")]
    NoKeyId,
    #[error(transparent)]
    Keys(#[from] JwksError),
    #[error("logout token failed verification: {0}")]
    Verification(String),
    #[error("logout token has no usable iat")]
    MissingIssuedAt,
    #[error("logout token was issued too long ago")]
    Stale,
    #[error("logout token was issued in the future")]
    IssuedInTheFuture,
    #[error("logout token is not a back-channel logout event")]
    NotALogoutEvent,
    #[error("logout token carries a nonce")]
    HasNonce,
    #[error("logout token names neither a subject nor a session")]
    NoSubjectOrSession,
    #[error("logout token's subject is not a user id")]
    SubjectNotAUuid,
    #[error("logout token has no jti")]
    MissingJti,
}

/// A verified logout token: whom it logs out, and what is needed to refuse its replay.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LogoutClaims {
    pub(crate) target: SessionSelector,
    pub(crate) jti: String,
    /// While this is in the future the token could still pass the age check, so its `jti`
    /// has to be remembered until then.
    pub(crate) replay_until: DateTime<Utc>,
}

impl Hydra {
    /// Verifies a back-channel logout token (OpenID Connect Back-Channel Logout 1.0, 2.6):
    /// signature against Hydra's JWKS, `iss`, `aud` (this client), `iat` not too old or
    /// new, `exp` if there is one, the logout `events` member, no `nonce`, a `sub` or a
    /// `sid`, and a `jti`. Remembering the `jti` against replay is the caller's job.
    pub(crate) async fn verify_logout_token(
        &self,
        raw: &str,
    ) -> Result<LogoutClaims, LogoutTokenError> {
        let header = jsonwebtoken::decode_header(raw)
            .map_err(|error| LogoutTokenError::Malformed(error.to_string()))?;
        // RFC 8725 3.11: a `typ` that is there must not mark the token as another kind; RFC 7515
        // 4.1.9 lets it carry an `application/` prefix.
        if header.typ.as_deref().is_some_and(|typ| {
            let typ = typ
                .get(..12)
                .filter(|prefix| prefix.eq_ignore_ascii_case("application/"))
                .and_then(|_| typ.get(12..))
                .unwrap_or(typ);
            !typ.eq_ignore_ascii_case("logout+jwt") && !typ.eq_ignore_ascii_case("JWT")
        }) {
            return Err(LogoutTokenError::Malformed("unexpected typ header".into()));
        }
        let kid = header.kid.ok_or(LogoutTokenError::NoKeyId)?;
        let keys = self.jwks.keys_for(Some(&kid)).await?;
        let jwk = keys
            .jwt
            .find(&kid)
            .ok_or_else(|| JwksError::UnknownKey(kid.clone()))?;
        let key = DecodingKey::from_jwk(jwk)
            .map_err(|error| LogoutTokenError::Verification(error.to_string()))?;

        // The one algorithm Hydra's keys use and the id_token check accepts; never an HMAC, so a
        // key from the JWKS can't be used as a secret.
        if header.alg != Algorithm::RS256 {
            return Err(LogoutTokenError::Verification(format!(
                "unsupported algorithm {:?}",
                header.alg
            )));
        }
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[&self.client_id]);
        // Hydra's `iss` may or may not carry a trailing `/` (see `Hydra::verify_id_token`).
        let issuer = self.public_url.trim_end_matches('/');
        validation.set_issuer(&[issuer.to_string(), format!("{issuer}/")]);
        // `exp` is checked when present but not required: Hydra's logout tokens may lack it.
        validation.required_spec_claims = ["iss", "aud"].map(str::to_string).into();
        validation.leeway = LEEWAY.num_seconds().unsigned_abs();
        let claims = jsonwebtoken::decode::<serde_json::Value>(raw, &key, &validation)
            .map_err(|error| LogoutTokenError::Verification(error.to_string()))?
            .claims;

        check_claims(&claims, Utc::now())
    }
}

/// The checks on a logout token's claims that come after its signature, issuer, audience
/// and expiry.
fn check_claims(
    claims: &serde_json::Value,
    now: DateTime<Utc>,
) -> Result<LogoutClaims, LogoutTokenError> {
    let issued_at = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .and_then(|iat| Utc.timestamp_opt(iat, 0).single())
        .ok_or(LogoutTokenError::MissingIssuedAt)?;
    if issued_at > now + LEEWAY {
        return Err(LogoutTokenError::IssuedInTheFuture);
    }
    if issued_at < now - MAX_AGE - LEEWAY {
        return Err(LogoutTokenError::Stale);
    }

    if !claims
        .get("events")
        .and_then(|events| events.get(BACKCHANNEL_LOGOUT_EVENT))
        .is_some_and(serde_json::Value::is_object)
    {
        return Err(LogoutTokenError::NotALogoutEvent);
    }
    if claims.get("nonce").is_some() {
        return Err(LogoutTokenError::HasNonce);
    }

    let text = |name: &str| {
        claims
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
    };
    let user_id = text("sub")
        .map(|sub| Uuid::parse_str(sub).map_err(|_| LogoutTokenError::SubjectNotAUuid))
        .transpose()?;
    let target = match (user_id, text("sid")) {
        (Some(user_id), Some(sid)) => SessionSelector::UserSession {
            user_id,
            sid: sid.to_string(),
        },
        (Some(user_id), None) => SessionSelector::User(user_id),
        (None, Some(sid)) => SessionSelector::Session {
            sid: sid.to_string(),
        },
        (None, None) => return Err(LogoutTokenError::NoSubjectOrSession),
    };
    let jti = text("jti").ok_or(LogoutTokenError::MissingJti)?.to_string();

    Ok(LogoutClaims {
        target,
        jti,
        replay_until: issued_at + MAX_AGE + LEEWAY,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{self as ts, CLIENT_ID, ISSUER};
    use serde_json::{Value, json};

    const SUB: &str = "5b1d3d0e-3a49-4a8f-9f43-1d1f0e0a7b11";

    fn valid() -> Value {
        json!({
            "iss": ISSUER,
            "aud": [CLIENT_ID],
            "iat": ts::now(),
            "jti": "jti-1",
            "sub": SUB,
            "sid": "sid-1",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        })
    }

    /// `valid()` with `change` applied.
    fn with(change: impl FnOnce(&mut Value)) -> Value {
        let mut claims = valid();
        change(&mut claims);
        claims
    }

    async fn hydra() -> Hydra {
        Hydra::new(&ts::config(&ts::serve_jwks().await)).unwrap()
    }

    async fn verify(token: &str) -> Result<LogoutClaims, LogoutTokenError> {
        hydra().await.verify_logout_token(token).await
    }

    #[tokio::test]
    async fn a_valid_token_for_a_user_and_a_session_ends_that_session() {
        let claims = verify(&ts::sign(&valid())).await.unwrap();

        assert_eq!(
            claims.target,
            SessionSelector::UserSession {
                user_id: Uuid::parse_str(SUB).unwrap(),
                sid: "sid-1".into()
            }
        );
        assert_eq!(claims.jti, "jti-1");
        assert!(claims.replay_until > Utc::now() + MAX_AGE);
    }

    #[tokio::test]
    async fn a_token_with_only_a_subject_ends_every_session_of_the_user() {
        let token = ts::sign(&with(|claims| {
            claims.as_object_mut().unwrap().remove("sid");
        }));

        assert_eq!(
            verify(&token).await.unwrap().target,
            SessionSelector::User(Uuid::parse_str(SUB).unwrap())
        );
    }

    #[tokio::test]
    async fn a_token_with_only_a_session_ends_that_session() {
        let token = ts::sign(&with(|claims| {
            claims.as_object_mut().unwrap().remove("sub");
        }));

        assert_eq!(
            verify(&token).await.unwrap().target,
            SessionSelector::Session {
                sid: "sid-1".into()
            }
        );
    }

    #[tokio::test]
    async fn the_audience_may_be_a_single_string_and_the_issuer_may_carry_a_slash() {
        let token = ts::sign(&with(|claims| {
            claims["aud"] = CLIENT_ID.into();
            claims["iss"] = format!("{ISSUER}/").into();
        }));

        assert!(verify(&token).await.is_ok());
    }

    #[tokio::test]
    async fn a_token_signed_by_another_key_is_refused() {
        let error = verify(&ts::sign_with_other_key(&valid()))
            .await
            .unwrap_err();

        assert!(
            matches!(error, LogoutTokenError::Verification(_)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_unsigned_token_is_refused() {
        assert!(verify(&ts::unsigned(&valid())).await.is_err());
    }

    #[tokio::test]
    async fn an_algorithm_other_than_rs256_is_refused_whoever_signed_it() {
        let error = verify(&ts::sign_rs384(&valid())).await.unwrap_err();
        assert!(
            matches!(&error, LogoutTokenError::Verification(why) if why.contains("unsupported algorithm")),
            "{error}"
        );

        // ES256 is not an algorithm of Hydra's keys either; the signature is never looked at.
        let es256 = ts::unsigned_as("ES256", &valid());
        let error = verify(&es256).await.unwrap_err();
        assert!(
            matches!(&error, LogoutTokenError::Verification(why) if why.contains("unsupported algorithm")),
            "{error}"
        );
    }

    #[tokio::test]
    async fn only_a_missing_or_logout_typ_header_is_accepted() {
        for typ in [
            None,
            Some("logout+jwt"),
            Some("JWT"),
            Some("application/logout+jwt"),
            Some("Application/JWT"),
        ] {
            assert!(
                verify(&ts::sign_with_typ(typ, &valid())).await.is_ok(),
                "{typ:?}"
            );
        }
        for typ in [
            "at+jwt",
            "secevent+jwt",
            "application/at+jwt",
            "application/",
        ] {
            let error = verify(&ts::sign_with_typ(Some(typ), &valid()))
                .await
                .unwrap_err();
            assert!(
                matches!(error, LogoutTokenError::Malformed(_)),
                "{typ}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn a_token_without_a_key_id_is_refused() {
        let header = jsonwebtoken::Header::new(Algorithm::RS256);
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(
            include_str!("../../tests/fixtures/hydra_key.pem").as_bytes(),
        )
        .unwrap();
        let token = jsonwebtoken::encode(&header, &valid(), &key).unwrap();

        assert_eq!(verify(&token).await.unwrap_err(), LogoutTokenError::NoKeyId);
    }

    #[tokio::test]
    async fn a_token_naming_a_key_hydra_does_not_publish_is_refused() {
        let error = verify(&ts::sign_under_kid("rotated-away", &valid()))
            .await
            .unwrap_err();

        assert_eq!(
            error,
            LogoutTokenError::Keys(JwksError::UnknownKey("rotated-away".into()))
        );
    }

    #[tokio::test]
    async fn a_token_from_another_issuer_or_for_another_client_is_refused() {
        for claims in [
            with(|claims| claims["iss"] = "https://evil.test".into()),
            with(|claims| claims["iss"] = format!("{ISSUER}.evil.test").into()),
            with(|claims| claims["aud"] = json!(["another-client"])),
            with(|claims| claims["aud"] = json!(["another-client", "yet-another"])),
            with(|claims| {
                claims.as_object_mut().unwrap().remove("aud");
            }),
            with(|claims| {
                claims.as_object_mut().unwrap().remove("iss");
            }),
        ] {
            let error = verify(&ts::sign(&claims)).await.unwrap_err();
            assert!(
                matches!(error, LogoutTokenError::Verification(_)),
                "{claims}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn exp_is_checked_when_present_and_not_required() {
        let expired = ts::sign(&with(|claims| claims["exp"] = (ts::now() - 3600).into()));
        let current = ts::sign(&with(|claims| claims["exp"] = (ts::now() + 3600).into()));

        assert!(matches!(
            verify(&expired).await.unwrap_err(),
            LogoutTokenError::Verification(_)
        ));
        assert!(verify(&current).await.is_ok());
    }

    #[tokio::test]
    async fn iat_must_be_present_recent_and_not_in_the_future() {
        let missing = with(|claims| {
            claims.as_object_mut().unwrap().remove("iat");
        });
        let stale = with(|claims| claims["iat"] = (ts::now() - 3600).into());
        let future = with(|claims| claims["iat"] = (ts::now() + 3600).into());
        let just_inside = with(|claims| claims["iat"] = (ts::now() - 300).into());

        assert_eq!(
            verify(&ts::sign(&missing)).await.unwrap_err(),
            LogoutTokenError::MissingIssuedAt
        );
        assert_eq!(
            verify(&ts::sign(&stale)).await.unwrap_err(),
            LogoutTokenError::Stale
        );
        assert_eq!(
            verify(&ts::sign(&future)).await.unwrap_err(),
            LogoutTokenError::IssuedInTheFuture
        );
        assert!(verify(&ts::sign(&just_inside)).await.is_ok());
    }

    #[test]
    fn the_issued_at_window_is_ten_minutes_back_and_a_minute_ahead_to_the_second() {
        let now = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let at = |offset: Duration| {
            let iat = (now + offset).timestamp();
            check_claims(&with(|claims| claims["iat"] = iat.into()), now)
        };

        assert!(at(LEEWAY).is_ok());
        assert_eq!(
            at(LEEWAY + Duration::seconds(1)).unwrap_err(),
            LogoutTokenError::IssuedInTheFuture
        );
        assert!(at(-MAX_AGE - LEEWAY).is_ok());
        assert_eq!(
            at(-MAX_AGE - LEEWAY - Duration::seconds(1)).unwrap_err(),
            LogoutTokenError::Stale
        );
    }

    #[tokio::test]
    async fn the_logout_event_must_be_there_as_an_object() {
        for events in [
            json!({}),
            json!({ "http://schemas.openid.net/event/other": {} }),
            json!({ BACKCHANNEL_LOGOUT_EVENT: "yes" }),
            json!({ BACKCHANNEL_LOGOUT_EVENT: null }),
            json!([BACKCHANNEL_LOGOUT_EVENT]),
            json!(null),
        ] {
            let token = ts::sign(&with(|claims| claims["events"] = events.clone()));
            assert_eq!(
                verify(&token).await.unwrap_err(),
                LogoutTokenError::NotALogoutEvent,
                "{events}"
            );
        }
        let no_events = ts::sign(&with(|claims| {
            claims.as_object_mut().unwrap().remove("events");
        }));
        assert_eq!(
            verify(&no_events).await.unwrap_err(),
            LogoutTokenError::NotALogoutEvent
        );
    }

    #[tokio::test]
    async fn a_token_with_a_nonce_is_an_id_token_and_is_refused() {
        for nonce in [json!("n-0S6_WzA2Mj"), json!(null), json!("")] {
            let token = ts::sign(&with(|claims| claims["nonce"] = nonce.clone()));
            assert_eq!(
                verify(&token).await.unwrap_err(),
                LogoutTokenError::HasNonce,
                "{nonce}"
            );
        }
    }

    #[tokio::test]
    async fn a_token_needs_a_subject_or_session_and_a_user_id_subject() {
        let neither = with(|claims| {
            let claims = claims.as_object_mut().unwrap();
            claims.remove("sub");
            claims.remove("sid");
        });
        let empty = with(|claims| {
            claims["sub"] = "".into();
            claims["sid"] = "".into();
        });
        let not_a_uuid = with(|claims| claims["sub"] = "alice".into());

        for claims in [neither, empty] {
            assert_eq!(
                verify(&ts::sign(&claims)).await.unwrap_err(),
                LogoutTokenError::NoSubjectOrSession
            );
        }
        assert_eq!(
            verify(&ts::sign(&not_a_uuid)).await.unwrap_err(),
            LogoutTokenError::SubjectNotAUuid
        );
    }

    #[tokio::test]
    async fn a_token_needs_a_jti() {
        for claims in [
            with(|claims| {
                claims.as_object_mut().unwrap().remove("jti");
            }),
            with(|claims| claims["jti"] = "".into()),
            with(|claims| claims["jti"] = 5.into()),
        ] {
            assert_eq!(
                verify(&ts::sign(&claims)).await.unwrap_err(),
                LogoutTokenError::MissingJti
            );
        }
    }

    #[tokio::test]
    async fn garbage_is_not_a_token() {
        for garbage in ["", "abc", "a.b.c", "....", "eyJhbGciOiJSUzI1NiJ9.e30."] {
            assert!(verify(garbage).await.is_err(), "{garbage}");
        }
    }
}
