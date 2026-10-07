pub(crate) use controller::revoke;

mod controller {
    use axum::extract::{FromRequestParts, State};
    use axum::http::request::Parts;
    use axum::http::{HeaderMap, StatusCode, header};
    use common::extract::ApiJson;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;
    use uuid::Uuid;

    use crate::server::AppState;

    use super::service::{self, RevokeServiceError};

    #[derive(Deserialize)]
    pub(crate) struct RevokeRequest {
        /// The user whose sessions end: the Kratos identity id.
        pub(super) sub: Uuid,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum RevokeError {
        #[error("missing or invalid API key")]
        #[error_response(StatusCode::UNAUTHORIZED, details = "missing or invalid API key")]
        Unauthorized,
    }

    impl From<RevokeServiceError> for RevokeError {
        fn from(err: RevokeServiceError) -> Self {
            tracing::warn!(%err, "internal revoke refused");
            match err {
                RevokeServiceError::MissingKey
                | RevokeServiceError::WrongKey
                | RevokeServiceError::NoKeyConfigured => RevokeError::Unauthorized,
            }
        }
    }

    /// The token of an `Authorization: Bearer <token>` header, `None` for any other scheme.
    pub(super) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token)
    }

    /// Proof that the request carried the internal API key. As an extractor it runs before
    /// the body is read, so an unauthorized caller never gets as far as parsing.
    pub(crate) struct InternalApiKey;

    impl FromRequestParts<AppState> for InternalApiKey {
        type Rejection = RevokeError;

        async fn from_request_parts(
            parts: &mut Parts,
            state: &AppState,
        ) -> Result<Self, Self::Rejection> {
            service::authorize(bearer_token(&parts.headers), &state.config.internal_api_key)?;
            Ok(Self)
        }
    }

    /// Ends every session of a user, for hooks to call after a recovery or a password change.
    pub(crate) async fn revoke(
        State(mut state): State<AppState>,
        _key: InternalApiKey,
        ApiJson(request): ApiJson<RevokeRequest>,
    ) -> StatusCode {
        service::revoke_user(&mut state, request.sub).await;
        StatusCode::NO_CONTENT
    }
}

mod service {
    use secrecy::{ExposeSecret, SecretString};
    use thiserror::Error;
    use uuid::Uuid;

    use crate::model::session::SessionSelector;
    use crate::server::AppState;
    use crate::server::secrets::constant_time_eq;

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum RevokeServiceError {
        #[error("no bearer token in the Authorization header")]
        MissingKey,
        #[error("the bearer token is not the internal API key")]
        WrongKey,
        #[error("no internal API key is configured")]
        NoKeyConfigured,
    }

    /// Checks the bearer token the request presented against the configured key, in constant
    /// time. An unset key refuses everyone rather than accepting an empty bearer.
    pub(crate) fn authorize(
        presented: Option<&str>,
        expected: &SecretString,
    ) -> Result<(), RevokeServiceError> {
        let expected = expected.expose_secret();
        if expected.is_empty() {
            return Err(RevokeServiceError::NoKeyConfigured);
        }
        let presented = presented.ok_or(RevokeServiceError::MissingKey)?;
        if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
            Ok(())
        } else {
            Err(RevokeServiceError::WrongKey)
        }
    }

    pub(crate) async fn revoke_user(state: &mut AppState, user_id: Uuid) {
        state.end_sessions(&SessionSelector::User(user_id)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::controller::bearer_token;
    use super::service::{RevokeServiceError, authorize};
    use axum::http::{HeaderMap, HeaderValue, header};
    use secrecy::SecretString;

    fn headers(authorization: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(authorization).unwrap(),
        );
        headers
    }

    fn key(key: &str) -> SecretString {
        key.to_string().into()
    }

    #[test]
    fn the_bearer_token_is_what_follows_the_bearer_scheme() {
        assert_eq!(bearer_token(&headers("Bearer k3y")), Some("k3y"));
        assert_eq!(bearer_token(&headers("bearer k3y")), Some("k3y"));
        assert_eq!(bearer_token(&headers("Bearer ")), Some(""));
        assert_eq!(bearer_token(&headers("Bearer x k3y")), Some("x k3y"));
    }

    #[test]
    fn any_other_authorization_has_no_bearer_token() {
        assert_eq!(bearer_token(&HeaderMap::new()), None);
        for presented in ["k3y", "Basic k3y", "Bearerk3y"] {
            assert_eq!(bearer_token(&headers(presented)), None, "{presented}");
        }
    }

    #[test]
    fn the_configured_key_is_accepted() {
        assert_eq!(authorize(Some("k3y"), &key("k3y")), Ok(()));
    }

    #[test]
    fn anything_else_is_refused() {
        assert_eq!(
            authorize(None, &key("k3y")),
            Err(RevokeServiceError::MissingKey)
        );
        for presented in ["k3Y", "k3y ", "k3", "", "x k3y"] {
            assert_eq!(
                authorize(Some(presented), &key("k3y")),
                Err(RevokeServiceError::WrongKey),
                "{presented}"
            );
        }
    }

    #[test]
    fn an_unset_key_refuses_even_an_empty_bearer() {
        for presented in [None, Some(""), Some("x")] {
            assert_eq!(
                authorize(presented, &key("")),
                Err(RevokeServiceError::NoKeyConfigured)
            );
        }
    }
}
