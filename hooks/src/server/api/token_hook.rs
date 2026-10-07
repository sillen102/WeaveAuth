pub(crate) use controller::token_hook;

mod controller {
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiJson;
    use common_macros::ErrorResponses;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use super::service::{self, IssuedClaims, TokenHookServiceError};
    use crate::server::AppState;

    /// What Hydra's `oauth2.token_hook` posts. Only the subject, the client and the requested
    /// scopes are read (`granted_scopes` is empty on the code grant).
    #[derive(Deserialize)]
    pub(crate) struct TokenHookRequest {
        session: HookSession,
        request: HookGrant,
    }

    #[derive(Deserialize)]
    struct HookGrant {
        client_id: String,
        #[serde(default)]
        requested_scopes: Vec<String>,
    }

    #[derive(Deserialize)]
    struct HookSession {
        #[serde(default)]
        id_token: HookIdToken,
    }

    #[derive(Default, Deserialize)]
    struct HookIdToken {
        #[serde(default)]
        subject: String,
        #[serde(default)]
        id_token_claims: HookIdTokenClaims,
    }

    #[derive(Default, Deserialize)]
    struct HookIdTokenClaims {
        #[serde(default)]
        sub: String,
    }

    impl TokenHookRequest {
        fn subject(&self) -> &str {
            let id_token = &self.session.id_token;
            if id_token.subject.is_empty() {
                &id_token.id_token_claims.sub
            } else {
                &id_token.subject
            }
        }
    }

    /// Hydra merges these into the tokens it is about to sign.
    #[derive(Serialize)]
    pub(crate) struct TokenHookResponse {
        session: HookClaims,
    }

    #[derive(Serialize)]
    struct HookClaims {
        access_token: serde_json::Map<String, serde_json::Value>,
        id_token: serde_json::Map<String, serde_json::Value>,
    }

    /// Any non-2xx aborts the token exchange; nothing is issued without the claims it carries.
    /// Hydra retries what isn't a 403, so a failure that repeating can't fix is one.
    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum TokenHookError {
        #[error("invalid subject")]
        #[error_response(StatusCode::FORBIDDEN)]
        InvalidSubject,
        #[error("unknown identity")]
        #[error_response(StatusCode::FORBIDDEN)]
        IdentityNotFound,
        #[error("identity lookup failed")]
        #[error_response(StatusCode::BAD_GATEWAY)]
        IdentityLookupFailed,
        #[error("identity is not active")]
        #[error_response(StatusCode::FORBIDDEN)]
        IdentityInactive,
        #[error("identity has no email")]
        #[error_response(StatusCode::FORBIDDEN)]
        IdentityWithoutEmail,
        #[error("email is not verified")]
        #[error_response(StatusCode::FORBIDDEN)]
        EmailNotVerified,
        #[error("downstream login-claims handler failed")]
        #[error_response(StatusCode::BAD_GATEWAY)]
        DownstreamServiceFailed,
        #[error("downstream login-claims handler returned a reserved claim name")]
        #[error_response(StatusCode::FORBIDDEN)]
        ReservedClaimOverridden,
    }

    impl From<TokenHookServiceError> for TokenHookError {
        fn from(err: TokenHookServiceError) -> Self {
            match &err {
                TokenHookServiceError::InvalidSubject
                | TokenHookServiceError::IdentityNotFound
                | TokenHookServiceError::IdentityInactive
                | TokenHookServiceError::EmailNotVerified => {
                    tracing::info!(%err, "token hook denied")
                }
                _ => tracing::warn!(%err, "token hook failed"),
            }
            match err {
                TokenHookServiceError::InvalidSubject => Self::InvalidSubject,
                TokenHookServiceError::IdentityNotFound => Self::IdentityNotFound,
                TokenHookServiceError::IdentityLookupFailed(_) => Self::IdentityLookupFailed,
                TokenHookServiceError::IdentityInactive => Self::IdentityInactive,
                TokenHookServiceError::IdentityWithoutEmail => Self::IdentityWithoutEmail,
                TokenHookServiceError::EmailNotVerified => Self::EmailNotVerified,
                TokenHookServiceError::DownstreamServiceFailed(_) => Self::DownstreamServiceFailed,
                TokenHookServiceError::ReservedClaimOverridden(_) => Self::ReservedClaimOverridden,
            }
        }
    }

    pub(crate) async fn token_hook(
        State(state): State<AppState>,
        ApiJson(req): ApiJson<TokenHookRequest>,
    ) -> Result<Json<TokenHookResponse>, TokenHookError> {
        let IssuedClaims {
            access_token,
            id_token,
        } = service::issue_claims(
            &state,
            req.subject(),
            &req.request.client_id,
            &req.request.requested_scopes,
        )
        .await?;
        Ok(Json(TokenHookResponse {
            session: HookClaims {
                access_token,
                id_token,
            },
        }))
    }
}

mod service {
    use serde_json::{Map, Value};
    use thiserror::Error;
    use uuid::Uuid;

    use crate::clients::UpstreamError;
    use crate::server::AppState;
    use crate::webhook::WebhookError;

    #[derive(Debug, Error)]
    pub(crate) enum TokenHookServiceError {
        #[error("subject is not an identity id")]
        InvalidSubject,
        #[error("kratos has no identity for the subject")]
        IdentityNotFound,
        #[error("looking up the identity failed: {0}")]
        IdentityLookupFailed(UpstreamError),
        #[error("the identity is not active")]
        IdentityInactive,
        #[error("the identity has no email trait")]
        IdentityWithoutEmail,
        #[error("the identity's email is not verified")]
        EmailNotVerified,
        #[error("{0}")]
        DownstreamServiceFailed(WebhookError),
        #[error("login-claims handler returned reserved claim name '{0}'")]
        ReservedClaimOverridden(String),
    }

    /// Claim names a login-claims handler must not set: the registered claims,
    /// the ones hooks sets itself, and the ones Hydra puts on its tokens. A
    /// handler that returned one could spoof identity or scope, or get a token
    /// accepted by a resource server it wasn't meant for (an injected `aud`).
    const RESERVED_CLAIM_NAMES: &[&str] = &[
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti",
        "email",
        "email_verified",
        "scp",
        "client_id",
        "ext",
        "sid",
        "nonce",
        "auth_time",
        "acr",
        "amr",
        "at_hash",
        "c_hash",
        "rat",
        "scope",
        "azp",
        "cnf",
        "act",
        "may_act",
        "typ",
        "token_use",
    ];

    pub(crate) struct IssuedClaims {
        pub(crate) access_token: Map<String, Value>,
        pub(crate) id_token: Map<String, Value>,
    }

    /// Both tokens carry the identity's current email and its verified flag
    /// (read from Kratos on every mint, so a refresh sees changes); the
    /// access token also carries what the deployer's claims handler returns (it is told which
    /// client and scopes the token is for, so it can answer differently per client).
    /// An identity Kratos no longer lets sign in gets nothing, so a refresh
    /// can't outlive its deactivation.
    pub(crate) async fn issue_claims(
        state: &AppState,
        subject: &str,
        client_id: &str,
        scopes: &[String],
    ) -> Result<IssuedClaims, TokenHookServiceError> {
        let user_id =
            Uuid::parse_str(subject).map_err(|_| TokenHookServiceError::InvalidSubject)?;
        let identity = state
            .kratos
            .get_identity(user_id, false)
            .await
            .map_err(|error| {
                if error.is_not_found() {
                    TokenHookServiceError::IdentityNotFound
                } else {
                    TokenHookServiceError::IdentityLookupFailed(error)
                }
            })?;
        if !identity.is_active() {
            return Err(TokenHookServiceError::IdentityInactive);
        }
        let email = identity
            .email()
            .ok_or(TokenHookServiceError::IdentityWithoutEmail)?;
        let email_verified = identity.email_verified();
        if state.require_verified_email && !email_verified {
            return Err(TokenHookServiceError::EmailNotVerified);
        }

        let mut access_token = match &state.login_claims {
            Some(handler) => {
                let claims = handler
                    .login_claims(user_id, email, email_verified, client_id, scopes)
                    .await
                    .map_err(TokenHookServiceError::DownstreamServiceFailed)?;
                reject_reserved(&claims)?;
                claims
            }
            None => Map::new(),
        };
        let mut id_token = Map::new();
        for claims in [&mut access_token, &mut id_token] {
            claims.insert("email".into(), email.into());
            claims.insert("email_verified".into(), email_verified.into());
        }
        Ok(IssuedClaims {
            access_token,
            id_token,
        })
    }

    fn reject_reserved(claims: &Map<String, Value>) -> Result<(), TokenHookServiceError> {
        match claims
            .keys()
            .find(|key| RESERVED_CLAIM_NAMES.contains(&key.as_str()))
        {
            Some(reserved) => Err(TokenHookServiceError::ReservedClaimOverridden(
                reserved.clone(),
            )),
            None => Ok(()),
        }
    }
}
