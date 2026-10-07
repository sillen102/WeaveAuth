pub(crate) use controller::after_registration;

mod controller {
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiJson;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;
    use uuid::Uuid;

    use super::service::{self, AfterRegistrationServiceError};
    use crate::server::AppState;
    use crate::server::api::KratosHookError;

    /// The body of Kratos's after-registration web hook, built by its Jsonnet
    /// `body:` template (`ory/kratos/hooks/after-registration.jsonnet`). Only
    /// these fields are read; the template sends more, and `provider` and
    /// `granted_scopes` may be left out. Whether the address is verified is
    /// read from Kratos, not from the body.
    #[derive(Deserialize)]
    pub(crate) struct AfterRegistrationRequest {
        pub(super) identity_id: Uuid,
        pub(super) email: String,
        /// Everything the registration form stored; all but `email` is forwarded as `fields`.
        #[serde(default)]
        pub(super) traits: serde_json::Map<String, serde_json::Value>,
        /// The Kratos OIDC provider id for a social sign-up, absent (or empty) for a password one.
        #[serde(default)]
        pub(super) provider: Option<String>,
        /// The scopes the provider granted. Kratos' hook context has none, so the shipped
        /// template leaves it out.
        #[serde(default)]
        pub(super) granted_scopes: Option<Vec<String>>,
    }

    /// Kratos aborts the registration on any non-2xx. It retries 5xx (and 429) and
    /// not other 4xx, so a failure a retry can't fix is a 4xx.
    #[derive(Debug, Error, ErrorResponses)]
    #[error_response_type(KratosHookError)]
    pub(crate) enum AfterRegistrationError {
        #[error("a permission this sign-up needs was not granted")]
        #[error_response(StatusCode::UNPROCESSABLE_ENTITY)]
        ConsentRequired,
        #[error("the profile could not be read from the sign-in provider")]
        #[error_response(StatusCode::UNPROCESSABLE_ENTITY)]
        ProfileApiFailed,
        #[error("the registration was rejected")]
        #[error_response(StatusCode::UNPROCESSABLE_ENTITY)]
        RegistrationRejected,
        #[error("the registration could not be completed")]
        #[error_response(StatusCode::BAD_GATEWAY)]
        RegistrationHandlerFailed,
        #[error("the identity could not be looked up")]
        #[error_response(StatusCode::BAD_GATEWAY)]
        IdentityLookupFailed,
        #[error("the identity no longer exists")]
        #[error_response(StatusCode::GONE)]
        IdentityGone,
        #[error("the registration took too long")]
        #[error_response(StatusCode::GATEWAY_TIMEOUT)]
        RegistrationTimedOut,
    }

    impl From<AfterRegistrationServiceError> for AfterRegistrationError {
        fn from(err: AfterRegistrationServiceError) -> Self {
            use AfterRegistrationServiceError as E;
            match &err {
                E::ConsentRequired(_) | E::RegistrationRejected(_) | E::IdentityGone => {
                    tracing::info!(%err, "registration blocked")
                }
                _ => tracing::warn!(%err, "registration blocked"),
            }
            match err {
                E::ConsentRequired(_) => Self::ConsentRequired,
                E::ProfileApiFailed(_) => Self::ProfileApiFailed,
                E::RegistrationRejected(_) => Self::RegistrationRejected,
                E::RegistrationHandlerFailed(_) => Self::RegistrationHandlerFailed,
                E::IdentityLookupFailed(_) => Self::IdentityLookupFailed,
                E::IdentityGone => Self::IdentityGone,
                E::TimedOut(_) => Self::RegistrationTimedOut,
            }
        }
    }

    pub(crate) async fn after_registration(
        State(state): State<AppState>,
        ApiJson(req): ApiJson<AfterRegistrationRequest>,
    ) -> Result<Json<serde_json::Value>, AfterRegistrationError> {
        service::register(&state, req).await?;
        Ok(Json(serde_json::json!({})))
    }
}

mod service {
    use std::collections::HashMap;
    use std::time::Duration;
    use thiserror::Error;
    use uuid::Uuid;

    use super::controller::AfterRegistrationRequest;
    use crate::clients::UpstreamError;
    use crate::clients::kratos::Identity;
    use crate::config::ProfileApiConfig;
    use crate::profile_api::{self, ProfileError, scalar_to_string};
    use crate::server::AppState;
    use crate::webhook::WebhookError;

    #[derive(Debug, Error)]
    pub(crate) enum AfterRegistrationServiceError {
        #[error("{0}")]
        ConsentRequired(ProfileError),
        #[error("{0}")]
        ProfileApiFailed(ProfileError),
        #[error("{0}")]
        RegistrationRejected(WebhookError),
        #[error("{0}")]
        RegistrationHandlerFailed(WebhookError),
        #[error("looking up the identity failed: {0}")]
        IdentityLookupFailed(UpstreamError),
        #[error("kratos has no identity for the registration")]
        IdentityGone,
        #[error("collecting and forwarding the registration took longer than {0:?}")]
        TimedOut(Duration),
    }

    /// Collects the registration's fields and hands them to the deployer. A
    /// failure aborts the registration; see [`delete_identity`] for the
    /// identity it leaves behind. The work gets half the request timeout, so
    /// the delete still runs when a slow upstream would otherwise cancel the
    /// request.
    pub(crate) async fn register(
        state: &AppState,
        req: AfterRegistrationRequest,
    ) -> Result<(), AfterRegistrationServiceError> {
        let identity_id = req.identity_id;
        let budget = state.request_timeout / 2;
        let result = match tokio::time::timeout(budget, collect_and_forward(state, req)).await {
            Ok(result) => result,
            Err(_) => Err(AfterRegistrationServiceError::TimedOut(budget)),
        };
        if matches!(&result, Err(error) if !matches!(error, AfterRegistrationServiceError::IdentityGone))
        {
            delete_identity(state, identity_id).await;
        }
        result
    }

    async fn collect_and_forward(
        state: &AppState,
        req: AfterRegistrationRequest,
    ) -> Result<(), AfterRegistrationServiceError> {
        let provider = req.provider.as_deref().filter(|p| !p.is_empty());
        let apis = provider
            .and_then(|provider| state.profile_apis.get(provider))
            .map(Vec::as_slice)
            .unwrap_or_default();
        if state.registration.is_none() && apis.is_empty() {
            return Ok(());
        }
        // The hook runs after Kratos persisted the identity. Kratos retries a 5xx, and an
        // identity a failed attempt deleted is gone on that retry: stop there instead of
        // registering it with the deployer again.
        let identity = state
            .kratos
            .get_identity(req.identity_id, !apis.is_empty())
            .await
            .map_err(|error| {
                if error.is_not_found() {
                    AfterRegistrationServiceError::IdentityGone
                } else {
                    AfterRegistrationServiceError::IdentityLookupFailed(error)
                }
            })?;

        let mut fields: HashMap<String, String> = req
            .traits
            .iter()
            .filter(|(name, _)| name.as_str() != "email")
            .filter_map(|(name, value)| Some((name.clone(), scalar_to_string(value)?)))
            .collect();
        if let Some(provider) = provider.filter(|_| !apis.is_empty()) {
            fields.extend(provider_fields(state, provider, apis, &identity, &req).await?);
        }

        if let Some(handler) = &state.registration {
            handler
                .registration(
                    req.identity_id,
                    &req.email,
                    identity.email_verified(),
                    &fields,
                )
                .await
                .map_err(|error| {
                    if error.is_refusal() {
                        AfterRegistrationServiceError::RegistrationRejected(error)
                    } else {
                        AfterRegistrationServiceError::RegistrationHandlerFailed(error)
                    }
                })?;
        }
        Ok(())
    }

    /// What the provider's profile APIs return for a social sign-up, using the
    /// access token Kratos stored on the identity.
    async fn provider_fields(
        state: &AppState,
        provider: &str,
        apis: &[ProfileApiConfig],
        identity: &Identity,
        req: &AfterRegistrationRequest,
    ) -> Result<HashMap<String, String>, AfterRegistrationServiceError> {
        profile_api::collect(
            &state.http_client,
            provider,
            apis,
            identity.oidc_access_token(provider),
            req.granted_scopes.as_deref(),
        )
        .await
        .map_err(|error| match error {
            ProfileError::ConsentRequired(_) => {
                AfterRegistrationServiceError::ConsentRequired(error)
            }
            ProfileError::Failed(_) => AfterRegistrationServiceError::ProfileApiFailed(error),
        })
    }

    /// Removes the identity of a registration that failed, so it doesn't
    /// outlive the error it is told about. Kratos runs this hook after saving
    /// the identity, so this is what undoes the registration. A failed delete
    /// is logged here and doesn't replace the error being returned.
    async fn delete_identity(state: &AppState, identity_id: Uuid) {
        if let Err(error) = state.kratos.delete_identity(identity_id).await {
            tracing::error!(%identity_id, %error, "could not delete the identity of a failed registration");
        }
    }
}
