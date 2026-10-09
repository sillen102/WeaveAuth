pub(crate) use controller::after_verification;

mod controller {
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use common::extract::ApiJson;
    use common_macros::ErrorResponses;
    use serde::Deserialize;
    use thiserror::Error;
    use uuid::Uuid;

    use super::service::{self, AfterVerificationServiceError};
    use crate::server::AppState;
    use crate::server::api::KratosHookError;

    /// The body of Kratos's after-verification web hook, built by its Jsonnet `body:` template
    /// (`ory/kratos/hooks/after-verification.jsonnet`).
    #[derive(Deserialize)]
    pub(crate) struct AfterVerificationRequest {
        pub(super) identity_id: Uuid,
        pub(super) email: String,
    }

    /// Kratos retries a 5xx, and once the retries are spent the user's flow ends on `/error`
    /// although the address is verified. So only a transient failure is an error; a refusal
    /// means nothing after the fact and is answered `200`. The identity is never touched.
    #[derive(Debug, Error, ErrorResponses)]
    #[error_response_type(KratosHookError)]
    pub(crate) enum AfterVerificationError {
        #[error("the verification notice could not be delivered")]
        #[error_response(StatusCode::BAD_GATEWAY)]
        NoticeFailed,
    }

    impl From<AfterVerificationServiceError> for AfterVerificationError {
        fn from(err: AfterVerificationServiceError) -> Self {
            tracing::warn!(%err, "verification notice not delivered");
            match err {
                AfterVerificationServiceError::Failed(_) => Self::NoticeFailed,
            }
        }
    }

    pub(crate) async fn after_verification(
        State(state): State<AppState>,
        ApiJson(req): ApiJson<AfterVerificationRequest>,
    ) -> Result<Json<serde_json::Value>, AfterVerificationError> {
        service::notify(&state, req).await?;
        Ok(Json(serde_json::json!({})))
    }
}

mod service {
    use thiserror::Error;

    use super::controller::AfterVerificationRequest;
    use crate::server::AppState;
    use crate::webhook::WebhookError;

    #[derive(Debug, Error)]
    pub(crate) enum AfterVerificationServiceError {
        #[error("{0}")]
        Failed(WebhookError),
    }

    /// Tells the deployer's verification handler, if one is configured. A refusal is logged and
    /// swallowed: the address is verified either way.
    pub(crate) async fn notify(
        state: &AppState,
        req: AfterVerificationRequest,
    ) -> Result<(), AfterVerificationServiceError> {
        let Some(handler) = &state.verification else {
            return Ok(());
        };
        handler
            .email_verified(req.identity_id, &req.email)
            .await
            .or_else(|error| {
                if error.is_refusal() {
                    tracing::info!(%error, "verification notice refused");
                    Ok(())
                } else {
                    Err(AfterVerificationServiceError::Failed(error))
                }
            })
    }
}
