pub(crate) use controller::after_password_change;

mod controller {
    use axum::Json;
    use axum::extract::State;
    use common::extract::ApiJson;

    use crate::server::AppState;
    use crate::server::api::revocation::{self, Revocation, RevocationError, RevocationRequest};

    /// A password change from the settings flow ends the other Kratos sessions and
    /// every Hydra and bff session and token (the caller's app session too; only its
    /// Kratos session stays) but leaves the credentials alone.
    pub(crate) async fn after_password_change(
        State(state): State<AppState>,
        ApiJson(req): ApiJson<RevocationRequest>,
    ) -> Result<Json<serde_json::Value>, RevocationError> {
        revocation::revoke(
            &state,
            Revocation {
                identity_id: req.identity_id,
                keep_session: req.session_id,
                purge_credentials: false,
            },
        )
        .await?;
        Ok(Json(serde_json::json!({})))
    }
}
