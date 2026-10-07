pub(crate) use controller::after_recovery;

mod controller {
    use axum::Json;
    use axum::extract::State;
    use common::extract::ApiJson;

    use crate::server::AppState;
    use crate::server::api::revocation::{self, Revocation, RevocationError, RevocationRequest};

    /// Recovery proves control of the mailbox, not of the account's other
    /// sign-ins: the password, every passkey, TOTP and recovery code and every
    /// linked social login go, and so does every session and token. The user
    /// ends up in the settings flow and must set a password; leaving without
    /// one means recovering again.
    pub(crate) async fn after_recovery(
        State(state): State<AppState>,
        ApiJson(req): ApiJson<RevocationRequest>,
    ) -> Result<Json<serde_json::Value>, RevocationError> {
        revocation::revoke(
            &state,
            Revocation {
                identity_id: req.identity_id,
                keep_session: req.session_id,
                purge_credentials: true,
            },
        )
        .await?;
        Ok(Json(serde_json::json!({})))
    }
}
