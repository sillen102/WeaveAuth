pub(crate) use controller::jwks;
pub(crate) use controller::jwks_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::State;
    use axum::Json;
    use serde_json::Value;

    use crate::server::AppState;
    use crate::storage::JwkStorage;

    pub(crate) fn jwks_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("jwks")
            .summary("JSON Web Key Set")
            .description("Public keys used to verify access token signatures (RFC 7517).")
    }

    pub(crate) async fn jwks(State(state): State<AppState>) -> Json<Value> {
        Json(state.jwt_keys.jwk_set().await)
    }
}