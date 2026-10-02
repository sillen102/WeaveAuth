pub(crate) use controller::jwks;
pub(crate) use controller::jwks_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::Json;
    use axum::extract::State;
    use axum::http::{HeaderValue, header};
    use serde_json::Value;

    use crate::server::AppState;

    use super::service;

    /// Below `JWT_KEY_ROTATION_MARGIN_SECS`, with headroom for the delay
    /// before a sweep tick stages the next key.
    const JWKS_CACHE_CONTROL: HeaderValue = HeaderValue::from_static("public, max-age=1800");

    pub(crate) fn jwks_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("jwks")
            .summary("JSON Web Key Set")
            .description(
                "Public keys used to verify access token signatures (RFC 7517). \
A new key is published ahead of signing with it (except right after a backend \
restart, when a fresh key signs at once and tokens signed before it no longer \
verify), and a replaced key stays published \
until its tokens have expired. Cache for at most the `max-age` sent, and \
re-fetch when a token has an unknown `kid`, at most once per minute.",
            )
    }

    pub(crate) async fn jwks(
        State(state): State<AppState>,
    ) -> ([(header::HeaderName, HeaderValue); 1], Json<Value>) {
        (
            [(header::CACHE_CONTROL, JWKS_CACHE_CONTROL)],
            Json(service::jwk_set(&state).await),
        )
    }
}

mod service {
    use serde_json::Value;

    use crate::server::AppState;
    use crate::storage::JwkStorage;

    pub(crate) async fn jwk_set(state: &AppState) -> Value {
        state.jwt_keys.jwk_set().await
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::State;
    use axum::http::header::CACHE_CONTROL;

    use crate::config::JWT_KEY_ROTATION_MARGIN_SECS;
    use crate::server::AppState;

    #[tokio::test]
    async fn max_age_stays_below_the_margin_the_next_key_is_published_ahead_by() {
        let (headers, _) = super::jwks(State(AppState::for_test().await)).await;

        let (name, value) = &headers[0];
        assert_eq!(name, CACHE_CONTROL);
        let max_age: i64 = value
            .to_str()
            .unwrap()
            .strip_prefix("public, max-age=")
            .unwrap()
            .parse()
            .unwrap();
        assert!(0 < max_age && max_age < JWT_KEY_ROTATION_MARGIN_SECS);
    }
}
