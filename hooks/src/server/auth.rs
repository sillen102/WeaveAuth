use crate::server::AppState;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use common_macros::ErrorResponses;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, ErrorResponses)]
pub(crate) enum ApiKeyError {
    #[error("missing or invalid API key")]
    #[error_response(StatusCode::UNAUTHORIZED)]
    Unauthorized,
}

/// Requires `Authorization: Bearer <hooks API key>`. Kratos and Hydra send it
/// via their web hook `auth: api_key`.
pub(crate) async fn require_api_key(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiKeyError> {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match presented {
        Some(key) if key_matches(&state.api_key_digest, key) => Ok(next.run(request).await),
        _ => {
            tracing::warn!("request without a valid API key refused");
            Err(ApiKeyError::Unauthorized)
        }
    }
}

/// Compares digests rather than keys, so the comparison is constant-time
/// without depending on the lengths being equal.
fn key_matches(expected_digest: &[u8; 32], presented: &str) -> bool {
    let presented_digest = Sha256::digest(presented.as_bytes());
    expected_digest
        .iter()
        .zip(presented_digest.iter())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_key_matches() {
        let digest: [u8; 32] = Sha256::digest(b"secret").into();

        assert!(key_matches(&digest, "secret"));
        assert!(!key_matches(&digest, "secre"));
        assert!(!key_matches(&digest, "secret!"));
        assert!(!key_matches(&digest, ""));
    }
}
