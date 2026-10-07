use serde::Serialize;

pub(crate) mod after_password_change;
pub(crate) mod after_recovery;
pub(crate) mod after_registration;
pub(crate) mod health;
mod revocation;
pub(crate) mod token_hook;

/// The error body of a route Kratos calls. Kratos (no `response.parse`) reads only the
/// status; the `messages` are in the shape it would show a user, and `text` is the same
/// fixed string as `details`, never anything derived from a cause.
#[derive(Debug, Serialize)]
pub(crate) struct KratosHookError {
    reason: String,
    details: String,
    messages: Vec<KratosMessages>,
}

#[derive(Debug, Serialize)]
struct KratosMessages {
    messages: Vec<KratosMessage>,
}

#[derive(Debug, Serialize)]
struct KratosMessage {
    id: u32,
    text: String,
    r#type: &'static str,
}

/// Kratos asks for a numeric id so the UI can interpret the message; 4000000+ is
/// its range for validation errors, and hooks' messages have no further meaning.
const MESSAGE_ID: u32 = 4_000_001;

impl KratosHookError {
    /// Constructor shape `ErrorResponses` expects of an error response type.
    pub(crate) fn new(details: impl Into<String>, reason: impl Into<String>) -> Self {
        let details = details.into();
        Self {
            reason: reason.into(),
            messages: vec![KratosMessages {
                messages: vec![KratosMessage {
                    id: MESSAGE_ID,
                    text: details.clone(),
                    r#type: "error",
                }],
            }],
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use common_macros::ErrorResponses;
    use thiserror::Error;

    #[derive(Debug, Error, ErrorResponses)]
    enum Sample {
        #[error("upstream said {0}")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "upstream failed")]
        Upstream(String),
        #[error("no such thing")]
        #[error_response(StatusCode::NOT_FOUND)]
        Missing,
    }

    async fn details_of(error: Sample) -> String {
        let body = axum::body::to_bytes(error.into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["details"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn the_declared_details_replace_the_display_text_which_may_carry_a_cause() {
        assert_eq!(
            details_of(Sample::Upstream("secret cause".into())).await,
            "upstream failed"
        );
        assert_eq!(details_of(Sample::Missing).await, "no such thing");
    }
}
