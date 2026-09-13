use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct ErrorResponse {
    /// The timestamp when the error occurred.
    pub timestamp: DateTime<Utc>,
    /// A machine-readable error code or reason, typically the name of an enum variant.
    pub reason: String,
    /// A human-readable description of the error.
    pub details: String,
}

impl ErrorResponse {
    pub fn new(details: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            reason: reason.into(),
            details: details.into(),
        }
    }
}
