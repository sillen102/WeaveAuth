//! Server-to-server calls to Kratos admin, Hydra admin and bff's internal listener.

use std::time::Duration;

pub(crate) mod bff;
pub(crate) mod hydra;
pub(crate) mod kratos;

/// Why a call upstream failed. Carries the cause for the log only; nothing
/// here reaches a response body.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UpstreamError {
    #[error("{what}: request failed: {cause}")]
    Request { what: &'static str, cause: String },
    #[error("{what}: returned {status}")]
    Status {
        what: &'static str,
        status: reqwest::StatusCode,
    },
    #[error("{what}: the identity is not active")]
    Inactive { what: &'static str },
    #[error("{what}: unreadable response: {cause}")]
    Body { what: &'static str, cause: String },
}

impl UpstreamError {
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(self, Self::Status { status, .. } if *status == reqwest::StatusCode::NOT_FOUND)
    }
}

/// No redirects: these are calls to deployer-configured internal targets, so
/// following a redirect elsewhere would be a request-forgery vector.
pub(crate) fn http_client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
}

/// Sends `request`; any non-2xx is an [`UpstreamError::Status`].
pub(crate) async fn send(
    what: &'static str,
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, UpstreamError> {
    let response = request
        .send()
        .await
        .map_err(|error| UpstreamError::Request {
            what,
            cause: common::error::cause_chain(&error.without_url()),
        })?;
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(UpstreamError::Status {
            what,
            status: response.status(),
        })
    }
}

pub(crate) async fn read_json<T: serde::de::DeserializeOwned>(
    what: &'static str,
    response: reqwest::Response,
) -> Result<T, UpstreamError> {
    response.json().await.map_err(|error| UpstreamError::Body {
        what,
        cause: common::error::cause_chain(&error.without_url()),
    })
}
