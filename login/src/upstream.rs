//! What can go wrong calling Kratos or Hydra. Carries the cause for the log; no HTTP knowledge,
//! and handlers never put any of it in a response.

use common::error::cause_chain;

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpstreamError {
    #[error("request to {service} at {url} failed: {cause}")]
    Request {
        service: &'static str,
        url: String,
        cause: String,
    },
    #[error("{service} answered {status} to {url}")]
    Status {
        service: &'static str,
        url: String,
        status: u16,
    },
    #[error("{service}'s answer from {url} could not be read: {cause}")]
    Unreadable {
        service: &'static str,
        url: String,
        cause: String,
    },
}

impl UpstreamError {
    pub(crate) fn request(service: &'static str, url: &url::Url, error: reqwest::Error) -> Self {
        Self::Request {
            service,
            url: loggable(url),
            cause: cause_chain(&error.without_url()),
        }
    }

    pub(crate) fn status(
        service: &'static str,
        url: &url::Url,
        status: reqwest::StatusCode,
    ) -> Self {
        Self::Status {
            service,
            url: loggable(url),
            status: status.as_u16(),
        }
    }

    pub(crate) fn unreadable(
        service: &'static str,
        url: &url::Url,
        error: impl std::error::Error + 'static,
    ) -> Self {
        Self::Unreadable {
            service,
            url: loggable(url),
            cause: cause_chain(&error),
        }
    }
}

/// The URL without its query: flow ids and challenges are credentials of a sort.
fn loggable(url: &url::Url) -> String {
    let mut url = url.clone();
    url.set_query(None);
    url.to_string()
}
