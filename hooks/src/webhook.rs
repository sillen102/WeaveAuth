//! The deployer's webhooks: claims on every token and the registration record.
//! Both are plain JSON POSTs.

use crate::clients::http_client;
use crate::config::WebhookConfig;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// Most bytes read from a webhook or provider API answer.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Why a webhook produced no answer. Carries the cause for the log only.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WebhookError {
    #[error("{what} webhook request failed: {cause}")]
    Request { what: &'static str, cause: String },
    #[error("{what} webhook returned {status}")]
    Status {
        what: &'static str,
        status: reqwest::StatusCode,
    },
    #[error("{what} webhook did not return {expected}")]
    Body {
        what: &'static str,
        expected: &'static str,
    },
}

impl WebhookError {
    /// The endpoint answered and said no (400, 403 or 422), as opposed to being broken,
    /// unreachable or rejecting hooks itself (a 401 from a rotated token, a 404, a 429).
    pub(crate) fn is_refusal(&self) -> bool {
        matches!(self, Self::Status { status, .. } if matches!(status.as_u16(), 400 | 403 | 422))
    }
}

/// Why an answer body could not be read.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReadError {
    #[error("the answer is over {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error("reading the answer failed: {0}")]
    Failed(String),
}

/// The whole body of `response`, refusing one over [`MAX_RESPONSE_BYTES`] before
/// it is held in memory.
pub(crate) async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, ReadError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ReadError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ReadError::Failed(common::error::cause_chain(&error.without_url())))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(ReadError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Clone)]
pub(crate) struct WebhookHandler {
    client: reqwest::Client,
    url: String,
    bearer_token: Option<SecretString>,
}

impl WebhookHandler {
    pub(crate) fn new(config: &WebhookConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: http_client(Duration::from_secs(config.timeout_secs))?,
            url: config.url.clone(),
            bearer_token: config.bearer_token.clone(),
        })
    }

    async fn post(
        &self,
        what: &'static str,
        payload: &serde_json::Value,
    ) -> Result<reqwest::Response, WebhookError> {
        let mut request = self.client.post(&self.url).json(payload);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token.expose_secret());
        }
        let response = request
            .send()
            .await
            .map_err(|error| WebhookError::Request {
                what,
                cause: common::error::cause_chain(&error.without_url()),
            })?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(WebhookError::Status {
                what,
                status: response.status(),
            })
        }
    }

    /// The answer's body as JSON.
    async fn json(
        what: &'static str,
        response: reqwest::Response,
    ) -> Result<serde_json::Value, WebhookError> {
        let bytes = read_limited(response).await.map_err(|error| match error {
            ReadError::TooLarge => WebhookError::Body {
                what,
                expected: "an answer within the size limit",
            },
            ReadError::Failed(_) => WebhookError::Request {
                what,
                cause: error.to_string(),
            },
        })?;
        serde_json::from_slice(&bytes).map_err(|_| WebhookError::Body {
            what,
            expected: "valid JSON",
        })
    }

    /// The extra access token claims for `user_id`. The answer must be a JSON
    /// object: anything else is an error, and no token may be minted on one.
    /// `email_verified` says whether Kratos has verified `email`; a handler must
    /// not derive roles from an address that is not.
    pub(crate) async fn login_claims(
        &self,
        user_id: Uuid,
        email: &str,
        email_verified: bool,
        client_id: &str,
        scopes: &[String],
    ) -> Result<serde_json::Map<String, serde_json::Value>, WebhookError> {
        const WHAT: &str = "login-claims";
        let mut payload = serde_json::Map::new();
        payload.insert("user_id".into(), user_id.to_string().into());
        payload.insert("email".into(), email.into());
        payload.insert("email_verified".into(), email_verified.into());
        payload.insert("client_id".into(), client_id.into());
        payload.insert("scopes".into(), scopes.into());
        let payload = serde_json::Value::Object(payload);
        match Self::json(WHAT, self.post(WHAT, &payload).await?).await? {
            serde_json::Value::Object(claims) => Ok(claims),
            _ => Err(WebhookError::Body {
                what: WHAT,
                expected: "a JSON object",
            }),
        }
    }

    /// Hands a new identity and its registration fields to the deployer.
    pub(crate) async fn registration(
        &self,
        user_id: Uuid,
        email: &str,
        email_verified: bool,
        fields: &HashMap<String, String>,
    ) -> Result<(), WebhookError> {
        let payload = serde_json::json!({
            "user_id": user_id,
            "email": email,
            "email_verified": email_verified,
            "fields": fields,
        });
        self.post("registration", &payload).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Answers one request with `chunks` as a chunked body, so no Content-Length announces its size.
    async fn chunked_answer(chunks: Vec<usize>) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let mut answer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for size in chunks {
                answer.extend(format!("{size:x}\r\n").bytes());
                answer.extend(std::iter::repeat_n(b'x', size));
                answer.extend(b"\r\n");
            }
            answer.extend(b"0\r\n\r\n");
            let _ = stream.write_all(&answer).await;
            let _ = stream.shutdown().await;
        });
        reqwest::get(url).await.unwrap()
    }

    #[tokio::test]
    async fn a_chunked_answer_is_read_up_to_the_limit_and_refused_beyond_it() {
        let half = MAX_RESPONSE_BYTES / 2;

        let body = read_limited(chunked_answer(vec![half, half]).await).await;
        assert_eq!(body.unwrap().len(), MAX_RESPONSE_BYTES);

        let refused = read_limited(chunked_answer(vec![half, half, 1]).await).await;
        assert!(matches!(refused, Err(ReadError::TooLarge)));
    }
}
