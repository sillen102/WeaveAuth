//! Hydra's admin API, as far as login uses it: finishing logout and consent challenges.

use crate::upstream::UpstreamError;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

const SERVICE: &str = "hydra";

#[derive(Clone)]
pub(crate) struct Hydra {
    client: reqwest::Client,
    base: url::Url,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LogoutRequest {
    /// Set when the app started the logout (a valid `id_token_hint`), so no one has to confirm
    /// it. Hydra's logout request has no `skip` field.
    #[serde(default)]
    pub rp_initiated: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConsentRequest {
    pub client: ConsentClient,
    #[serde(default)]
    pub requested_scope: Vec<String>,
    #[serde(default)]
    pub requested_access_token_audience: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConsentClient {
    pub client_id: String,
}

#[derive(Deserialize)]
struct Redirect {
    redirect_to: String,
}

#[derive(Serialize)]
struct AcceptConsent<'a> {
    grant_scope: &'a [String],
    grant_access_token_audience: &'a [String],
    remember: bool,
}

impl Hydra {
    pub(crate) fn new(client: reqwest::Client, base: &str) -> anyhow::Result<Self> {
        let base = url::Url::parse(&format!("{}/", base.trim_end_matches('/')))
            .map_err(|error| anyhow::anyhow!("invalid WA_HYDRA_ADMIN_URL {base:?}: {error}"))?;
        Ok(Self { client, base })
    }

    /// `None` when Hydra doesn't know the challenge (expired or made up).
    pub(crate) async fn logout_request(
        &self,
        challenge: &str,
    ) -> Result<Option<LogoutRequest>, UpstreamError> {
        self.lookup("logout", "logout_challenge", challenge).await
    }

    /// Returns where to send the browser next.
    pub(crate) async fn accept_logout(&self, challenge: &str) -> Result<String, UpstreamError> {
        self.put("logout/accept", "logout_challenge", challenge, &json!({}))
            .await
    }

    pub(crate) async fn consent_request(
        &self,
        challenge: &str,
    ) -> Result<Option<ConsentRequest>, UpstreamError> {
        self.lookup("consent", "consent_challenge", challenge).await
    }

    pub(crate) async fn accept_consent(
        &self,
        challenge: &str,
        scopes: &[String],
        audience: &[String],
    ) -> Result<String, UpstreamError> {
        let body = AcceptConsent {
            grant_scope: scopes,
            grant_access_token_audience: audience,
            remember: false,
        };
        self.put("consent/accept", "consent_challenge", challenge, &body)
            .await
    }

    pub(crate) async fn reject_consent(&self, challenge: &str) -> Result<String, UpstreamError> {
        let body =
            json!({"error": "access_denied", "error_description": "Consent was not granted"});
        self.put("consent/reject", "consent_challenge", challenge, &body)
            .await
    }

    fn url(&self, path: &str, key: &str, challenge: &str) -> Result<url::Url, UpstreamError> {
        let mut url = self
            .base
            .join(&format!("admin/oauth2/auth/requests/{path}"))
            .map_err(|error| UpstreamError::unreadable(SERVICE, &self.base, error))?;
        url.query_pairs_mut().append_pair(key, challenge);
        Ok(url)
    }

    async fn lookup<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        key: &str,
        challenge: &str,
    ) -> Result<Option<T>, UpstreamError> {
        let url = self.url(path, key, challenge)?;
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|error| UpstreamError::request(SERVICE, &url, error))?;
        match response.status() {
            StatusCode::OK => response
                .json()
                .await
                .map(Some)
                .map_err(|error| UpstreamError::unreadable(SERVICE, &url, error.without_url())),
            StatusCode::NOT_FOUND | StatusCode::GONE => Ok(None),
            status => Err(UpstreamError::status(SERVICE, &url, status)),
        }
    }

    async fn put(
        &self,
        path: &str,
        key: &str,
        challenge: &str,
        body: &impl Serialize,
    ) -> Result<String, UpstreamError> {
        let url = self.url(path, key, challenge)?;
        let response = self
            .client
            .put(url.clone())
            .json(body)
            .send()
            .await
            .map_err(|error| UpstreamError::request(SERVICE, &url, error))?;
        if !response.status().is_success() {
            return Err(UpstreamError::status(SERVICE, &url, response.status()));
        }
        response
            .json::<Redirect>()
            .await
            .map(|redirect| redirect.redirect_to)
            .map_err(|error| UpstreamError::unreadable(SERVICE, &url, error.without_url()))
    }
}
