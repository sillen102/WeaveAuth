//! Kratos' flow JSON as login renders it, and login's calls to Kratos' public API.

use crate::upstream::UpstreamError;
use axum::http::{HeaderValue, StatusCode, header};
use serde::Deserialize;
use serde_json::Value;

const SERVICE: &str = "kratos";

/// The five browser flows, each with a page of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowKind {
    Login,
    Registration,
    Recovery,
    Verification,
    Settings,
}

impl FlowKind {
    /// The segment of Kratos' `/self-service/<segment>/...` paths, and of login's own page.
    pub(crate) fn segment(self) -> &'static str {
        match self {
            FlowKind::Login => "login",
            FlowKind::Registration => "registration",
            FlowKind::Recovery => "recovery",
            FlowKind::Verification => "verification",
            FlowKind::Settings => "settings",
        }
    }

    pub(crate) fn template(self) -> &'static str {
        match self {
            FlowKind::Login => "login.html",
            FlowKind::Registration => "registration.html",
            FlowKind::Recovery => "recovery.html",
            FlowKind::Verification => "verification.html",
            FlowKind::Settings => "settings.html",
        }
    }

    /// Whether the flow belongs to a Hydra login request, so it can only start from a challenge.
    pub(crate) fn needs_challenge(self) -> bool {
        matches!(self, FlowKind::Login | FlowKind::Registration)
    }
}

pub(crate) enum FlowFetch {
    Found(Value),
    /// Expired, unknown, or not this browser's (Kratos' CSRF check answers `403` for a flow link
    /// opened elsewhere): the page starts a new one.
    Gone,
    /// The flow needs a session the browser doesn't have (`401`, settings).
    SignInRequired,
}

#[derive(Clone)]
pub(crate) struct Kratos {
    client: reqwest::Client,
    base: url::Url,
}

impl Kratos {
    pub(crate) fn new(client: reqwest::Client, base: &str) -> anyhow::Result<Self> {
        let base = url::Url::parse(&format!("{}/", base.trim_end_matches('/')))
            .map_err(|error| anyhow::anyhow!("invalid WA_KRATOS_PUBLIC_URL {base:?}: {error}"))?;
        Ok(Self { client, base })
    }

    pub(crate) fn origin(&self) -> String {
        self.base.origin().ascii_serialization()
    }

    /// `path` is absolute (`/self-service/...`); the query is appended as given.
    pub(crate) fn url(&self, path: &str, query: Option<&str>) -> Result<url::Url, url::ParseError> {
        let mut url = self.base.join(path.trim_start_matches('/'))?;
        url.set_query(query);
        Ok(url)
    }

    pub(crate) async fn fetch_flow(
        &self,
        kind: FlowKind,
        id: &str,
        cookie: Option<&HeaderValue>,
    ) -> Result<FlowFetch, UpstreamError> {
        let url = self.endpoint(
            &format!("self-service/{}/flows", kind.segment()),
            &[("id", id)],
        )?;
        match self.get(&url, cookie).await? {
            (StatusCode::OK, body) => {
                let flow: Value = serde_json::from_slice(&body)
                    .map_err(|error| UpstreamError::unreadable(SERVICE, &url, error))?;
                // Only what render needs, checked here so a malformed flow is one logged error.
                serde_json::from_value::<Flow>(flow.clone())
                    .map_err(|error| UpstreamError::unreadable(SERVICE, &url, error))?;
                Ok(FlowFetch::Found(flow))
            }
            (StatusCode::NOT_FOUND | StatusCode::GONE | StatusCode::FORBIDDEN, _) => {
                Ok(FlowFetch::Gone)
            }
            (StatusCode::UNAUTHORIZED, _) => Ok(FlowFetch::SignInRequired),
            (status, _) => Err(UpstreamError::status(SERVICE, &url, status)),
        }
    }

    /// `None` when Kratos doesn't know the error id (it expires).
    pub(crate) async fn fetch_error(&self, id: &str) -> Result<Option<Value>, UpstreamError> {
        let url = self.endpoint("self-service/errors", &[("id", id)])?;
        match self.get(&url, None).await? {
            (StatusCode::OK, body) => serde_json::from_slice(&body)
                .map(Some)
                .map_err(|error| UpstreamError::unreadable(SERVICE, &url, error)),
            (StatusCode::NOT_FOUND | StatusCode::GONE, _) => Ok(None),
            (status, _) => Err(UpstreamError::status(SERVICE, &url, status)),
        }
    }

    /// Ends the browser's Kratos session. Returns the `Set-Cookie` values Kratos answers with,
    /// to pass on so the browser drops its cookies; `None` when there was no session to end.
    pub(crate) async fn end_session(
        &self,
        cookie: Option<&HeaderValue>,
    ) -> Result<Option<Vec<HeaderValue>>, UpstreamError> {
        let url = self.endpoint("self-service/logout/browser", &[])?;
        let token = match self.get(&url, cookie).await? {
            (StatusCode::OK, body) => {
                serde_json::from_slice::<LogoutToken>(&body)
                    .map_err(|error| UpstreamError::unreadable(SERVICE, &url, error))?
                    .logout_token
            }
            (StatusCode::UNAUTHORIZED, _) => return Ok(None),
            (status, _) => return Err(UpstreamError::status(SERVICE, &url, status)),
        };
        let url = self.endpoint("self-service/logout", &[("token", &token)])?;
        let mut request = self.client.get(url.clone());
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let response = request
            .send()
            .await
            .map_err(|error| UpstreamError::request(SERVICE, &url, error))?;
        // Kratos answers with a redirect to wherever it was told; only the cookies matter.
        if !response.status().is_redirection() && !response.status().is_success() {
            return Err(UpstreamError::status(SERVICE, &url, response.status()));
        }
        Ok(Some(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .cloned()
                .collect(),
        ))
    }

    fn endpoint(&self, path: &str, query: &[(&str, &str)]) -> Result<url::Url, UpstreamError> {
        let mut url = self
            .base
            .join(path)
            .map_err(|error| UpstreamError::unreadable(SERVICE, &self.base, error))?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        Ok(url)
    }

    async fn get(
        &self,
        url: &url::Url,
        cookie: Option<&HeaderValue>,
    ) -> Result<(StatusCode, axum::body::Bytes), UpstreamError> {
        let mut request = self
            .client
            .get(url.clone())
            .header(header::ACCEPT, "application/json");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let response = request
            .send()
            .await
            .map_err(|error| UpstreamError::request(SERVICE, url, error))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| UpstreamError::request(SERVICE, url, error))?;
        Ok((status, body))
    }
}

#[derive(Deserialize)]
struct LogoutToken {
    logout_token: String,
}

/// The parts of a Kratos flow login renders. Anything else in the JSON stays available to the
/// page templates through the raw value.
#[derive(Debug, Deserialize)]
pub(crate) struct Flow {
    pub ui: Ui,
    pub request_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Ui {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub messages: Vec<UiText>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Node {
    #[serde(default)]
    pub group: String,
    #[serde(flatten)]
    pub kind: NodeKind,
    #[serde(default)]
    pub messages: Vec<UiText>,
    #[serde(default)]
    pub meta: Meta,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "attributes", rename_all = "lowercase")]
pub(crate) enum NodeKind {
    Input(InputAttributes),
    Text(TextAttributes),
    Img(ImgAttributes),
    A(AnchorAttributes),
    Script(ScriptAttributes),
    Div(DivAttributes),
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Meta {
    pub label: Option<UiText>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UiText {
    /// Kratos' message id; `0` when absent, which matches no id login looks for.
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub text: String,
    /// `info`, `error` or `success`.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// The values Kratos filled its text with (`provider`, `min_length`, ...).
    #[serde(default, deserialize_with = "null_as_default")]
    pub context: serde_json::Map<String, Value>,
}

/// A `null` where a default will do, so one odd field doesn't fail the whole flow.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Deserialize)]
pub(crate) struct InputAttributes {
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub autocomplete: Option<String>,
    #[serde(default)]
    pub maxlength: Option<u64>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default, rename = "onclickTrigger")]
    pub onclick_trigger: Option<String>,
    #[serde(default, rename = "onloadTrigger")]
    pub onload_trigger: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TextAttributes {
    pub text: UiText,
    #[serde(default)]
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ImgAttributes {
    pub src: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub width: Option<u64>,
    #[serde(default)]
    pub height: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AnchorAttributes {
    pub href: String,
    pub title: UiText,
    #[serde(default)]
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ScriptAttributes {
    pub src: String,
    #[serde(default, rename = "async")]
    pub is_async: bool,
    #[serde(default)]
    pub crossorigin: Option<String>,
    #[serde(default)]
    pub integrity: Option<String>,
    #[serde(default)]
    pub referrerpolicy: Option<String>,
    #[serde(default)]
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DivAttributes {
    #[serde(default)]
    pub id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_or_missing_context_is_empty() {
        let null: UiText = serde_json::from_str(r#"{"id": 1, "context": null}"#).unwrap();
        let missing: UiText = serde_json::from_str(r#"{"id": 1}"#).unwrap();
        let given: UiText = serde_json::from_str(r#"{"id": 1, "context": {"a": 2}}"#).unwrap();

        assert!(null.context.is_empty());
        assert!(missing.context.is_empty());
        assert_eq!(given.context["a"], 2);
    }
}
