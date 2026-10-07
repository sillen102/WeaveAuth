//! Claims the provider's id_token doesn't carry, fetched from its APIs with
//! the access token Kratos stored at sign-up.

use crate::config::ProfileApiConfig;
use crate::webhook::read_limited;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub(crate) enum ProfileError {
    #[error("the user did not grant required scope '{0}'")]
    ConsentRequired(String),
    #[error("required profile api failed: {0}")]
    Failed(String),
}

/// What the provider APIs of one sign-up yielded. `granted_scopes` is `None`
/// when the sign-up reports none: that counts as having granted what was
/// asked for (RFC 6749 section 5.1). `access_token` is `None` when Kratos
/// holds no token for the identity, which only a `required` entry minds.
pub(crate) async fn collect(
    client: &reqwest::Client,
    provider: &str,
    apis: &[ProfileApiConfig],
    access_token: Option<&str>,
    granted_scopes: Option<&[String]>,
) -> Result<HashMap<String, String>, ProfileError> {
    // Decided before any call goes out, so a required entry whose scope was
    // declined fails without calling anything.
    let mut selected = Vec::new();
    for api in apis {
        match api
            .scope
            .as_deref()
            .filter(|scope| !scope_granted(granted_scopes, scope))
        {
            Some(scope) if api.required => {
                return Err(ProfileError::ConsentRequired(scope.to_string()));
            }
            Some(scope) => {
                tracing::info!(%scope, %provider, "user declined scope, skipping profile api")
            }
            None => selected.push(api),
        }
    }
    let Some(access_token) = access_token else {
        if selected.iter().any(|api| api.required) {
            return Err(ProfileError::Failed(format!(
                "kratos holds no access token for provider '{provider}'"
            )));
        }
        if !selected.is_empty() {
            tracing::warn!(%provider, "no stored access token, skipping optional profile apis");
        }
        return Ok(HashMap::new());
    };

    let results = futures_util::future::join_all(
        selected
            .iter()
            .map(|api| fetch_profile_api(client, api, access_token)),
    )
    .await;
    let mut fields = HashMap::new();
    // Results come back in list order, so a later entry still wins a field-name clash.
    for (api, result) in selected.iter().zip(results) {
        match result {
            Ok(ProfileApiFields::Partial { missing, .. }) if api.required => {
                return Err(ProfileError::Failed(missing));
            }
            Ok(ProfileApiFields::Complete(found) | ProfileApiFields::Partial { found, .. }) => {
                fields.extend(found)
            }
            Err(cause) if api.required => return Err(ProfileError::Failed(cause)),
            Err(cause) => {
                tracing::warn!(%cause, %provider, "optional profile api call failed")
            }
        }
    }
    Ok(fields)
}

fn scope_granted(granted: Option<&[String]>, scope: &str) -> bool {
    granted.is_none_or(|granted| granted.iter().any(|s| s == scope))
}

/// What a profile API call that succeeded found.
enum ProfileApiFields {
    Complete(HashMap<String, String>),
    /// Some mapped pointer found nothing. Not a failed call: it fails the
    /// registration only for a `required` entry.
    Partial {
        found: HashMap<String, String>,
        missing: String,
    },
}

/// Calls one configured profile API with the user's access token. An `Err`
/// is a failed call (request error, non-2xx, body that isn't JSON).
async fn fetch_profile_api(
    client: &reqwest::Client,
    api: &ProfileApiConfig,
    access_token: &str,
) -> Result<ProfileApiFields, String> {
    let place = location(&api.url);
    let response = client
        .get(&api.url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|error| {
            format!(
                "request to {place} failed: {}",
                common::error::cause_chain(&error.without_url())
            )
        })?;
    if !response.status().is_success() {
        return Err(format!("{place} returned {}", response.status()));
    }
    let body = read_limited(response)
        .await
        .map_err(|error| format!("reading {place} failed: {error}"))?;
    let json: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|error| format!("{place} did not return valid JSON: {error}"))?;

    let mut found = HashMap::new();
    let mut missing_pointers = Vec::new();
    for (field, pointer) in &api.claims {
        match json.pointer(pointer).and_then(scalar_to_string) {
            Some(value) => {
                found.insert(field.clone(), value);
            }
            None => missing_pointers.push(pointer.as_str()),
        }
    }
    if missing_pointers.is_empty() {
        return Ok(ProfileApiFields::Complete(found));
    }
    // Key names only: enough to see what the API sent, no personal data.
    let keys = json
        .as_object()
        .map(|object| object.keys().cloned().collect::<Vec<_>>().join(", "));
    let missing = format!(
        "{place} has no value at {} (response keys: {})",
        missing_pointers.join(", "),
        keys.as_deref().unwrap_or("not an object")
    );
    Ok(ProfileApiFields::Partial { found, missing })
}

/// Host and path of a configured URL, for messages: its query or userinfo may carry a key.
fn location(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(url) => format!("{}{}", url.host_str().unwrap_or_default(), url.path()),
        Err(_) => "an unparseable url".to_string(),
    }
}

/// Scalars are stringified; objects, arrays and null have no field form.
pub(crate) fn scalar_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_is_reduced_to_host_and_path() {
        assert_eq!(
            location("https://user:pw@api.example.com/v1/me?key=abc123#x"),
            "api.example.com/v1/me"
        );
        assert_eq!(location("not a url"), "an unparseable url");
    }

    #[tokio::test]
    async fn a_failed_call_names_neither_the_key_nor_the_credentials_in_its_url() {
        let api = ProfileApiConfig {
            url: "http://user:pw@127.0.0.1:1/v1/me?key=abc123".to_string(),
            claims: HashMap::new(),
            scope: None,
            required: true,
        };

        let cause = fetch_profile_api(&reqwest::Client::new(), &api, "token")
            .await
            .err()
            .expect("nothing listens on port 1");

        assert!(cause.contains("127.0.0.1/v1/me"), "{cause}");
        assert!(
            !cause.contains("abc123") && !cause.contains("pw@"),
            "{cause}"
        );
    }
}
