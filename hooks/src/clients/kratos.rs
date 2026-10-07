use super::{UpstreamError, read_json, send};
use base64::Engine;
use rand::RngExt;
use serde::Deserialize;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct KratosAdmin {
    client: reqwest::Client,
    base: String,
}

/// The parts of a Kratos identity hooks reads or has to write back.
#[derive(Debug, Deserialize)]
pub(crate) struct Identity {
    pub(crate) id: Uuid,
    pub(crate) schema_id: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    pub(crate) traits: serde_json::Value,
    #[serde(default)]
    verifiable_addresses: Vec<VerifiableAddress>,
    #[serde(default)]
    metadata_public: serde_json::Value,
    #[serde(default)]
    metadata_admin: serde_json::Value,
    #[serde(default)]
    credentials: HashMap<String, Credential>,
}

#[derive(Debug, Deserialize)]
struct VerifiableAddress {
    value: String,
    #[serde(default)]
    verified: bool,
}

#[derive(Debug, Deserialize)]
struct Credential {
    /// What Kratos addresses the credential by; for `oidc`, one `provider:subject` per link.
    #[serde(default)]
    identifiers: Vec<String>,
    #[serde(default)]
    config: serde_json::Value,
}

impl Identity {
    /// Whether Kratos lets the identity sign in. Anything but `active` (a deactivated
    /// identity, or a state this code doesn't know) counts as not.
    pub(crate) fn is_active(&self) -> bool {
        self.state.as_deref() == Some("active")
    }

    fn has_credential(&self, credential_type: &str) -> bool {
        self.credentials.contains_key(credential_type)
    }

    pub(crate) fn email(&self) -> Option<&str> {
        self.traits.get("email")?.as_str()
    }

    /// Whether the address in `traits.email` is one Kratos has verified.
    pub(crate) fn email_verified(&self) -> bool {
        let Some(email) = self.email() else {
            return false;
        };
        self.verifiable_addresses
            .iter()
            .any(|address| address.verified && address.value.eq_ignore_ascii_case(email))
    }

    /// The access token Kratos stored when `provider` signed this identity up.
    /// Empty (an import, a provider that returned none) counts as absent.
    pub(crate) fn oidc_access_token(&self, provider: &str) -> Option<&str> {
        self.credentials
            .get("oidc")?
            .config
            .get("providers")?
            .as_array()?
            .iter()
            .find(|entry| entry.get("provider").and_then(|p| p.as_str()) == Some(provider))?
            .get("initial_access_token")?
            .as_str()
            .filter(|token| !token.is_empty())
    }

    /// The `provider:subject` identifier of each linked social login. Needs the identity
    /// fetched with the OIDC credential included.
    pub(crate) fn oidc_identifiers(&self) -> &[String] {
        self.credentials
            .get("oidc")
            .map(|credential| credential.identifiers.as_slice())
            .unwrap_or_default()
    }

    /// The PUT body that sets `password` and keeps everything else. Kratos' admin update
    /// requires `state`, so it is sent as `active`; callers write back active identities only.
    /// Kratos replaces a password credential given this way and leaves the other types alone.
    fn with_password(&self, password: &str) -> serde_json::Value {
        let mut body = serde_json::json!({
            "schema_id": self.schema_id,
            "state": "active",
            "traits": self.traits,
            "credentials": { "password": { "config": { "password": password } } },
        });
        if let Some(body) = body.as_object_mut() {
            for (key, value) in [
                ("metadata_public", &self.metadata_public),
                ("metadata_admin", &self.metadata_admin),
            ] {
                if !value.is_null() {
                    body.insert(key.into(), value.clone());
                }
            }
        }
        body
    }
}

/// Credential types the recovery purge removes besides the password and the OIDC links
/// (those go one by one, see [`KratosAdmin::delete_oidc_link`]). Kratos answers 404 for a
/// type the identity doesn't have.
pub(crate) const PURGED_CREDENTIAL_TYPES: &[&str] =
    &["webauthn", "passkey", "totp", "lookup_secret"];

impl KratosAdmin {
    pub(crate) fn new(client: reqwest::Client, base: String) -> Self {
        Self { client, base }
    }

    /// `include_oidc` adds the OIDC credential's links and provider tokens.
    pub(crate) async fn get_identity(
        &self,
        id: Uuid,
        include_oidc: bool,
    ) -> Result<Identity, UpstreamError> {
        let mut request = self
            .client
            .get(format!("{}/admin/identities/{id}", self.base));
        if include_oidc {
            request = request.query(&[("include_credential", "oidc")]);
        }
        let what = "kratos get identity";
        read_json(what, send(what, request).await?).await
    }

    /// Replaces the identity's password with a random one nobody knows, which
    /// ends the old one. Kratos refuses to delete a last first-factor
    /// credential, so deleting it isn't an option for an account that has
    /// nothing else; the user sets a new one afterwards. The identity is read
    /// again right before the write, which sends its state back: an admin
    /// deactivation in between must not be undone, so a non-active identity is refused.
    pub(crate) async fn scramble_password(&self, id: Uuid) -> Result<(), UpstreamError> {
        let what = "kratos replace password";
        let identity = self.get_identity(id, false).await?;
        if !identity.is_active() {
            return Err(UpstreamError::Inactive { what });
        }
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let password = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let request = self
            .client
            .put(format!("{}/admin/identities/{}", self.base, identity.id))
            .json(&identity.with_password(&password));
        send(what, request).await?;
        Ok(())
    }

    /// Unlinks one social login by its `provider:subject` identifier; one that is
    /// already gone is not an error.
    pub(crate) async fn delete_oidc_link(
        &self,
        id: Uuid,
        identifier: &str,
    ) -> Result<(), UpstreamError> {
        let request = self
            .client
            .delete(format!(
                "{}/admin/identities/{id}/credentials/oidc",
                self.base
            ))
            .query(&[("identifier", identifier)]);
        ignore_not_found(send("kratos delete oidc link", request).await)
    }

    /// Deletes one credential type; an identity without it is not an error.
    pub(crate) async fn delete_credential(
        &self,
        id: Uuid,
        credential_type: &str,
    ) -> Result<(), UpstreamError> {
        // Kratos' credential DELETE refuses passkeys (400); only a JSON patch removes them, and
        // that 400s for a passkey the identity doesn't have, so look first.
        let request = if credential_type == "passkey" {
            if !self
                .get_identity(id, false)
                .await?
                .has_credential("passkey")
            {
                return Ok(());
            }
            self.client
                .patch(format!("{}/admin/identities/{id}", self.base))
                .json(&serde_json::json!([{"op": "remove", "path": "/credentials/passkey"}]))
        } else {
            self.client.delete(format!(
                "{}/admin/identities/{id}/credentials/{credential_type}",
                self.base
            ))
        };
        ignore_not_found(send("kratos delete credential", request).await)
    }

    /// Ids of the identity's active sessions (the first page).
    pub(crate) async fn active_sessions(&self, id: Uuid) -> Result<Vec<Uuid>, UpstreamError> {
        #[derive(Deserialize)]
        struct Session {
            id: Uuid,
        }
        let request = self
            .client
            .get(format!("{}/admin/identities/{id}/sessions", self.base))
            .query(&[("active", "true"), ("page_size", "250")]);
        let what = "kratos list sessions";
        let sessions: Vec<Session> = read_json(what, send(what, request).await?).await?;
        Ok(sessions.into_iter().map(|session| session.id).collect())
    }

    pub(crate) async fn revoke_session(&self, session_id: Uuid) -> Result<(), UpstreamError> {
        let request = self
            .client
            .delete(format!("{}/admin/sessions/{session_id}", self.base));
        ignore_not_found(send("kratos revoke session", request).await)
    }

    pub(crate) async fn revoke_all_sessions(&self, id: Uuid) -> Result<(), UpstreamError> {
        let request = self
            .client
            .delete(format!("{}/admin/identities/{id}/sessions", self.base));
        ignore_not_found(send("kratos revoke sessions", request).await)
    }

    /// Deleting an identity that is already gone is success.
    pub(crate) async fn delete_identity(&self, id: Uuid) -> Result<(), UpstreamError> {
        let request = self
            .client
            .delete(format!("{}/admin/identities/{id}", self.base));
        ignore_not_found(send("kratos delete identity", request).await)
    }
}

fn ignore_not_found(result: Result<reqwest::Response, UpstreamError>) -> Result<(), UpstreamError> {
    match result {
        Err(error) if error.is_not_found() => Ok(()),
        other => other.map(|_| ()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(json: serde_json::Value) -> Identity {
        serde_json::from_value(json).unwrap()
    }

    fn base() -> serde_json::Value {
        serde_json::json!({
            "id": "11111111-1111-1111-1111-111111111111",
            "schema_id": "default",
            "traits": {"email": "Alice@example.com"},
            "verifiable_addresses": [{"value": "alice@example.com", "verified": true}],
        })
    }

    #[test]
    fn email_is_verified_only_when_that_address_is() {
        assert!(identity(base()).email_verified());

        let mut unverified = base();
        unverified["verifiable_addresses"][0]["verified"] = false.into();
        assert!(!identity(unverified).email_verified());

        let mut other = base();
        other["verifiable_addresses"][0]["value"] = "bob@example.com".into();
        assert!(!identity(other).email_verified());

        let mut none = base();
        none["traits"] = serde_json::json!({});
        assert!(!identity(none).email_verified());
    }

    #[test]
    fn the_stored_provider_token_is_found_by_provider_and_empty_counts_as_absent() {
        let mut json = base();
        json["credentials"] = serde_json::json!({"oidc": {"config": {"providers": [
            {"provider": "github", "initial_access_token": "gh"},
            {"provider": "google", "initial_access_token": "g"},
            {"provider": "empty", "initial_access_token": ""},
        ]}}});
        let identity = identity(json);

        assert_eq!(identity.oidc_access_token("google"), Some("g"));
        assert_eq!(identity.oidc_access_token("github"), Some("gh"));
        assert_eq!(identity.oidc_access_token("empty"), None);
        assert_eq!(identity.oidc_access_token("other"), None);
    }

    #[test]
    fn a_credential_is_present_by_its_type() {
        let mut json = base();
        json["credentials"] = serde_json::json!({"passkey": {}});
        let identity = identity(json);

        assert!(identity.has_credential("passkey"));
        assert!(!identity.has_credential("totp"));
    }

    #[test]
    fn the_password_body_keeps_traits_and_metadata_and_adds_only_the_password() {
        let mut json = base();
        json["metadata_public"] = serde_json::json!({"x": 1});

        let body = identity(json).with_password("pw");

        assert_eq!(body["traits"]["email"], "Alice@example.com");
        assert_eq!(body["metadata_public"]["x"], 1);
        assert_eq!(body["state"], "active");
        assert_eq!(body["credentials"]["password"]["config"]["password"], "pw");
        assert!(body.get("metadata_admin").is_none());
        assert_eq!(body["credentials"].as_object().unwrap().len(), 1);
    }
}
