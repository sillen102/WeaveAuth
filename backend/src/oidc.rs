use crate::config::OidcProviderConfig;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{ClientId, ClientSecret, EndpointNotSet, EndpointSet, IssuerUrl, RedirectUrl};
use secrecy::ExposeSecret;
use std::collections::HashMap;

/// A `CoreClient` built with only the auth and token endpoints set -- the
/// only two this app ever calls directly -- so every configured provider's
/// client has the same concrete type regardless of what else its discovery
/// document happens to advertise (device auth, introspection, etc).
pub(crate) type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointNotSet,
>;

/// Discovers each configured provider's endpoints and JWKS once at startup
/// (`{issuer}/.well-known/openid-configuration`), rather than hardcoding
/// endpoint URLs -- keeps working if a provider rotates its signing keys or
/// tweaks its endpoint paths.
pub(crate) async fn build_providers(
    configs: &HashMap<String, OidcProviderConfig>,
    http_client: &openidconnect::reqwest::Client,
) -> anyhow::Result<HashMap<String, OidcClient>> {
    let mut providers = HashMap::with_capacity(configs.len());
    for (name, config) in configs {
        let issuer = IssuerUrl::new(config.issuer.clone())?;
        let metadata = CoreProviderMetadata::discover_async(issuer.clone(), http_client).await?;
        let token_endpoint = metadata
            .token_endpoint()
            .ok_or_else(|| anyhow::anyhow!("oidc provider '{name}' has no token endpoint"))?
            .clone();

        let client = CoreClient::new(
            ClientId::new(config.client_id.clone()),
            issuer,
            metadata.jwks().clone(),
        )
        .set_client_secret(ClientSecret::new(config.client_secret.expose_secret().to_string()))
        .set_auth_uri(metadata.authorization_endpoint().clone())
        .set_token_uri(token_endpoint)
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri.clone())?);

        providers.insert(name.clone(), client);
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OidcProviderConfig;
    use secrecy::SecretString;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn build_providers_discovers_and_returns_a_client_for_each_configured_provider() {
        let server = MockServer::start().await;
        let issuer = server.uri();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": [] })))
            .mount(&server)
            .await;

        let mut configs = HashMap::new();
        configs.insert(
            "test-provider".to_string(),
            OidcProviderConfig {
                issuer: issuer.clone(),
                client_id: "client-id".to_string(),
                client_secret: SecretString::from("client-secret".to_string()),
                redirect_uri: "http://localhost/callback".to_string(),
            },
        );

        let http_client = openidconnect::reqwest::Client::new();
        let providers = build_providers(&configs, &http_client).await.expect("discovery succeeds");

        assert!(providers.contains_key("test-provider"));
    }
}
