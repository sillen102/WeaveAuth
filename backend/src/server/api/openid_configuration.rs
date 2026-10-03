pub(crate) use controller::openid_configuration;
pub(crate) use controller::openid_configuration_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::Json;
    use axum::extract::State;
    use indoc::indoc;

    use crate::server::AppState;

    use super::service::{self, OpenIdConfiguration};

    pub(crate) fn openid_configuration_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("openid_configuration")
            .summary("OpenID Provider metadata")
            .description(indoc! {"
                OpenID Connect Discovery-style metadata for verifiers that configure themselves
                from the issuer URL (`WA_ISSUER`): `jwks_uri` points at
                `/.well-known/jwks.json`, and `issuer` matches access tokens' `iss` claim. Not a
                compliant OpenID Provider document: `authorization_endpoint` is left out because
                /oauth/authorize is not a standard authorize endpoint (it needs a login_session
                and takes no client_id or response_type), so a generic OAuth/OIDC client can't
                be pointed at this issuer. No id_token is ever issued;
                `id_token_signing_alg_values_supported` is there only because the spec requires
                it, and names the access token's algorithm."})
    }

    pub(crate) async fn openid_configuration(
        State(state): State<AppState>,
    ) -> Json<OpenIdConfiguration> {
        Json(service::openid_configuration(&state.issuer))
    }
}

mod service {
    use schemars::JsonSchema;
    use serde::Serialize;

    #[derive(Debug, Serialize, JsonSchema)]
    pub(crate) struct OpenIdConfiguration {
        pub(super) issuer: String,
        pub(super) token_endpoint: String,
        pub(super) jwks_uri: String,
        pub(super) response_types_supported: [&'static str; 1],
        pub(super) grant_types_supported: [&'static str; 2],
        pub(super) token_endpoint_auth_methods_supported: [&'static str; 1],
        pub(super) code_challenge_methods_supported: [&'static str; 1],
        pub(super) subject_types_supported: [&'static str; 1],
        pub(super) id_token_signing_alg_values_supported: [&'static str; 1],
    }

    pub(crate) fn openid_configuration(issuer: &str) -> OpenIdConfiguration {
        OpenIdConfiguration {
            issuer: issuer.to_string(),
            token_endpoint: format!("{issuer}/oauth/token"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code", "refresh_token"],
            token_endpoint_auth_methods_supported: ["none"],
            code_challenge_methods_supported: ["S256"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"],
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::State;

    use super::controller::*;
    use crate::server::AppState;

    #[tokio::test]
    async fn advertises_only_what_backend_supports_under_the_configured_issuer() {
        let mut state = AppState::for_test().await;
        state.issuer = "https://auth.internal".into();

        let axum::Json(body) = openid_configuration(State(state)).await;

        assert_eq!(
            serde_json::to_value(body).unwrap(),
            serde_json::json!({
                "issuer": "https://auth.internal",
                "token_endpoint": "https://auth.internal/oauth/token",
                "jwks_uri": "https://auth.internal/.well-known/jwks.json",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["none"],
                "code_challenge_methods_supported": ["S256"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })
        );
    }
}
