pub(crate) use controller::oidc_callback;
pub(crate) use controller::oidc_callback_doc;
pub(crate) use controller::oidc_confirm_link;
pub(crate) use controller::oidc_confirm_link_doc;
pub(crate) use controller::oidc_login;
pub(crate) use controller::oidc_login_doc;
pub(crate) use controller::oidc_providers;
pub(crate) use controller::oidc_providers_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::Redirect;
    use common::extract::{ApiJson, ApiQuery};
    use common_macros::ErrorResponses;
    use indoc::indoc;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::server::AppState;

    use super::service;

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct OidcLoginQuery {
        pub(super) provider: String,
    }

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct OidcCallbackQuery {
        pub(super) provider: String,
        pub(super) code: String,
        pub(super) state: String,
        /// Set when this sign-in confirms a pending link: it must then come
        /// from an identity already linked to that pending link's account.
        pub(super) pending_link_token: Option<String>,
    }

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct OidcConfirmLinkRequest {
        pub(super) pending_link_token: String,
        pub(super) password: String,
    }

    #[derive(Serialize, JsonSchema)]
    pub(crate) struct OidcConfirmLinkResponse {
        /// Same shape as a successful `/oauth/login` response.
        pub(super) login_session: String,
    }

    #[derive(Serialize, JsonSchema)]
    pub(crate) struct OidcProvidersResponse {
        /// Ordered by key.
        providers: Vec<OidcProviderEntry>,
    }

    #[derive(Serialize, JsonSchema)]
    struct OidcProviderEntry {
        /// What goes in bff's `/oidc/{provider}/login`.
        key: String,
        display_name: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum OidcError {
        #[error("unknown oidc provider")]
        #[error_response(StatusCode::NOT_FOUND, details = "unknown oidc provider")]
        UnknownProvider,
        #[error("invalid or expired oidc state")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid or expired oidc state")]
        InvalidState,
        #[error("oidc token exchange or id token verification failed")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "oidc token exchange or id token verification failed"
        )]
        ExchangeFailed,
        #[error("oidc provider did not return a verified email")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "oidc provider did not return a verified email"
        )]
        EmailNotVerified,
        #[error("downstream extra-data handler rejected the new user")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "downstream extra-data handler rejected the new user"
        )]
        DownstreamServiceFailed,
        #[error("oidc provider profile api call failed")]
        #[error_response(
            StatusCode::BAD_GATEWAY,
            details = "oidc provider profile api call failed"
        )]
        ProfileApiFailed,
        #[error("a permission this deployment requires was not granted at the oidc provider")]
        #[error_response(
            StatusCode::FORBIDDEN,
            details = "a permission this deployment requires was not granted at the oidc provider"
        )]
        ConsentRequired,
        #[error("this sign-in is not linked to the account being confirmed")]
        #[error_response(
            StatusCode::CONFLICT,
            details = "this sign-in is not linked to the account being confirmed"
        )]
        LinkConfirmationFailed,
    }

    impl From<service::OidcServiceError> for OidcError {
        fn from(err: service::OidcServiceError) -> Self {
            if let service::OidcServiceError::ConsentRequired(_)
            | service::OidcServiceError::LinkConfirmationFailed(_) = &err
            {
                // A declined permission, or the wrong or a stale sign-in for a link: not a fault.
                tracing::info!(%err, "oidc callback refused");
            }
            if let service::OidcServiceError::ExchangeFailed(_)
            | service::OidcServiceError::DownstreamServiceFailed(_)
            | service::OidcServiceError::ProfileApiFailed(_) = &err
            {
                tracing::warn!(%err, "oidc callback failed");
            }
            match err {
                service::OidcServiceError::UnknownProvider => OidcError::UnknownProvider,
                service::OidcServiceError::InvalidState => OidcError::InvalidState,
                service::OidcServiceError::ExchangeFailed(_) => OidcError::ExchangeFailed,
                service::OidcServiceError::EmailNotVerified => OidcError::EmailNotVerified,
                service::OidcServiceError::DownstreamServiceFailed(_) => {
                    OidcError::DownstreamServiceFailed
                }
                service::OidcServiceError::ProfileApiFailed(_) => OidcError::ProfileApiFailed,
                service::OidcServiceError::ConsentRequired(_) => OidcError::ConsentRequired,
                service::OidcServiceError::LinkConfirmationFailed(_) => {
                    OidcError::LinkConfirmationFailed
                }
            }
        }
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum ConfirmLinkError {
        #[error("invalid or expired pending oidc link")]
        #[error_response(
            StatusCode::BAD_REQUEST,
            details = "invalid or expired pending oidc link"
        )]
        InvalidPendingLink,
        #[error("incorrect password")]
        #[error_response(StatusCode::UNAUTHORIZED, details = "incorrect password")]
        PasswordConfirmationFailed,
    }

    impl From<service::ConfirmLinkServiceError> for ConfirmLinkError {
        fn from(err: service::ConfirmLinkServiceError) -> Self {
            match err {
                service::ConfirmLinkServiceError::InvalidPendingLink => {
                    ConfirmLinkError::InvalidPendingLink
                }
                service::ConfirmLinkServiceError::PasswordConfirmationFailed => {
                    ConfirmLinkError::PasswordConfirmationFailed
                }
            }
        }
    }

    pub(crate) fn oidc_providers_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("oidc_providers")
            .summary("List the configured OIDC providers")
            .description(indoc! {"
                Each configured provider's key and the name a login page should show for it
                (`display_name`, default the key capitalized). bff serves this as its own
                /oidc/providers."})
    }

    pub(crate) fn oidc_login_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("oidc_login")
            .summary("Start a third-party OIDC login")
            .description(indoc! {r#"
                Not meant to be called by the browser directly -- bff proxies this
                server-to-server and relays the redirect. `provider` (query param) is one of the
                keys configured under `oidc_providers`, e.g. "google"."#})
    }

    pub(crate) fn oidc_callback_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("oidc_callback")
            .summary("Complete a third-party OIDC login")
            .description(indoc! {"
                Not meant to be called by the provider directly -- backend isn't
                internet-exposed, so bff receives the provider's redirect at its own public URL
                and forwards provider+code+state (all query params) here server-to-server.
                Returns either an Authenticated login_session (same shape as a successful
                /oauth/login), or a LinkConfirmationRequired response if this email matches an
                existing account this identity isn't linked to yet. The link is confirmed either
                with the account's password (/oauth/oidc/confirm-link) or by calling this again
                for a sign-in through one of the account's linked providers, passing
                pending_link_token (409 if that sign-in isn't linked to the account)."})
    }

    pub(crate) fn oidc_confirm_link_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("oidc_confirm_link")
            .summary("Link an OIDC identity into an existing account with its password")
            .description(indoc! {"
                Call after /oauth/oidc/callback returns LinkConfirmationRequired, supplying that
                account's password. On success, the identity is linked and the account is marked
                email_verified."})
    }

    pub(crate) async fn oidc_providers(
        State(state): State<AppState>,
    ) -> Json<OidcProvidersResponse> {
        let providers = state
            .oidc_display_names
            .iter()
            .map(|(key, display_name)| OidcProviderEntry {
                key: key.clone(),
                display_name: display_name.clone(),
            })
            .collect();
        Json(OidcProvidersResponse { providers })
    }

    pub(crate) async fn oidc_login(
        State(mut state): State<AppState>,
        ApiQuery(query): ApiQuery<OidcLoginQuery>,
    ) -> Result<Redirect, OidcError> {
        let auth_url = service::oidc_login(&mut state, query.provider).await?;
        Ok(Redirect::to(&auth_url))
    }

    pub(crate) async fn oidc_callback(
        State(mut state): State<AppState>,
        ApiQuery(query): ApiQuery<OidcCallbackQuery>,
    ) -> Result<Json<service::OidcCallbackResponse>, OidcError> {
        let purpose = match query.pending_link_token {
            Some(pending_link_token) => {
                service::CallbackPurpose::ConfirmLink { pending_link_token }
            }
            None => service::CallbackPurpose::SignIn,
        };
        let response =
            service::oidc_callback(&mut state, query.provider, query.code, query.state, purpose)
                .await?;
        Ok(Json(response))
    }

    /// Finishes linking an OIDC identity that `oidc_callback` flagged as
    /// `LinkConfirmationRequired`, once the caller has supplied the existing
    /// account's password.
    pub(crate) async fn oidc_confirm_link(
        State(mut state): State<AppState>,
        ApiJson(req): ApiJson<OidcConfirmLinkRequest>,
    ) -> Result<Json<OidcConfirmLinkResponse>, ConfirmLinkError> {
        let login_session =
            service::oidc_confirm_link(&mut state, &req.pending_link_token, req.password.into())
                .await?;
        Ok(Json(OidcConfirmLinkResponse { login_session }))
    }
}

mod service {
    use std::collections::HashMap;

    use openidconnect::core::{CoreAuthenticationFlow, CoreIdToken};
    use openidconnect::{
        AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
        PkceCodeVerifier, Scope, TokenResponse,
    };
    use schemars::JsonSchema;
    use secrecy::{ExposeSecret, SecretString};
    use serde::Serialize;
    use thiserror::Error;

    use crate::crypto;
    use crate::model::user::PasswordHash;
    use crate::server::AppState;
    use crate::storage::{
        LoginSessionStorage, OidcLinkOutcome, OidcStateStorage, PendingOidcLinkStorage,
        UserStorage, VerifiedEmail,
    };

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum OidcServiceError {
        #[error("unknown oidc provider")]
        UnknownProvider,
        #[error("invalid or expired oidc state")]
        InvalidState,
        #[error("oidc token exchange or id token verification failed: {0}")]
        ExchangeFailed(String),
        /// Accounts are linked across providers by email (see
        /// `UserStorage::resolve_oidc_login`), so an id_token whose email
        /// isn't provider-confirmed can't be trusted for that -- rather than
        /// silently falling back to an unmerged identity, this fails loudly
        /// since it means either the provider doesn't verify emails
        /// (shouldn't happen for a provider deliberately configured here) or
        /// something is misconfigured (e.g. missing the `email` scope).
        #[error("oidc provider did not return a verified email")]
        EmailNotVerified,
        #[error("downstream extra-data handler rejected the new user: {0}")]
        DownstreamServiceFailed(String),
        #[error("oidc provider profile api call failed: {0}")]
        ProfileApiFailed(String),
        #[error("the user did not grant required scope '{0}'")]
        ConsentRequired(String),
        #[error("pending oidc link not confirmed: {0}")]
        LinkConfirmationFailed(String),
    }

    #[derive(Debug, Error, Eq, PartialEq)]
    pub(crate) enum ConfirmLinkServiceError {
        #[error("invalid or expired pending oidc link")]
        InvalidPendingLink,
        #[error("incorrect password")]
        PasswordConfirmationFailed,
    }

    #[derive(Serialize, JsonSchema)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub(crate) enum OidcCallbackResponse {
        /// Same shape as a successful `/oauth/login` response -- single-use
        /// proof of this authentication, required by `/oauth/authorize`.
        Authenticated { login_session: String },
        /// An account with this email already exists and this identity isn't
        /// linked to it (see `UserStorage::resolve_oidc_login`); the OIDC
        /// login isn't authenticated yet. Confirm with the account's password
        /// (`/oauth/oidc/confirm-link`, only if `has_password`) or a sign-in
        /// through one of `linked_providers` (`/oauth/oidc/callback` with
        /// `pending_link_token`).
        LinkConfirmationRequired {
            pending_link_token: String,
            email: String,
            has_password: bool,
            linked_providers: Vec<String>,
        },
    }

    /// What a callback sign-in is for.
    pub(crate) enum CallbackPurpose {
        SignIn,
        /// Confirms this pending link; the sign-in must be through an
        /// identity already linked to its account.
        ConfirmLink {
            pending_link_token: String,
        },
    }

    /// Starts a third-party OIDC login for `provider`, returning the
    /// provider's consent-screen URL to redirect the caller to.
    pub(crate) async fn oidc_login(
        state: &mut AppState,
        provider: String,
    ) -> Result<String, OidcServiceError> {
        let client = state
            .oidc_providers
            .get(&provider)
            .ok_or(OidcServiceError::UnknownProvider)?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let scopes = state
            .oidc_scopes
            .get(&provider)
            .into_iter()
            .flatten()
            .cloned()
            .map(Scope::new);
        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scopes(scopes)
            .set_pkce_challenge(pkce_challenge)
            .url();

        state
            .oidc_state
            .save_state(
                csrf_token.secret().clone(),
                provider,
                pkce_verifier.secret().clone(),
                nonce.secret().clone(),
            )
            .await;

        Ok(auth_url.to_string())
    }

    pub(crate) async fn oidc_callback(
        state: &mut AppState,
        provider: String,
        code: String,
        query_state: String,
        purpose: CallbackPurpose,
    ) -> Result<OidcCallbackResponse, OidcServiceError> {
        let login_state = state
            .oidc_state
            .take_state(&query_state)
            .await
            .filter(|s| s.provider == provider)
            .ok_or(OidcServiceError::InvalidState)?;
        let stored_provider = login_state.provider;

        let client = state
            .oidc_providers
            .get(&stored_provider)
            .ok_or(OidcServiceError::UnknownProvider)?;

        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(
                login_state.pkce_verifier.expose_secret().to_string(),
            ))
            .request_async(&*state.oidc_http_client)
            .await
            .map_err(|error| {
                OidcServiceError::ExchangeFailed(format!(
                    "provider '{stored_provider}' code exchange: {}",
                    common::error::cause_chain(&error)
                ))
            })?;

        let id_token = token_response.id_token().ok_or_else(|| {
            OidcServiceError::ExchangeFailed(format!(
                "provider '{stored_provider}' returned no id_token"
            ))
        })?;
        let claims = id_token
            .claims(
                &client.id_token_verifier(),
                &Nonce::new(login_state.nonce.expose_secret().to_string()),
            )
            .map_err(|error| {
                OidcServiceError::ExchangeFailed(format!(
                    "provider '{stored_provider}' id_token: {}",
                    common::error::cause_chain(&error)
                ))
            })?;

        // Accounts are linked across providers by matching this email against
        // existing users (see `resolve_oidc_login`), so it must be one the
        // provider has actually confirmed the user owns -- otherwise anyone
        // able to put an arbitrary "email" claim in an id_token could attach
        // themselves to any victim's account. Naming that proof here (rather
        // than a bare `if` guarding a later call) is what lets
        // `resolve_oidc_login` require a `VerifiedEmail` in its signature --
        // this is the only place in the codebase allowed to construct one
        // from an OIDC claim.
        let email = claims
            .email()
            .ok_or(OidcServiceError::EmailNotVerified)?
            .as_str()
            .to_string();
        let verified_email =
            VerifiedEmail::new(email.clone(), claims.email_verified() == Some(true))
                .ok_or(OidcServiceError::EmailNotVerified)?;
        let subject = claims.subject().as_str();
        // Before anything can create a user: a confirming sign-in must be an existing one.
        match purpose {
            CallbackPurpose::ConfirmLink { pending_link_token } => {
                return confirm_link_via_linked_identity(
                    state,
                    &stored_provider,
                    subject,
                    &pending_link_token,
                )
                .await;
            }
            CallbackPurpose::SignIn => {}
        }
        let is_new_user = state.users.get_user_by_email(&email).await.is_none();
        let mut profile = profile_fields(id_token, state.oidc_extra_claims.get(&stored_provider));

        if is_new_user {
            let access_token = token_response.access_token().secret();
            let all_apis = state
                .oidc_profile_apis
                .get(&stored_provider)
                .map(Vec::as_slice)
                .unwrap_or_default();
            // Decided before any call goes out, so a required entry whose scope
            // was declined fails without calling anything.
            let mut apis = Vec::new();
            for api in all_apis {
                match api
                    .scope
                    .as_deref()
                    .filter(|scope| !scope_granted(&token_response, scope))
                {
                    Some(scope) if api.required => {
                        return Err(OidcServiceError::ConsentRequired(scope.to_string()));
                    }
                    Some(scope) => {
                        tracing::info!(%scope, provider = %stored_provider, "user declined scope, skipping profile api")
                    }
                    None => apis.push(api),
                }
            }
            let results = futures_util::future::join_all(
                apis.iter()
                    .map(|api| fetch_profile_api(&state.oidc_http_client, api, access_token)),
            )
            .await;
            // Results come back in list order, so a later entry still wins a field-name clash.
            for (api, result) in apis.iter().zip(results) {
                match result {
                    Ok(ProfileApiFields {
                        missing: Some(cause),
                        ..
                    }) if api.required => {
                        return Err(OidcServiceError::ProfileApiFailed(cause));
                    }
                    Ok(ProfileApiFields { found, .. }) => profile.extend(found),
                    Err(cause) if api.required => {
                        return Err(OidcServiceError::ProfileApiFailed(cause));
                    }
                    Err(cause) => {
                        tracing::warn!(%cause, provider = %stored_provider, "optional oidc profile api call failed")
                    }
                }
            }
        }

        // The handler hears about a new user before the user exists, so a
        // rejection leaves nothing behind -- same order as password registration.
        let new_user_id = uuid::Uuid::new_v4();
        if is_new_user && !profile.is_empty() {
            forward_profile(state, new_user_id, &email, &profile).await?;
        }

        let response = match state
            .users
            .resolve_oidc_login(&stored_provider, subject, &verified_email, new_user_id)
            .await
        {
            OidcLinkOutcome::Resolved(user) => {
                let login_session = state.login_sessions.create_session(user.id).await;
                OidcCallbackResponse::Authenticated { login_session }
            }
            OidcLinkOutcome::RequiresLinkConfirmation {
                existing_user_id,
                has_password,
                linked_providers,
            } => {
                let pending_link_token = state
                    .pending_oidc_links
                    .save_pending_link(stored_provider, subject.to_string(), existing_user_id)
                    .await;
                OidcCallbackResponse::LinkConfirmationRequired {
                    pending_link_token,
                    email,
                    has_password,
                    linked_providers,
                }
            }
        };

        Ok(response)
    }

    /// Links the identity waiting under `pending_link_token` once
    /// `(provider, subject)` -- the sign-in that just completed -- proves to be
    /// already linked to the same account. The pending link is spent either way.
    async fn confirm_link_via_linked_identity(
        state: &mut AppState,
        provider: &str,
        subject: &str,
        pending_link_token: &str,
    ) -> Result<OidcCallbackResponse, OidcServiceError> {
        let pending_link = state
            .pending_oidc_links
            .take_pending_link(pending_link_token)
            .await
            .ok_or_else(|| {
                OidcServiceError::LinkConfirmationFailed("pending link unknown or expired".into())
            })?;
        let owner = state.users.oidc_identity_owner(provider, subject).await;
        if owner != Some(pending_link.existing_user_id) {
            return Err(OidcServiceError::LinkConfirmationFailed(format!(
                "provider '{provider}' sign-in belongs to {owner:?}, not account {}",
                pending_link.existing_user_id
            )));
        }
        let user = state
            .users
            .link_verified_oidc_identity(
                pending_link.existing_user_id,
                &pending_link.provider,
                &pending_link.subject,
            )
            .await
            .ok_or_else(|| {
                OidcServiceError::LinkConfirmationFailed(format!(
                    "account {} no longer exists",
                    pending_link.existing_user_id
                ))
            })?;
        let login_session = state.login_sessions.create_session(user.id).await;
        Ok(OidcCallbackResponse::Authenticated { login_session })
    }

    /// Reads the id_token claims the deployer mapped for this provider
    /// (`OidcProviderConfig::extra_claims`). Only called with a token whose
    /// signature `IdToken::claims` has already verified; scalar claims are
    /// stringified, anything else is skipped.
    fn profile_fields(
        id_token: &CoreIdToken,
        mapping: Option<&HashMap<String, String>>,
    ) -> HashMap<String, String> {
        use base64::Engine;
        let payload = id_token
            .to_string()
            .split('.')
            .nth(1)
            .and_then(|segment| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(segment)
                    .ok()
            })
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        let (Some(payload), Some(mapping)) = (payload, mapping) else {
            return HashMap::new();
        };
        mapping
            .iter()
            .filter_map(|(field, claim)| {
                Some((field.clone(), scalar_to_string(payload.get(claim)?)?))
            })
            .collect()
    }

    fn scalar_to_string(value: &serde_json::Value) -> Option<String> {
        match value {
            serde_json::Value::String(value) => Some(value.clone()),
            serde_json::Value::Bool(_) | serde_json::Value::Number(_) => Some(value.to_string()),
            _ => None,
        }
    }

    /// A token response without a `scope` field means the provider granted
    /// what was asked for (RFC 6749 section 5.1).
    fn scope_granted(token_response: &impl OAuth2TokenResponse, scope: &str) -> bool {
        token_response
            .scopes()
            .is_none_or(|granted| granted.iter().any(|s| s.as_str() == scope))
    }

    /// What a profile API call that succeeded found.
    pub(crate) struct ProfileApiFields {
        pub(crate) found: HashMap<String, String>,
        /// Set when some mapped pointer found nothing. Not a failed call: the
        /// caller returns it only for a `required` entry and otherwise drops it.
        pub(crate) missing: Option<String>,
    }

    /// Calls one configured profile API with the user's access token. An `Err`
    /// is a failed call (request error, non-2xx, body that isn't JSON); the
    /// caller decides whether to log or return it.
    pub(crate) async fn fetch_profile_api(
        client: &openidconnect::reqwest::Client,
        api: &crate::config::ProfileApiConfig,
        access_token: &str,
    ) -> Result<ProfileApiFields, String> {
        let url = &api.url;
        let response = client
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| {
                format!(
                    "request to {url} failed: {}",
                    common::error::cause_chain(&error.without_url())
                )
            })?;
        if !response.status().is_success() {
            return Err(format!("{url} returned {}", response.status()));
        }
        let body = response.text().await.map_err(|error| {
            format!(
                "reading {url} failed: {}",
                common::error::cause_chain(&error.without_url())
            )
        })?;
        let json: serde_json::Value = serde_json::from_str(&body)
            .map_err(|error| format!("{url} did not return valid JSON: {error}"))?;

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
        let missing = (!missing_pointers.is_empty()).then(|| {
            // Key names only: enough to see what the API sent, no personal data.
            let keys = json
                .as_object()
                .map(|object| object.keys().cloned().collect::<Vec<_>>().join(", "));
            format!(
                "{url} has no value at {} (response keys: {})",
                missing_pointers.join(", "),
                keys.as_deref().unwrap_or("not an object")
            )
        });
        Ok(ProfileApiFields { found, missing })
    }

    async fn forward_profile(
        state: &AppState,
        user_id: uuid::Uuid,
        email: &str,
        profile: &HashMap<String, String>,
    ) -> Result<(), OidcServiceError> {
        let Some(handler) = state.extra_data_handler.as_ref() else {
            return Ok(());
        };
        handler
            .handle(user_id, email, profile)
            .await
            .map_err(|error| OidcServiceError::DownstreamServiceFailed(error.0))
    }

    /// Finishes linking an OIDC identity that `oidc_callback` flagged as
    /// `LinkConfirmationRequired`, once the caller has supplied the existing
    /// account's password.
    pub(crate) async fn oidc_confirm_link(
        state: &mut AppState,
        pending_link_token: &str,
        password: SecretString,
    ) -> Result<String, ConfirmLinkServiceError> {
        let pending_link = state
            .pending_oidc_links
            .take_pending_link(pending_link_token)
            .await
            .ok_or(ConfirmLinkServiceError::InvalidPendingLink)?;

        let user = state
            .users
            .get_user_by_id(pending_link.existing_user_id)
            .await
            .ok_or(ConfirmLinkServiceError::InvalidPendingLink)?;
        let hash = user
            .password
            .ok_or(ConfirmLinkServiceError::PasswordConfirmationFailed)?;
        let is_legacy_bcrypt = matches!(hash, PasswordHash::Bcrypt(_));

        // No dummy-hash timing guard needed: pending_link_token already reveals the account exists.
        match crypto::verify_password(hash, password.clone(), state.max_bcrypt_cost).await {
            Ok(crypto::PasswordVerifyOutcome::Verified) => {}
            Ok(crypto::PasswordVerifyOutcome::NotVerified) => {
                return Err(ConfirmLinkServiceError::PasswordConfirmationFailed);
            }
            Err(error) => {
                tracing::warn!(%error, user_id = %user.id, "oidc confirm-link password check errored");
                return Err(ConfirmLinkServiceError::PasswordConfirmationFailed);
            }
        }

        if is_legacy_bcrypt {
            crate::server::api::upgrade_bcrypt_to_argon2(&mut state.users, user.id, password).await;
        }

        let user = state
            .users
            .link_verified_oidc_identity(
                pending_link.existing_user_id,
                &pending_link.provider,
                &pending_link.subject,
            )
            .await
            .ok_or(ConfirmLinkServiceError::PasswordConfirmationFailed)?;
        let login_session = state.login_sessions.create_session(user.id).await;

        Ok(login_session)
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::Json;
    use axum::extract::State;
    use common::extract::{ApiJson, ApiQuery};
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::model::user::{PasswordHash, User};
    use crate::server::AppState;
    use crate::storage::{OidcStateStorage, PendingOidcLinkStorage, UserStorage};

    async fn state_with_no_providers() -> AppState {
        AppState {
            pkce: crate::storage::in_memory::InMemoryPkceStorage::new(300),
            users: crate::storage::in_memory::InMemoryUserStorage::new(),
            login_sessions: crate::storage::in_memory::InMemoryLoginSessionStorage::new(60),
            redirect_uri_allowlist: Arc::new(vec![]),
            jwt_keys: crate::storage::in_memory::InMemoryJwkStorage::new()
                .expect("RSA keygen for tests never fails"),
            access_token_ttl_secs: 900,
            refresh_tokens: crate::storage::in_memory::InMemoryRefreshTokenStorage::new(2_592_000),
            refresh_token_ttl_secs: 2_592_000,
            jwt_key_rotation_interval_secs: 2_592_000,
            issuer: "http://localhost:1983".into(),
            oidc_providers: Arc::new(HashMap::new()),
            oidc_extra_claims: Arc::new(Default::default()),
            oidc_scopes: Arc::new(Default::default()),
            oidc_display_names: Arc::new(Default::default()),
            oidc_profile_apis: Arc::new(Default::default()),
            oidc_state: crate::storage::in_memory::InMemoryOidcStateStorage::new(300),
            pending_oidc_links: crate::storage::in_memory::InMemoryPendingOidcLinkStorage::new(300),
            oidc_http_client: Arc::new(openidconnect::reqwest::Client::new()),
            email_verification: crate::server::api::email_verification::EmailVerification::disabled(
            ),
            password_reset_tokens:
                crate::storage::in_memory::InMemoryPasswordResetTokenStorage::new(1_800),
            max_bcrypt_cost: 12,
            extra_data_handler: None,
            login_claims_handler: None,
        }
    }

    #[tokio::test]
    async fn login_rejects_unknown_provider() {
        let state = state_with_no_providers().await;

        let result = oidc_login(
            State(state),
            ApiQuery(OidcLoginQuery {
                provider: "google".to_string(),
            }),
        )
        .await;

        assert_eq!(result.err(), Some(OidcError::UnknownProvider));
    }

    #[tokio::test]
    async fn callback_rejects_missing_or_unknown_state() {
        let state = state_with_no_providers().await;
        let query = OidcCallbackQuery {
            provider: "google".to_string(),
            code: "irrelevant".to_string(),
            state: "no-such-state".to_string(),
            pending_link_token: None,
        };

        let result = oidc_callback(State(state), ApiQuery(query)).await;

        assert_eq!(result.err(), Some(OidcError::InvalidState));
    }

    #[tokio::test]
    async fn callback_rejects_state_issued_for_a_different_provider() {
        let mut state = state_with_no_providers().await;
        state
            .oidc_state
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;
        let query = OidcCallbackQuery {
            provider: "some-other-provider".to_string(),
            code: "irrelevant".to_string(),
            state: "csrf-token".to_string(),
            pending_link_token: None,
        };

        let result = oidc_callback(State(state), ApiQuery(query)).await;

        assert_eq!(result.err(), Some(OidcError::InvalidState));
    }

    #[tokio::test]
    async fn callback_state_is_single_use() {
        let mut state = state_with_no_providers().await;
        state
            .oidc_state
            .save_state(
                "csrf-token".to_string(),
                "google".to_string(),
                "verifier".to_string(),
                "nonce".to_string(),
            )
            .await;
        let query = OidcCallbackQuery {
            provider: "google".to_string(),
            code: "irrelevant".to_string(),
            state: "csrf-token".to_string(),
            pending_link_token: None,
        };
        // First call consumes the state; provider is unknown here (no real
        // client configured in this test), so it fails past the state check
        // -- what matters is the state entry is gone afterwards.
        let _ = oidc_callback(State(state.clone()), ApiQuery(query)).await;

        let replay_query = OidcCallbackQuery {
            provider: "google".to_string(),
            code: "irrelevant".to_string(),
            state: "csrf-token".to_string(),
            pending_link_token: None,
        };
        let result = oidc_callback(State(state), ApiQuery(replay_query)).await;

        assert_eq!(result.err(), Some(OidcError::InvalidState));
    }

    /// Builds a real `OidcClient` (via discovery against a mocked issuer)
    /// plus a matching signed id_token, so `oidc_callback` can run its full
    /// exchange instead of stopping at the state/provider lookup like the
    /// other tests here.
    async fn provider_and_id_token(
        email: &str,
        email_verified: bool,
        nonce: &str,
    ) -> (
        String,
        std::sync::Arc<HashMap<String, crate::oidc::OidcClient>>,
        String,
    ) {
        provider_and_id_token_granting(email, email_verified, nonce, None).await
    }

    /// `granted_scope` is the `scope` field of the token response; `None` omits it.
    async fn provider_and_id_token_granting(
        email: &str,
        email_verified: bool,
        nonce: &str,
        granted_scope: Option<&str>,
    ) -> (
        String,
        std::sync::Arc<HashMap<String, crate::oidc::OidcClient>>,
        String,
    ) {
        use serde::Serialize;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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

        let signing_key =
            crate::crypto::JwtKeys::generate().expect("RSA keygen for tests never fails");

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "keys": [signing_key.jwk()] })),
            )
            .mount(&server)
            .await;

        #[derive(Serialize)]
        struct IdTokenClaims<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: &'a str,
            exp: i64,
            iat: i64,
            nonce: &'a str,
            email: &'a str,
            email_verified: bool,
            given_name: &'a str,
            family_name: &'a str,
        }

        let now = chrono::Utc::now();
        let claims = IdTokenClaims {
            iss: &issuer,
            sub: "provider-subject",
            aud: "client-id",
            exp: (now + chrono::Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            nonce,
            email,
            email_verified,
            given_name: "Alice",
            family_name: "Liddell",
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(signing_key.kid.clone());
        let id_token =
            jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key).expect("signing");

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut body = serde_json::json!({
                    "access_token": "opaque-access-token",
                    "token_type": "Bearer",
                    "id_token": id_token,
                });
                if let Some(scope) = granted_scope {
                    body["scope"] = scope.into();
                }
                body
            }))
            .mount(&server)
            .await;

        let mut configs = HashMap::new();
        configs.insert(
            "test-provider".to_string(),
            crate::config::OidcProviderConfig {
                issuer: issuer.clone(),
                client_id: "client-id".to_string(),
                client_secret: secrecy::SecretString::from("client-secret".to_string()),
                redirect_uri: Some("http://localhost/callback".to_string()),
                display_name: None,
                extra_claims: HashMap::new(),
                scopes: vec!["email".to_string()],
                profile_apis: Vec::new(),
            },
        );
        let http_client = openidconnect::reqwest::Client::new();
        let providers = crate::oidc::build_providers(&configs, "http://bff.test", &http_client)
            .await
            .expect("discovery succeeds");

        // The mock server must outlive the request that hits it -- returning
        // it (leaked, effectively) alongside the providers keeps it alive
        // for the caller's `oidc_callback` call.
        std::mem::forget(server);
        (issuer, std::sync::Arc::new(providers), id_token)
    }

    #[tokio::test]
    async fn callback_resolves_to_authenticated_when_the_provider_confirms_the_email() {
        let (_issuer, providers, _id_token) =
            provider_and_id_token("alice@example.com", true, "test-nonce").await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        state
            .oidc_state
            .save_state(
                "csrf-token".to_string(),
                "test-provider".to_string(),
                "verifier".to_string(),
                "test-nonce".to_string(),
            )
            .await;
        let query = OidcCallbackQuery {
            provider: "test-provider".to_string(),
            code: "irrelevant".to_string(),
            state: "csrf-token".to_string(),
            pending_link_token: None,
        };

        let result = oidc_callback(State(state), ApiQuery(query)).await;

        let Json(super::service::OidcCallbackResponse::Authenticated { .. }) =
            result.expect("callback succeeds")
        else {
            unreachable!("expected Authenticated");
        };
    }

    struct RecordingHandler {
        calls: std::sync::Mutex<Vec<(uuid::Uuid, std::collections::HashMap<String, String>)>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl crate::server::api::register::ExtraDataHandler for RecordingHandler {
        async fn handle(
            &self,
            user_id: uuid::Uuid,
            _email: &str,
            fields: &HashMap<String, String>,
        ) -> Result<(), crate::server::api::register::ExtraDataError> {
            self.calls.lock().unwrap().push((user_id, fields.clone()));
            if self.fail {
                Err(crate::server::api::register::ExtraDataError(
                    "stub rejected".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }

    async fn run_callback(state: &AppState, csrf: &str) -> Result<(), OidcError> {
        callback_response(state, csrf, None).await.map(|_| ())
    }

    async fn callback_response(
        state: &AppState,
        csrf: &str,
        pending_link_token: Option<&str>,
    ) -> Result<Json<super::service::OidcCallbackResponse>, OidcError> {
        state
            .oidc_state
            .clone()
            .save_state(
                csrf.to_string(),
                "test-provider".to_string(),
                "verifier".to_string(),
                "test-nonce".to_string(),
            )
            .await;
        let query = OidcCallbackQuery {
            provider: "test-provider".to_string(),
            code: "irrelevant".to_string(),
            state: csrf.to_string(),
            pending_link_token: pending_link_token.map(str::to_string),
        };
        oidc_callback(State(state.clone()), ApiQuery(query)).await
    }

    #[tokio::test]
    async fn login_requests_the_providers_configured_scopes() {
        let (_issuer, providers, _id_token) =
            provider_and_id_token("alice@example.com", true, "test-nonce").await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        state.oidc_scopes = Arc::new(HashMap::from([(
            "test-provider".to_string(),
            vec!["email".to_string(), "https://example.com/phone".to_string()],
        )]));

        let auth_url = super::service::oidc_login(&mut state, "test-provider".to_string())
            .await
            .expect("login starts");

        let url = url::Url::parse(&auth_url).expect("valid url");
        let scope = url
            .query_pairs()
            .find(|(key, _)| key == "scope")
            .expect("scope param")
            .1
            .into_owned();
        assert_eq!(scope, "openid email https://example.com/phone");
    }

    #[tokio::test]
    async fn first_oidc_login_forwards_profile_claims_to_the_extra_data_handler_once() {
        let (_issuer, providers, _id_token) =
            provider_and_id_token("alice@example.com", true, "test-nonce").await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        state.oidc_extra_claims = Arc::new(HashMap::from([(
            "test-provider".to_string(),
            HashMap::from([
                ("first_name".to_string(), "given_name".to_string()),
                ("surname".to_string(), "family_name".to_string()),
            ]),
        )]));
        let handler = Arc::new(RecordingHandler {
            calls: Default::default(),
            fail: false,
        });
        state.extra_data_handler = Some(handler.clone());

        run_callback(&state, "csrf-1")
            .await
            .expect("callback succeeds");
        run_callback(&state, "csrf-2")
            .await
            .expect("callback succeeds");

        let created = state
            .users
            .get_user_by_email("alice@example.com")
            .await
            .expect("user created");
        let calls = handler.calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "only the login that creates the user forwards claims"
        );
        assert_eq!(
            calls[0].0, created.id,
            "handler is told the id the user is created with"
        );
        assert_eq!(
            calls[0].1.get("first_name").map(String::as_str),
            Some("Alice")
        );
        assert_eq!(
            calls[0].1.get("surname").map(String::as_str),
            Some("Liddell")
        );
    }

    #[tokio::test]
    async fn failing_extra_data_handler_fails_the_login_and_creates_no_user() {
        let (_issuer, providers, _id_token) =
            provider_and_id_token("alice@example.com", true, "test-nonce").await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        state.oidc_extra_claims = Arc::new(HashMap::from([(
            "test-provider".to_string(),
            HashMap::from([("first_name".to_string(), "given_name".to_string())]),
        )]));
        state.extra_data_handler = Some(Arc::new(RecordingHandler {
            calls: Default::default(),
            fail: true,
        }));

        let result = run_callback(&state, "csrf-1").await;

        assert_eq!(result, Err(OidcError::DownstreamServiceFailed));
        assert!(
            state
                .users
                .get_user_by_email("alice@example.com")
                .await
                .is_none()
        );
    }

    async fn profile_api_server(
        response: wiremock::ResponseTemplate,
        expected_calls: u64,
    ) -> wiremock::MockServer {
        use wiremock::matchers::{header, method, path};
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(path("/me"))
            .and(header("authorization", "Bearer opaque-access-token"))
            .respond_with(response)
            .expect(expected_calls)
            .mount(&server)
            .await;
        server
    }

    fn profile_api(
        server: &wiremock::MockServer,
        claims: &[(&str, &str)],
        required: bool,
    ) -> crate::config::ProfileApiConfig {
        crate::config::ProfileApiConfig {
            url: format!("{}/me", server.uri()),
            claims: claims
                .iter()
                .map(|(field, pointer)| (field.to_string(), pointer.to_string()))
                .collect(),
            required,
            scope: None,
        }
    }

    /// A state whose provider calls `apis` on first login and whose handler
    /// also gets `first_name` from the id_token, so it is invoked even when
    /// every profile API contributes nothing.
    async fn state_with_profile_apis(
        apis: Vec<crate::config::ProfileApiConfig>,
    ) -> (AppState, Arc<RecordingHandler>) {
        state_with_profile_apis_granting(apis, None).await
    }

    async fn state_with_profile_apis_granting(
        apis: Vec<crate::config::ProfileApiConfig>,
        granted_scope: Option<&str>,
    ) -> (AppState, Arc<RecordingHandler>) {
        let (_issuer, providers, _id_token) =
            provider_and_id_token_granting("alice@example.com", true, "test-nonce", granted_scope)
                .await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        state.oidc_extra_claims = Arc::new(HashMap::from([(
            "test-provider".to_string(),
            HashMap::from([("first_name".to_string(), "given_name".to_string())]),
        )]));
        state.oidc_profile_apis = Arc::new(HashMap::from([("test-provider".to_string(), apis)]));
        let handler = Arc::new(RecordingHandler {
            calls: Default::default(),
            fail: false,
        });
        state.extra_data_handler = Some(handler.clone());
        (state, handler)
    }

    fn phone_response() -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "phoneNumbers": [{ "value": "+46701234567" }] }))
    }

    #[tokio::test]
    async fn profile_api_fields_reach_the_handler_once_per_new_user() {
        // `expect(1)` over two logins: the second login is not a new user.
        let server = profile_api_server(phone_response(), 1).await;
        let api = profile_api(&server, &[("phone_number", "/phoneNumbers/0/value")], false);
        let (state, handler) = state_with_profile_apis(vec![api]).await;

        run_callback(&state, "csrf-1")
            .await
            .expect("callback succeeds");
        run_callback(&state, "csrf-2")
            .await
            .expect("callback succeeds");

        let calls = handler.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1.get("phone_number").map(String::as_str),
            Some("+46701234567")
        );
        assert_eq!(
            calls[0].1.get("first_name").map(String::as_str),
            Some("Alice"),
            "id_token claims still forwarded"
        );
    }

    #[tokio::test]
    async fn required_profile_api_failure_fails_the_login_and_creates_no_user() {
        let server = profile_api_server(wiremock::ResponseTemplate::new(500), 1).await;
        let api = profile_api(&server, &[("phone_number", "/phoneNumbers/0/value")], true);
        let (state, handler) = state_with_profile_apis(vec![api]).await;

        let result = run_callback(&state, "csrf-1").await;

        assert_eq!(result, Err(OidcError::ProfileApiFailed));
        assert!(
            state
                .users
                .get_user_by_email("alice@example.com")
                .await
                .is_none()
        );
        assert!(handler.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn optional_profile_api_failure_leaves_the_field_out_and_logs_in() {
        let server = profile_api_server(wiremock::ResponseTemplate::new(500), 1).await;
        let api = profile_api(&server, &[("phone_number", "/phoneNumbers/0/value")], false);
        let (state, handler) = state_with_profile_apis(vec![api]).await;

        run_callback(&state, "csrf-1")
            .await
            .expect("callback succeeds");

        assert!(
            state
                .users
                .get_user_by_email("alice@example.com")
                .await
                .is_some()
        );
        let calls = handler.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].1.contains_key("phone_number"));
    }

    #[tokio::test]
    async fn a_missing_value_is_a_failure_only_when_the_call_is_required() {
        let server = profile_api_server(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
            2,
        )
        .await;
        let claims = [("phone_number", "/phoneNumbers/0/value")];

        let (state, _handler) =
            state_with_profile_apis(vec![profile_api(&server, &claims, true)]).await;
        assert_eq!(
            run_callback(&state, "csrf-1").await,
            Err(OidcError::ProfileApiFailed)
        );

        let (state, _handler) =
            state_with_profile_apis(vec![profile_api(&server, &claims, false)]).await;
        assert!(run_callback(&state, "csrf-1").await.is_ok());
    }

    #[tokio::test]
    async fn every_profile_api_is_called_and_a_failed_optional_one_does_not_stop_the_rest() {
        let phone = profile_api_server(phone_response(), 1).await;
        let broken = profile_api_server(wiremock::ResponseTemplate::new(500), 1).await;
        let nickname = profile_api_server(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "nick": "ally" })),
            1,
        )
        .await;
        let apis = vec![
            profile_api(&phone, &[("phone_number", "/phoneNumbers/0/value")], false),
            profile_api(&broken, &[("birthday", "/birthday")], false),
            profile_api(&nickname, &[("nickname", "/nick")], false),
        ];
        let (state, handler) = state_with_profile_apis(apis).await;

        run_callback(&state, "csrf-1")
            .await
            .expect("callback succeeds");

        let calls = handler.calls.lock().unwrap();
        assert_eq!(
            calls[0].1.get("phone_number").map(String::as_str),
            Some("+46701234567")
        );
        assert_eq!(calls[0].1.get("nickname").map(String::as_str), Some("ally"));
        assert!(!calls[0].1.contains_key("birthday"));
    }

    #[tokio::test]
    async fn profile_apis_are_called_concurrently() {
        let delay = std::time::Duration::from_millis(500);
        let slow_phone = profile_api_server(phone_response().set_delay(delay), 1).await;
        let slow_nickname = profile_api_server(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "nick": "ally" }))
                .set_delay(delay),
            1,
        )
        .await;
        let apis = vec![
            profile_api(
                &slow_phone,
                &[("phone_number", "/phoneNumbers/0/value")],
                false,
            ),
            profile_api(&slow_nickname, &[("nickname", "/nick")], false),
        ];
        let (state, handler) = state_with_profile_apis(apis).await;

        let started = std::time::Instant::now();
        run_callback(&state, "csrf-1")
            .await
            .expect("callback succeeds");
        let elapsed = started.elapsed();

        // One after the other would take at least twice the delay.
        assert!(elapsed < delay * 2, "calls ran sequentially: {elapsed:?}");
        let calls = handler.calls.lock().unwrap();
        assert_eq!(
            calls[0].1.get("phone_number").map(String::as_str),
            Some("+46701234567")
        );
        assert_eq!(calls[0].1.get("nickname").map(String::as_str), Some("ally"));
    }

    const PHONE_SCOPE: &str = "https://example.com/auth/phone";

    fn scoped(mut api: crate::config::ProfileApiConfig) -> crate::config::ProfileApiConfig {
        api.scope = Some(PHONE_SCOPE.to_string());
        api
    }

    #[tokio::test]
    async fn a_declined_scope_skips_an_optional_call_without_calling_it() {
        let server = profile_api_server(phone_response(), 0).await;
        let api = scoped(profile_api(
            &server,
            &[("phone_number", "/phoneNumbers/0/value")],
            false,
        ));
        let (state, handler) =
            state_with_profile_apis_granting(vec![api], Some("openid email")).await;

        run_callback(&state, "csrf-1")
            .await
            .expect("callback succeeds");

        assert!(
            state
                .users
                .get_user_by_email("alice@example.com")
                .await
                .is_some()
        );
        assert!(
            !handler.calls.lock().unwrap()[0]
                .1
                .contains_key("phone_number")
        );
    }

    #[tokio::test]
    async fn a_declined_scope_fails_a_required_call_without_calling_it() {
        let server = profile_api_server(phone_response(), 0).await;
        let api = scoped(profile_api(
            &server,
            &[("phone_number", "/phoneNumbers/0/value")],
            true,
        ));
        let (state, handler) =
            state_with_profile_apis_granting(vec![api], Some("openid email")).await;

        let result = run_callback(&state, "csrf-1").await;

        assert_eq!(result, Err(OidcError::ConsentRequired));
        assert!(
            state
                .users
                .get_user_by_email("alice@example.com")
                .await
                .is_none()
        );
        assert!(handler.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_granted_scope_lets_the_call_through() {
        let server = profile_api_server(phone_response(), 1).await;
        let api = scoped(profile_api(
            &server,
            &[("phone_number", "/phoneNumbers/0/value")],
            true,
        ));
        let granted = format!("openid email {PHONE_SCOPE}");
        let (state, handler) = state_with_profile_apis_granting(vec![api], Some(&granted)).await;

        run_callback(&state, "csrf-1")
            .await
            .expect("callback succeeds");

        assert_eq!(
            handler.calls.lock().unwrap()[0]
                .1
                .get("phone_number")
                .map(String::as_str),
            Some("+46701234567")
        );
    }

    #[tokio::test]
    async fn a_token_response_without_a_scope_field_counts_as_granting_what_was_asked() {
        let server = profile_api_server(phone_response(), 1).await;
        let api = scoped(profile_api(
            &server,
            &[("phone_number", "/phoneNumbers/0/value")],
            true,
        ));
        let (state, _handler) = state_with_profile_apis_granting(vec![api], None).await;

        assert!(run_callback(&state, "csrf-1").await.is_ok());
    }

    #[tokio::test]
    async fn an_optional_call_keeps_the_fields_it_found_when_another_is_missing() {
        let server = profile_api_server(phone_response(), 1).await;
        let claims = [
            ("phone_number", "/phoneNumbers/0/value"),
            ("birthday", "/birthdays/0/date"),
        ];
        let (state, handler) =
            state_with_profile_apis(vec![profile_api(&server, &claims, false)]).await;

        run_callback(&state, "csrf-1")
            .await
            .expect("callback succeeds");

        let calls = handler.calls.lock().unwrap();
        assert_eq!(
            calls[0].1.get("phone_number").map(String::as_str),
            Some("+46701234567")
        );
        assert!(!calls[0].1.contains_key("birthday"));
    }

    #[tokio::test]
    async fn a_missing_value_error_names_the_response_keys_but_not_their_values() {
        let body = serde_json::json!({ "resourceName": "people/secret-id", "etag": "abc" });
        let server =
            profile_api_server(wiremock::ResponseTemplate::new(200).set_body_json(body), 1).await;
        let api = profile_api(&server, &[("phone_number", "/phoneNumbers/0/value")], false);

        let result = super::service::fetch_profile_api(
            &openidconnect::reqwest::Client::new(),
            &api,
            "opaque-access-token",
        )
        .await
        .expect("a response without the value is not a failed call");

        assert!(result.found.is_empty());
        let error = result.missing.expect("reports what was missing");
        assert!(error.contains("/phoneNumbers/0/value"), "{error}");
        assert!(
            error.contains("resourceName") && error.contains("etag"),
            "{error}"
        );
        assert!(
            !error.contains("secret-id"),
            "values must not be logged: {error}"
        );
    }

    #[tokio::test]
    async fn callback_rejects_an_id_token_whose_email_is_not_verified() {
        // The only reason this must fail is the provider's email_verified
        // claim being false -- everything else about the exchange (issuer,
        // audience, signature, nonce) is valid. Without this check, anyone
        // able to put an arbitrary "email" in an id_token could attach
        // themselves to any victim's account (see the comment at the call
        // site in `service::oidc_callback`).
        let (_issuer, providers, _id_token) =
            provider_and_id_token("alice@example.com", false, "test-nonce").await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        state
            .oidc_state
            .save_state(
                "csrf-token".to_string(),
                "test-provider".to_string(),
                "verifier".to_string(),
                "test-nonce".to_string(),
            )
            .await;
        let query = OidcCallbackQuery {
            provider: "test-provider".to_string(),
            code: "irrelevant".to_string(),
            state: "csrf-token".to_string(),
            pending_link_token: None,
        };

        let result = oidc_callback(State(state), ApiQuery(query)).await;

        assert_eq!(result.err(), Some(OidcError::EmailNotVerified));
    }

    #[tokio::test]
    async fn confirm_link_rejects_missing_or_expired_token() {
        let state = state_with_no_providers().await;
        let req = OidcConfirmLinkRequest {
            pending_link_token: "no-such-token".to_string(),
            password: "whatever".to_string(),
        };

        let result = oidc_confirm_link(State(state), ApiJson(req)).await;

        assert_eq!(result.err(), Some(ConfirmLinkError::InvalidPendingLink));
    }

    #[tokio::test]
    async fn confirm_link_rejects_wrong_password() {
        use crate::crypto::ARGON2;
        use argon2::PasswordHasher;

        let mut state = state_with_no_providers().await;
        let hash = ARGON2
            .hash_password(b"correct-password")
            .expect("hashing a test password never fails")
            .to_string();
        let user = User {
            email: "squatter@example.com".to_string(),
            password: Some(PasswordHash::Argon2(hash.into())),
            email_verified: false,
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let token = state
            .pending_oidc_links
            .save_pending_link("google".to_string(), "sub-123".to_string(), user_id)
            .await;

        let req = OidcConfirmLinkRequest {
            pending_link_token: token,
            password: "wrong-password".to_string(),
        };
        let result = oidc_confirm_link(State(state.clone()), ApiJson(req)).await;

        assert_eq!(
            result.err(),
            Some(ConfirmLinkError::PasswordConfirmationFailed)
        );
        // Untouched: still unverified, no identity linked.
        let still_unverified = state
            .users
            .get_user_by_email("squatter@example.com")
            .await
            .unwrap();
        assert!(!still_unverified.email_verified);
    }

    #[tokio::test]
    async fn confirm_link_succeeds_with_correct_password_and_is_single_use() {
        use crate::crypto::ARGON2;
        use argon2::PasswordHasher;

        let mut state = state_with_no_providers().await;
        let hash = ARGON2
            .hash_password(b"correct-password")
            .expect("hashing a test password never fails")
            .to_string();
        let user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2(hash.into())),
            email_verified: false,
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let token = state
            .pending_oidc_links
            .save_pending_link("google".to_string(), "sub-123".to_string(), user_id)
            .await;

        let req = OidcConfirmLinkRequest {
            pending_link_token: token.clone(),
            password: "correct-password".to_string(),
        };
        let Json(body) = oidc_confirm_link(State(state.clone()), ApiJson(req))
            .await
            .unwrap();
        assert!(!body.login_session.is_empty());

        let now_verified = state
            .users
            .get_user_by_email("alice@example.com")
            .await
            .unwrap();
        assert!(now_verified.email_verified);

        // Single-use: the same token can't be redeemed twice.
        let replay = OidcConfirmLinkRequest {
            pending_link_token: token,
            password: "correct-password".to_string(),
        };
        let result = oidc_confirm_link(State(state), ApiJson(replay)).await;
        assert_eq!(result.err(), Some(ConfirmLinkError::InvalidPendingLink));
    }

    /// A user already linked to "test-provider" as `provider-subject`, with a
    /// pending LinkedIn identity waiting to be linked to the same account.
    async fn state_with_pending_linkedin_link(
        sign_in_email: &str,
    ) -> (AppState, uuid::Uuid, String) {
        let (_issuer, providers, _id_token) =
            provider_and_id_token(sign_in_email, true, "test-nonce").await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        let user = User {
            email: "alice@example.com".to_string(),
            email_verified: true,
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let token = state
            .pending_oidc_links
            .save_pending_link("linkedin".to_string(), "li-sub".to_string(), user_id)
            .await;
        (state, user_id, token)
    }

    #[tokio::test]
    async fn callback_links_a_pending_identity_when_signing_in_through_one_already_linked() {
        let (mut state, user_id, token) =
            state_with_pending_linkedin_link("alice@example.com").await;
        let _ = state
            .users
            .link_verified_oidc_identity(user_id, "test-provider", "provider-subject")
            .await;

        let result = callback_response(&state, "csrf-token", Some(&token)).await;

        let Ok(Json(super::service::OidcCallbackResponse::Authenticated { .. })) = result else {
            unreachable!("expected Authenticated");
        };
        assert_eq!(
            state.users.oidc_identity_owner("linkedin", "li-sub").await,
            Some(user_id)
        );
        assert!(
            state
                .pending_oidc_links
                .take_pending_link(&token)
                .await
                .is_none(),
            "the pending link is single-use"
        );
    }

    #[tokio::test]
    async fn callback_refuses_a_pending_link_when_the_sign_in_is_not_linked_to_that_account() {
        let (state, _user_id, token) = state_with_pending_linkedin_link("other@example.com").await;

        let result = callback_response(&state, "csrf-token", Some(&token)).await;

        assert_eq!(result.err(), Some(OidcError::LinkConfirmationFailed));
        assert_eq!(
            state.users.oidc_identity_owner("linkedin", "li-sub").await,
            None
        );
        assert!(
            state
                .users
                .get_user_by_email("other@example.com")
                .await
                .is_none(),
            "no account is created for the sign-in"
        );
    }

    #[tokio::test]
    async fn callback_refuses_a_pending_link_when_the_sign_in_is_linked_to_another_account() {
        let (mut state, _user_id, token) =
            state_with_pending_linkedin_link("bob@example.com").await;
        let bob = User {
            email: "bob@example.com".to_string(),
            email_verified: true,
            ..User::default()
        };
        let bob_id = bob.id;
        let _ = state.users.create_user(bob).await;
        let _ = state
            .users
            .link_verified_oidc_identity(bob_id, "test-provider", "provider-subject")
            .await;

        let result = callback_response(&state, "csrf-token", Some(&token)).await;

        assert_eq!(result.err(), Some(OidcError::LinkConfirmationFailed));
        assert_eq!(
            state.users.oidc_identity_owner("linkedin", "li-sub").await,
            None
        );
    }

    #[tokio::test]
    async fn callback_for_an_existing_account_lists_how_the_link_can_be_confirmed() {
        let (_issuer, providers, _id_token) =
            provider_and_id_token("alice@example.com", true, "test-nonce").await;
        let mut state = state_with_no_providers().await;
        state.oidc_providers = providers;
        let user = User {
            email: "alice@example.com".to_string(),
            password: Some(PasswordHash::Argon2("hash".into())),
            email_verified: true,
            ..User::default()
        };
        let user_id = user.id;
        let _ = state.users.create_user(user).await;
        let _ = state
            .users
            .link_verified_oidc_identity(user_id, "linkedin", "li-sub")
            .await;

        let result = callback_response(&state, "csrf-token", None).await;

        let Ok(Json(super::service::OidcCallbackResponse::LinkConfirmationRequired {
            email,
            has_password,
            linked_providers,
            ..
        })) = result
        else {
            unreachable!("expected LinkConfirmationRequired");
        };
        assert_eq!(email, "alice@example.com");
        assert!(has_password);
        assert_eq!(linked_providers, vec!["linkedin".to_string()]);
    }

    #[tokio::test]
    async fn providers_lists_each_configured_provider_with_its_display_name() {
        let mut state = state_with_no_providers().await;
        state.oidc_display_names = Arc::new(std::collections::BTreeMap::from([
            ("google".to_string(), "Google".to_string()),
            ("linkedin".to_string(), "LinkedIn".to_string()),
        ]));

        let Json(body) = oidc_providers(State(state)).await;

        assert_eq!(
            serde_json::to_value(body).unwrap(),
            serde_json::json!({"providers": [
                {"key": "google", "display_name": "Google"},
                {"key": "linkedin", "display_name": "LinkedIn"},
            ]})
        );
    }
}
