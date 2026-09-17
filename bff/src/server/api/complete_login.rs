pub(crate) use service::complete_login;
pub(crate) use service::CompleteLoginError;

mod service {
    use axum::http::{header, StatusCode};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::{DateTime, Utc};
    use common_macros::ErrorResponses;
    use rand::RngExt;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use thiserror::Error;
    use uuid::Uuid;

    use crate::model::session::SessionData;
    use crate::server::cookie::build_cookie;
    use crate::server::AppState;
    use crate::storage::SessionStorage;

    fn b64url(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[derive(Serialize)]
    struct TokenExchangeRequest<'a> {
        grant_type: &'static str,
        code: &'a str,
        redirect_uri: &'a str,
        code_verifier: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_secret: Option<&'a str>,
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: String,
        expires_at: DateTime<Utc>,
        refresh_expires_at: DateTime<Utc>,
        user_id: Uuid,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    #[error_response_no_openapi]
    pub(crate) enum CompleteLoginError {
        #[error("redirect_uri is not allowed")]
        #[error_response(StatusCode::BAD_REQUEST, details = "redirect_uri is not allowed")]
        InvalidRedirectUri,
        #[error("token exchange failed")]
        #[error_response(StatusCode::BAD_REQUEST, details = "token exchange failed")]
        TokenExchangeFailed,
        #[error("backend returned an unexpected response")]
        #[error_response(StatusCode::BAD_GATEWAY, details = "backend returned an unexpected response")]
        BackendUnavailable,
    }

    /// Drives the PKCE authorization-code exchange against backend
    /// server-to-server given an already-minted `login_session` -- backend
    /// mints one of these the same way whether it came from a password
    /// `/oauth/login` or an `/oauth/oidc/{provider}/callback`, so both bff
    /// login paths converge here. Saves the resulting session and returns the
    /// `Set-Cookie` header value for it; the caller builds the actual redirect
    /// response.
    ///
    /// Per RFC 6749 4.1.1, authenticating the resource owner happens before a
    /// code is issued -- backend enforces this by requiring `login_session`
    /// before `/oauth/authorize` will issue one, for any caller, not just bff.
    ///
    /// `redirect_uri` is sent as-is to backend's `/oauth/authorize`, which
    /// allowlist-checks it and refuses to issue a code for anything not
    /// listed. bff never navigates the browser there itself during this hop
    /// (redirects aren't followed), so there's no open-redirect exposure in
    /// sending the real value through.
    pub(crate) async fn complete_login(
        state: &mut AppState,
        login_session: &str,
        redirect_uri: &str,
    ) -> Result<String, CompleteLoginError> {
        let mut verifier_bytes = [0u8; 32];
        rand::rng().fill(&mut verifier_bytes);
        let code_verifier = b64url(&verifier_bytes);
        let challenge = b64url(&Sha256::digest(code_verifier.as_bytes()));

        let qs = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("login_session", login_session)
            .finish();

        let authorize_resp = state
            .http_client
            .get(format!("{}/oauth/authorize?{}", state.config.backend_url, qs))
            .send()
            .await
            .map_err(|_| CompleteLoginError::BackendUnavailable)?;

        if authorize_resp.status() == StatusCode::BAD_REQUEST {
            // backend rejected redirect_uri (not allowlisted) -- a client error, not a
            // backend-connectivity problem.
            return Err(CompleteLoginError::InvalidRedirectUri);
        }
        if !authorize_resp.status().is_redirection() {
            return Err(CompleteLoginError::BackendUnavailable);
        }
        let location = authorize_resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(CompleteLoginError::BackendUnavailable)?;
        let code = url::Url::parse(location)
            .ok()
            .and_then(|u| u.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.into_owned()))
            .ok_or(CompleteLoginError::BackendUnavailable)?;

        let token_req = TokenExchangeRequest {
            grant_type: "authorization_code",
            code: &code,
            redirect_uri,
            code_verifier: &code_verifier,
            client_id: None,
            client_secret: None,
        };
        let token_resp = state
            .http_client
            .post(format!("{}/oauth/token", state.config.backend_url))
            .form(&token_req)
            .send()
            .await
            .map_err(|_| CompleteLoginError::BackendUnavailable)?;

        if !token_resp.status().is_success() {
            return Err(CompleteLoginError::TokenExchangeFailed);
        }
        let token: TokenResponse = token_resp
            .json()
            .await
            .map_err(|_| CompleteLoginError::BackendUnavailable)?;

        let session_id = Uuid::new_v4().to_string();
        state
            .sessions
            .save_session(
                session_id.clone(),
                SessionData {
                    access_token: token.access_token.into(),
                    refresh_token: token.refresh_token.into(),
                    expires_at: token.expires_at,
                    refresh_expires_at: token.refresh_expires_at,
                    user_id: token.user_id,
                },
            )
            .await;

        let max_age = (token.expires_at - Utc::now()).num_seconds().max(0);
        Ok(build_cookie(
            &state.config.session_cookie_name,
            &session_id,
            "/",
            max_age,
            state.config.secure_cookies(),
        ))
    }
}
