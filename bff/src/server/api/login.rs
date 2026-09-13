pub(crate) use controller::start_login;

mod controller {
    use axum::body::Body;
    use axum::extract::State;
    use axum::Form;
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
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
    use crate::server::origin_check::require_trusted_origin;
    use crate::server::AppState;
    use crate::storage::SessionStorage;

    fn b64url(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[derive(Deserialize)]
    pub(crate) struct LoginRequest {
        pub(super) identifier: String,
        pub(super) password: String,
        pub(super) redirect_uri: String,
        /// Where to bounce the browser back to on wrong credentials -- the login
        /// page's own URL, supplied by its form, not user-typed input.
        pub(super) next: String,
    }

    #[derive(Serialize)]
    struct VerifyLoginRequest<'a> {
        identifier: &'a str,
        password: &'a str,
    }

    #[derive(Serialize)]
    struct TokenExchangeRequest<'a> {
        grant_type: &'static str,
        code: &'a str,
        redirect_uri: String,
        code_verifier: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_secret: Option<&'a str>,
    }

    #[derive(Deserialize)]
    struct LoginSessionResponse {
        login_session: String,
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
    pub(crate) enum LoginError {
        #[error("request did not come from a trusted origin")]
        #[error_response(StatusCode::FORBIDDEN, details = "request did not come from a trusted origin")]
        UntrustedOrigin,
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

    /// Verifies the submitted credentials against backend's `/oauth/login`, then
    /// drives the whole authorization-code + PKCE exchange server-to-server in
    /// one request, so the browser only ever talks to bff and never sees backend
    /// (it POSTs its login form straight to bff's absolute URL, so the session
    /// cookie below ends up scoped to bff's origin, not the login page's).
    ///
    /// Per RFC 6749 4.1.1, authenticating the resource owner happens before a
    /// code is issued: `/oauth/login`'s response carries a single-use
    /// `login_session` that `/oauth/authorize` requires, so backend itself
    /// enforces this order for any caller -- not just bff.
    ///
    /// The `redirect_uri` a caller passes here (the final browser destination) is
    /// sent as-is to backend's `/oauth/authorize`, which allowlist-checks it and
    /// refuses to issue a code for anything not listed. bff never navigates the
    /// browser there itself during this hop (redirects aren't followed), so
    /// there's no open-redirect exposure in sending the real value through.
    pub(crate) async fn start_login(
        State(mut state): State<AppState>,
        headers: HeaderMap,
        Form(req): Form<LoginRequest>,
    ) -> Result<Response, LoginError> {
        require_trusted_origin(&headers, &state.config.trusted_origins)
            .map_err(|_| LoginError::UntrustedOrigin)?;

        let redirect_uri = req.redirect_uri;

        let verify_resp = state
            .http_client
            .post(format!("{}/oauth/login", state.config.backend_url))
            .json(&VerifyLoginRequest {
                identifier: &req.identifier,
                password: &req.password,
            })
            .send()
            .await
            .map_err(|_| LoginError::BackendUnavailable)?;
        if verify_resp.status() == StatusCode::UNAUTHORIZED {
            // A plain form POST, not a fetch -- so a friendly bounce back to the
            // login page (rather than a bare 401 body) is what the browser shows.
            let sep = if req.next.contains('?') { '&' } else { '?' };
            return Ok((
                StatusCode::SEE_OTHER,
                [(header::LOCATION, format!("{}{sep}error=1", req.next))],
            )
                .into_response());
        }
        if !verify_resp.status().is_success() {
            return Err(LoginError::BackendUnavailable);
        }
        let login_session = verify_resp
            .json::<LoginSessionResponse>()
            .await
            .map_err(|_| LoginError::BackendUnavailable)?
            .login_session;

        let mut verifier_bytes = [0u8; 32];
        rand::rng().fill(&mut verifier_bytes);
        let code_verifier = b64url(&verifier_bytes);
        let challenge = b64url(&Sha256::digest(code_verifier.as_bytes()));

        let qs = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("login_session", &login_session)
            .finish();

        let authorize_resp = state
            .http_client
            .get(format!("{}/oauth/authorize?{}", state.config.backend_url, qs))
            .send()
            .await
            .map_err(|_| LoginError::BackendUnavailable)?;

        if authorize_resp.status() == StatusCode::BAD_REQUEST {
            // backend rejected redirect_uri (not allowlisted) -- a client error, not a
            // backend-connectivity problem.
            return Err(LoginError::InvalidRedirectUri);
        }
        if !authorize_resp.status().is_redirection() {
            return Err(LoginError::BackendUnavailable);
        }
        let location = authorize_resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(LoginError::BackendUnavailable)?;
        let code = url::Url::parse(location)
            .ok()
            .and_then(|u| u.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.into_owned()))
            .ok_or(LoginError::BackendUnavailable)?;

        let token_req = TokenExchangeRequest {
            grant_type: "authorization_code",
            code: &code,
            redirect_uri: redirect_uri.clone(),
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
            .map_err(|_| LoginError::BackendUnavailable)?;

        if !token_resp.status().is_success() {
            return Err(LoginError::TokenExchangeFailed);
        }
        let token: TokenResponse = token_resp
            .json()
            .await
            .map_err(|_| LoginError::BackendUnavailable)?;

        let session_id = Uuid::new_v4().to_string();
        state
            .sessions
            .save_session(
                session_id.clone(),
                SessionData {
                    access_token: token.access_token,
                    refresh_token: token.refresh_token,
                    expires_at: token.expires_at,
                    refresh_expires_at: token.refresh_expires_at,
                    user_id: token.user_id,
                },
            )
            .await;

        let max_age = (token.expires_at - Utc::now()).num_seconds().max(0);
        let cookie = format!(
            "{}={}; HttpOnly; Path=/; SameSite=Lax; Max-Age={}",
            state.config.session_cookie_name, session_id, max_age
        );

        Ok((
            StatusCode::SEE_OTHER,
            [(header::LOCATION, redirect_uri), (header::SET_COOKIE, cookie)],
            Body::empty(),
        )
            .into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue};
    use axum::Form;

    use crate::config::Config;
    use crate::server::AppState;

    fn state_with_trusted_origins(trusted_origins: Vec<String>) -> AppState {
        AppState::new(Config {
            port: 8080,
            bff_url: "http://bff.test".into(),
            backend_url: "http://unused.test".into(),
            session_cookie_name: "wa_session".into(),
            routes: vec![],
            trusted_origins,
            rate_limit_max_attempts: 1000,
            rate_limit_window_secs: 60,
        })
        .expect("valid app state")
    }

    #[tokio::test]
    async fn rejects_an_untrusted_origin_before_contacting_backend() {
        // backend_url above is unreachable -- a FORBIDDEN result (rather than a
        // BAD_GATEWAY from trying to reach it) proves the origin check runs first.
        let state = state_with_trusted_origins(vec!["http://login.test".to_string()]);
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("http://evil.test"));
        let req = LoginRequest {
            identifier: "alice".to_string(),
            password: "hunter2".to_string(),
            redirect_uri: "http://admin.test/".to_string(),
            next: "http://login.test/".to_string(),
        };

        let result = start_login(State(state), headers, Form(req)).await;

        assert_eq!(result.err(), Some(LoginError::UntrustedOrigin));
    }
}
