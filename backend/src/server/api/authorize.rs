pub(crate) use controller::authorize;
pub(crate) use controller::authorize_doc;

mod controller {
    use aide::transform::TransformOperation;
    use axum::extract::{Query, State};
    use axum::http::StatusCode;
    use axum::response::Redirect;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::RngExt;
    use schemars::JsonSchema;
    use serde::Deserialize;
    use thiserror::Error;
    use common_macros::ErrorResponses;

    use crate::model::pkce::CodeChallengeMethod;
    use crate::server::AppState;
    use crate::storage::{LoginSessionStorage, PkceStorage};

    #[derive(Deserialize, JsonSchema)]
    pub(crate) struct AuthorizeRequest {
        pub(super) redirect_uri: String,
        pub(super) code_challenge: String,
        pub(super) code_challenge_method: CodeChallengeMethod,
        #[serde(default)]
        pub(super) state: Option<String>,
        /// Single-use token from `/oauth/login` -- proves the resource owner was
        /// already authenticated (RFC 6749 4.1.1); without one, no code is issued.
        pub(super) login_session: String,
    }

    #[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]
    pub(crate) enum AuthorizeError {
        #[error("invalid login session")]
        #[error_response(StatusCode::UNAUTHORIZED, details = "invalid login session")]
        InvalidLoginSession,
        #[error("invalid redirect uri")]
        #[error_response(StatusCode::BAD_REQUEST, details = "invalid redirect uri")]
        InvalidRedirectUri,
    }

    pub(crate) async fn authorize(
        State(mut state): State<AppState>,
        Query(req): Query<AuthorizeRequest>,
    ) -> Result<Redirect, AuthorizeError> {
        let user_id = state
            .login_sessions
            .take_session(&req.login_session)
            .await
            .ok_or(AuthorizeError::InvalidLoginSession)?;

        if !state
            .redirect_uri_allowlist
            .iter()
            .any(|allowed| allowed == &req.redirect_uri)
        {
            return Err(AuthorizeError::InvalidRedirectUri);
        }

        let mut code_bytes = [0u8; 32];
        rand::rng().fill(&mut code_bytes);
        let auth_code = URL_SAFE_NO_PAD.encode(code_bytes);

        state
            .pkce
            .save_code_challenge(
                auth_code.clone(),
                req.code_challenge,
                req.code_challenge_method,
                req.redirect_uri.clone(),
                user_id,
            )
            .await;

        let location = match req.state {
            Some(s) => format!("{}?code={}&state={}", req.redirect_uri, auth_code, s),
            None => format!("{}?code={}", req.redirect_uri, auth_code),
        };
        Ok(Redirect::to(&location))
    }

    pub(crate) fn authorize_doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("authorize")
            .summary("Issue an authorization code")
            .description(
                "Requires a login_session from /oauth/login proving the user is authenticated, \
                 then binds a single-use auth_code to the given PKCE code_challenge",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    use axum::extract::{Query, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Redirect};
    use std::sync::Arc;

    use crate::model::pkce::CodeChallengeMethod;
    use crate::server::api::authorize::controller::AuthorizeError::{InvalidLoginSession, InvalidRedirectUri};
    use crate::server::AppState;
    use crate::storage::{LoginSessionStorage, PkceStorage};

    async fn state_with_allowlist(allowlist: &[&str]) -> (AppState, String) {
        let (state, login_session, _user_id) = state_with_allowlist_and_user(allowlist).await;
        (state, login_session)
    }

    async fn state_with_allowlist_and_user(allowlist: &[&str]) -> (AppState, String, uuid::Uuid) {
        let mut login_sessions = crate::storage::in_memory::InMemoryLoginSessionStorage::new(60);
        let user_id = uuid::Uuid::new_v4();
        let login_session = login_sessions.create_session(user_id).await;
        let state = AppState {
            pkce: crate::storage::in_memory::InMemoryPkceStorage::new(300),
            users: crate::storage::in_memory::InMemoryUserStorage::new(),
            login_sessions,
            redirect_uri_allowlist: Arc::new(allowlist.iter().map(|s| s.to_string()).collect()),
            jwt_keys: crate::storage::in_memory::InMemoryJwkStorage::new().expect("RSA keygen for tests never fails"),
            access_token_ttl_secs: 900,
        };
        (state, login_session, user_id)
    }

    fn location_of(redirect: Redirect) -> String {
        let response = redirect.into_response();
        response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn issues_code_for_allowed_redirect_uri() {
        let (state, login_session) = state_with_allowlist(&["http://redirect.test"]).await;
        let req = AuthorizeRequest {
            redirect_uri: "http://redirect.test".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            state: None,
            login_session,
        };

        let redirect = authorize(State(state), Query(req)).await.unwrap();

        let location = location_of(redirect);
        assert!(location.starts_with("http://redirect.test?code="));
    }

    #[tokio::test]
    async fn forwards_state_param_when_present() {
        let (state, login_session) = state_with_allowlist(&["http://redirect.test"]).await;
        let req = AuthorizeRequest {
            redirect_uri: "http://redirect.test".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            state: Some("xyz".to_string()),
            login_session,
        };

        let redirect = authorize(State(state), Query(req)).await.unwrap();

        assert!(location_of(redirect).ends_with("&state=xyz"));
    }

    #[tokio::test]
    async fn omits_state_param_when_absent() {
        let (state, login_session) = state_with_allowlist(&["http://redirect.test"]).await;
        let req = AuthorizeRequest {
            redirect_uri: "http://redirect.test".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            state: None,
            login_session,
        };

        let redirect = authorize(State(state), Query(req)).await.unwrap();

        assert!(!location_of(redirect).contains("state="));
    }

    #[tokio::test]
    async fn rejects_redirect_uri_not_in_allowlist() {
        let (state, login_session) = state_with_allowlist(&["http://allowed.test"]).await;
        let req = AuthorizeRequest {
            redirect_uri: "http://evil.test".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            state: None,
            login_session,
        };

        let result = authorize(State(state), Query(req)).await;

        assert_eq!(result.err(), Some(InvalidRedirectUri));
    }

    #[tokio::test]
    async fn rejects_missing_or_unknown_login_session() {
        let (state, _login_session) = state_with_allowlist(&["http://redirect.test"]).await;
        let req = AuthorizeRequest {
            redirect_uri: "http://redirect.test".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            state: None,
            login_session: "not-a-real-session".to_string(),
        };

        let result = authorize(State(state), Query(req)).await;

        assert_eq!(result.err(), Some(InvalidLoginSession));
    }

    #[tokio::test]
    async fn rejects_a_login_session_that_was_already_used() {
        let (state, login_session) = state_with_allowlist(&["http://redirect.test"]).await;
        let req = AuthorizeRequest {
            redirect_uri: "http://redirect.test".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            state: None,
            login_session: login_session.clone(),
        };
        let _ = authorize(State(state.clone()), Query(req)).await.unwrap();

        let replay_req = AuthorizeRequest {
            redirect_uri: "http://redirect.test".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            state: None,
            login_session,
        };
        let result = authorize(State(state), Query(replay_req)).await;

        assert_eq!(result.err(), Some(InvalidLoginSession));
    }

    #[tokio::test]
    async fn saves_code_challenge_bound_to_redirect_uri() {
        let (mut state, login_session, user_id) =
            state_with_allowlist_and_user(&["http://redirect.test"]).await;
        let req = AuthorizeRequest {
            redirect_uri: "http://redirect.test".to_string(),
            code_challenge: "my_challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            state: None,
            login_session,
        };

        let redirect = authorize(State(state.clone()), Query(req)).await.unwrap();
        let location = location_of(redirect);
        let code = location.split("code=").nth(1).unwrap();

        let saved = state.pkce.take_code_challenge(code).await;
        assert_eq!(
            saved,
            Some((
                "my_challenge".to_string(),
                CodeChallengeMethod::S256,
                "http://redirect.test".to_string(),
                user_id,
            ))
        );
    }
}
