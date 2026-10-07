//! Hydra's logout and consent challenges: the two places Hydra hands the browser to login and
//! expects it back from.

use crate::AppState;
use crate::hydra::ConsentRequest;
use crate::pages::cookie_header;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

/// The only scopes `/consent` grants.
const ALLOWED_SCOPES: [&str; 2] = ["openid", "offline_access"];

const UNAVAILABLE: &str = "Sign-out is unavailable right now. Please try again in a moment.";

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ChallengeQuery {
    logout_challenge: Option<String>,
    consent_challenge: Option<String>,
}

fn challenge_query(query: Result<Query<ChallengeQuery>, QueryRejection>) -> ChallengeQuery {
    query.map(|Query(query)| query).unwrap_or_default()
}

/// Ends the Kratos session, then lets Hydra finish its own logout (which calls bff's back-channel
/// logout). Only logouts the app started are accepted: a bare link to Hydra's logout endpoint
/// would otherwise sign anyone out.
pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<ChallengeQuery>, QueryRejection>,
) -> Response {
    let Some(challenge) = challenge_query(query).logout_challenge else {
        return state.error_page(StatusCode::BAD_REQUEST, "This sign-out link is not valid.");
    };
    match state.hydra.logout_request(&challenge).await {
        Ok(Some(request)) if request.rp_initiated => {}
        Ok(Some(_)) => {
            tracing::warn!("a logout request without an app behind it was not accepted");
            return state.error_page(
                StatusCode::BAD_REQUEST,
                "Sign out from the application you are signed in to.",
            );
        }
        Ok(None) => {
            return state.error_page(StatusCode::BAD_REQUEST, "This sign-out link has expired.");
        }
        Err(error) => {
            tracing::error!(%error, "could not look up a logout challenge");
            return state.error_page(StatusCode::BAD_GATEWAY, UNAVAILABLE);
        }
    }

    let cookies = end_kratos_session(&state, &headers).await;
    match state.hydra.accept_logout(&challenge).await {
        Ok(redirect_to) => with_cookies(Redirect::to(&redirect_to).into_response(), cookies),
        Err(error) => {
            tracing::error!(%error, "could not accept a logout challenge");
            // The Kratos session is already gone, so the browser must still drop its cookies.
            with_cookies(
                state.error_page(StatusCode::BAD_GATEWAY, UNAVAILABLE),
                cookies,
            )
        }
    }
}

fn with_cookies(mut response: Response, cookies: Vec<axum::http::HeaderValue>) -> Response {
    for cookie in cookies {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

/// The cookies Kratos clears when it ends the browser's session. A failure here doesn't stop the
/// Hydra logout: the app's session is what matters most, and the Kratos one expires on its own.
async fn end_kratos_session(state: &AppState, headers: &HeaderMap) -> Vec<axum::http::HeaderValue> {
    let cookie = cookie_header(headers);
    match state.kratos.end_session(cookie.as_ref()).await {
        Ok(cookies) => cookies.unwrap_or_default(),
        Err(error) => {
            tracing::warn!(%error, "could not end the Kratos session during logout");
            Vec::new()
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Ungrantable {
    #[error("not the configured client")]
    WrongClient,
    #[error("scope {0:?} is not allowed")]
    ScopeNotAllowed(String),
}

/// Grants the configured client the scopes it asked for, if they are within [`ALLOWED_SCOPES`],
/// and refuses everything else. Hydra sends the browser here for every authorization (the client's
/// `skip_consent` does not bypass it); this keeps that working without a consent screen.
pub(crate) async fn consent(
    State(state): State<AppState>,
    query: Result<Query<ChallengeQuery>, QueryRejection>,
) -> Response {
    let Some(challenge) = challenge_query(query).consent_challenge else {
        return state.error_page(StatusCode::BAD_REQUEST, "This link is not valid.");
    };
    let request = match state.hydra.consent_request(&challenge).await {
        Ok(Some(request)) => request,
        Ok(None) => return state.error_page(StatusCode::BAD_REQUEST, "This link has expired."),
        Err(error) => {
            tracing::error!(%error, "could not look up a consent challenge");
            return state.error_page(StatusCode::BAD_GATEWAY, "Sign-in is unavailable right now.");
        }
    };
    let result = match check_grantable(&request, &state.config.bff_client_id) {
        // Hydra only puts an audience in the access token when consent grants it.
        Ok(()) => {
            state
                .hydra
                .accept_consent(
                    &challenge,
                    &request.requested_scope,
                    &request.requested_access_token_audience,
                )
                .await
        }
        Err(refusal) => {
            tracing::warn!(client_id = %request.client.client_id, error = %refusal, "consent refused");
            state.hydra.reject_consent(&challenge).await
        }
    };
    match result {
        Ok(redirect_to) => Redirect::to(&redirect_to).into_response(),
        Err(error) => {
            tracing::error!(%error, "could not answer a consent challenge");
            state.error_page(StatusCode::BAD_GATEWAY, "Sign-in is unavailable right now.")
        }
    }
}

fn check_grantable(request: &ConsentRequest, client_id: &str) -> Result<(), Ungrantable> {
    if request.client.client_id != client_id {
        return Err(Ungrantable::WrongClient);
    }
    match request
        .requested_scope
        .iter()
        .find(|scope| !ALLOWED_SCOPES.contains(&scope.as_str()))
    {
        Some(scope) => Err(Ungrantable::ScopeNotAllowed(scope.clone())),
        None => Ok(()),
    }
}
