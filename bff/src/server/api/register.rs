use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::{Deserialize, Serialize};

use crate::server::AppState;

#[derive(Deserialize)]
pub(crate) struct RegisterRequest {
    identifier: String,
    password: String,
    /// Where to send the browser back to once registration is done, success or
    /// not -- supplied by the login page's own form, not user-typed input.
    next: String,
}

#[derive(Serialize)]
struct BackendRegisterRequest<'a> {
    identifier: &'a str,
    password: &'a str,
}

/// Forwards registration to backend's `/register`, then bounces the browser
/// back to `next` (the login page) -- `?error=1` appended when it failed, so
/// the static registration page can show a message without any JS fetch/CORS
/// dance.
pub(crate) async fn start_register(
    State(state): State<AppState>,
    Form(req): Form<RegisterRequest>,
) -> Result<Response, StatusCode> {
    let resp = state
        .http_client
        .post(format!("{}/register", state.config.backend_url))
        .json(&BackendRegisterRequest {
            identifier: &req.identifier,
            password: &req.password,
        })
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let location = if resp.status().is_success() {
        req.next
    } else if resp.status().is_client_error() {
        let sep = if req.next.contains('?') { '&' } else { '?' };
        format!("{}{sep}error=1", req.next)
    } else {
        return Err(StatusCode::BAD_GATEWAY);
    };

    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}
