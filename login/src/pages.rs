//! The flow pages (`/login`, `/registration`, `/recovery`, `/verification`, `/settings`) and
//! `/error`: each starts a Kratos flow or renders the one the browser came back with.

use crate::AppState;
use crate::kratos::{FlowFetch, FlowKind};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tera::Context;

const GENERIC_ERROR: &str = "Something went wrong. Please try again.";
const UNAVAILABLE: &str = "Sign-in is unavailable right now. Please try again in a moment.";

/// What a page can be opened with. All optional; a malformed query string counts as none.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct PageQuery {
    /// Kratos' flow id, when the browser is sent back to render a flow.
    flow: Option<String>,
    /// Hydra's login challenge, to start a login or registration flow for.
    login_challenge: Option<String>,
    return_to: Option<String>,
    /// Where bff sends the browser afterwards, for a page opened without a challenge.
    redirect_uri: Option<String>,
    /// Kratos' error id (`/error`).
    id: Option<String>,
}

pub(crate) fn page_query(query: Result<Query<PageQuery>, QueryRejection>) -> PageQuery {
    match query {
        Ok(Query(query)) => query,
        Err(error) => {
            tracing::info!(status = %error.status(), "ignoring a malformed query string");
            PageQuery::default()
        }
    }
}

pub(crate) async fn login_page(
    state: State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    flow_page(state.0, FlowKind::Login, &headers, page_query(query)).await
}

pub(crate) async fn registration_page(
    state: State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    flow_page(state.0, FlowKind::Registration, &headers, page_query(query)).await
}

pub(crate) async fn recovery_page(
    state: State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    flow_page(state.0, FlowKind::Recovery, &headers, page_query(query)).await
}

pub(crate) async fn verification_page(
    state: State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    flow_page(state.0, FlowKind::Verification, &headers, page_query(query)).await
}

pub(crate) async fn settings_page(
    state: State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    flow_page(state.0, FlowKind::Settings, &headers, page_query(query)).await
}

async fn flow_page(
    state: AppState,
    kind: FlowKind,
    headers: &HeaderMap,
    query: PageQuery,
) -> Response {
    let Some(id) = query.flow.as_deref() else {
        return start_flow(&state, kind, &query);
    };
    let cookie = cookie_header(headers);
    match state.kratos.fetch_flow(kind, id, cookie.as_ref()).await {
        Ok(FlowFetch::Found(flow)) => {
            let mut ctx = Context::new();
            insert_navigation(&mut ctx, &flow);
            ctx.insert("flow", &flow);
            ctx.insert("bff_url", &state.config.bff_url);
            state.renderer.page(StatusCode::OK, kind.template(), ctx)
        }
        Ok(FlowFetch::Gone) => start_flow(&state, kind, &query),
        Ok(FlowFetch::SignInRequired) if kind == FlowKind::Settings => {
            Redirect::to("/login").into_response()
        }
        Ok(FlowFetch::SignInRequired) => start_flow(&state, kind, &query),
        Err(error) => {
            tracing::error!(%error, "could not fetch a {} flow", kind.segment());
            state.error_page(StatusCode::BAD_GATEWAY, UNAVAILABLE)
        }
    }
}

/// Where a page opened without a flow goes: into Kratos to start one, or (for the pages that
/// only make sense inside a Hydra login) back to bff to begin at the beginning.
fn start_flow(state: &AppState, kind: FlowKind, query: &PageQuery) -> Response {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    if kind.needs_challenge() {
        match query.login_challenge.as_deref() {
            Some(challenge) => params.append_pair("login_challenge", challenge),
            None => return back_to_bff(state, query),
        };
    }
    if let Some(return_to) = query.return_to.as_deref() {
        params.append_pair("return_to", return_to);
    }
    let params = params.finish();
    let mut location = format!("/self-service/{}/browser", kind.segment());
    if !params.is_empty() {
        location.push('?');
        location.push_str(&params);
    }
    Redirect::to(&location).into_response()
}

/// bff's `/login` needs a `redirect_uri`. Without one there is nowhere to send the user, and
/// guessing (login's own origin) would loop through bff forever for a signed-in user.
fn back_to_bff(state: &AppState, query: &PageQuery) -> Response {
    let target = query
        .redirect_uri
        .as_ref()
        .or(state.config.default_redirect_uri.as_ref());
    let Some(target) = target else {
        tracing::warn!("a page was opened without a challenge, a flow or a redirect target");
        return state.error_page(
            StatusCode::BAD_REQUEST,
            "There is nothing to sign in to here. Open the sign-in page from the application.",
        );
    };
    let redirect_uri: String = url::form_urlencoded::byte_serialize(target.as_bytes()).collect();
    Redirect::to(&format!(
        "{}/login?redirect_uri={redirect_uri}",
        state.config.bff_url
    ))
    .into_response()
}

/// Links between the pages that keep the Hydra challenge (or `return_to`) the flow was started with.
fn insert_navigation(ctx: &mut Context, flow: &Value) {
    let carried = |key: &str| {
        flow.get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    };
    let link = |path: &str| {
        let query = match (carried("oauth2_login_challenge"), carried("return_to")) {
            (Some(challenge), _) => ("login_challenge", challenge),
            (None, Some(return_to)) => ("return_to", return_to),
            (None, None) => return path.to_string(),
        };
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair(query.0, query.1)
            .finish();
        format!("{path}?{query}")
    };
    ctx.insert("login_url", &link("/login"));
    ctx.insert("registration_url", &link("/registration"));
    ctx.insert("recovery_url", &link("/recovery"));
}

/// Kratos' own wording can carry what the caller put in the link (`return_to` and the like), and
/// the link works for anyone, so only a fixed text per status is shown.
fn error_text(code: Option<u64>) -> &'static str {
    match code {
        Some(400) => "The request was not valid. Please start again.",
        Some(401 | 403) => "You are not allowed to do that.",
        Some(404) => "That page was not found.",
        _ => GENERIC_ERROR,
    }
}

pub(crate) async fn error_page(
    State(state): State<AppState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let query = page_query(query);
    let Some(id) = query.id.as_deref() else {
        return state.error_page(StatusCode::OK, GENERIC_ERROR);
    };
    match state.kratos.fetch_error(id).await {
        Ok(Some(error)) => {
            let code = error.pointer("/error/code").and_then(Value::as_u64);
            state.error_page(StatusCode::OK, error_text(code))
        }
        Ok(None) => state.error_page(StatusCode::OK, GENERIC_ERROR),
        Err(error) => {
            tracing::error!(%error, "could not fetch a Kratos error");
            state.error_page(StatusCode::BAD_GATEWAY, UNAVAILABLE)
        }
    }
}

impl AppState {
    pub(crate) fn error_page(&self, status: StatusCode, message: &str) -> Response {
        let mut ctx = Context::new();
        ctx.insert("error", &json!({"message": message}));
        self.renderer.page(status, "error.html", ctx)
    }

    /// What a throttled login submission gets: the same page whoever the identifier is.
    pub(crate) fn throttled_page(&self, wait: Duration) -> Response {
        let seconds = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
        let mut response = self.error_page(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Too many sign-in attempts. Try again in {seconds} seconds."),
        );
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

/// The browser's cookies as one header (HTTP/2 clients send one per cookie).
pub(crate) fn cookie_header(headers: &HeaderMap) -> Option<HeaderValue> {
    let cookies: Vec<&str> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    if cookies.is_empty() {
        return None;
    }
    HeaderValue::from_str(&cookies.join("; ")).ok()
}
