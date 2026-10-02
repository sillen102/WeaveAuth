//! Drop-in replacements for axum's `Json`, `Form`, `Query` and `Path` whose
//! rejections are the same JSON `ErrorResponse` every other error uses,
//! instead of axum's plain-text message.

use aide::OperationInput;
use aide::generate::GenContext;
use aide::openapi::{
    Example, MediaType, Operation, ReferenceOr, Response as OpenApiResponse, SchemaObject,
    StatusCode as OpenApiStatusCode,
};
use axum::Json;
use axum::extract::rejection::{FormRejection, JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Form, FromRequest, FromRequestParts, Path, Query, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;

use crate::model::error_response::ErrorResponse;

/// The response for a rejected extractor. Client input problems keep axum's
/// status (400, 415, 422, ...) with a fixed `InvalidRequest` body; a rejection
/// that is the server's own fault (a route missing its path params) is a
/// generic 500, not an "invalid request".
#[derive(Debug)]
pub struct InvalidRequest {
    status: StatusCode,
}

impl InvalidRequest {
    /// Logs the extractor and status only: serde's message can echo the
    /// offending value (a password sent as the wrong type, say).
    fn new(extractor: &'static str, status: StatusCode) -> Self {
        if status.is_server_error() {
            tracing::error!(extractor, %status, "extractor rejected the request through no fault of the client");
        } else {
            tracing::info!(extractor, %status, "request input rejected");
        }
        Self { status }
    }
}

impl IntoResponse for InvalidRequest {
    fn into_response(self) -> Response {
        let body = if self.status.is_server_error() {
            ErrorResponse::new("internal server error", "InternalError")
        } else {
            ErrorResponse::new("invalid request", "InvalidRequest")
        };
        (self.status, Json(body)).into_response()
    }
}

#[derive(Debug)]
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = InvalidRequest;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|err| InvalidRequest::new("json", err.status()))
    }
}

#[derive(Debug)]
pub struct ApiForm<T>(pub T);

impl<T, S> FromRequest<S> for ApiForm<T>
where
    S: Send + Sync,
    Form<T>: FromRequest<S, Rejection = FormRejection>,
{
    type Rejection = InvalidRequest;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        Form::<T>::from_request(req, state)
            .await
            .map(|Form(value)| Self(value))
            .map_err(|err| InvalidRequest::new("form", err.status()))
    }
}

#[derive(Debug)]
pub struct ApiQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = InvalidRequest;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|err: QueryRejection| InvalidRequest::new("query", err.status()))
    }
}

#[derive(Debug)]
pub struct ApiPath<T>(pub T);

impl<T, S> FromRequestParts<S> for ApiPath<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = InvalidRequest;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|err: PathRejection| InvalidRequest::new("path", err.status()))
    }
}

const INVALID_REQUEST_DESCRIPTION: &str = "invalid request";

/// The `InvalidRequest` media type: the `ErrorResponse` schema plus one example.
fn invalid_request_media(ctx: &mut GenContext) -> MediaType {
    let example = Example {
        summary: Some(INVALID_REQUEST_DESCRIPTION.to_string()),
        value: serde_json::to_value(ErrorResponse::new(
            INVALID_REQUEST_DESCRIPTION,
            "InvalidRequest",
        ))
        .ok(),
        ..Default::default()
    };
    let mut media = MediaType {
        schema: Some(SchemaObject {
            json_schema: ctx.schema.subschema_for::<ErrorResponse>(),
            example: None,
            external_docs: None,
        }),
        ..Default::default()
    };
    media
        .examples
        .insert("InvalidRequest".to_string(), ReferenceOr::Item(example));
    media
}

/// The responses to add for `statuses`. aide refuses to overwrite a status the
/// endpoint already documents (its own error enum's 400, say) and drops the
/// new response, so for those the `InvalidRequest` example and description are
/// merged into the existing response in place and nothing is returned for them.
fn rejection_responses(
    ctx: &mut GenContext,
    operation: &mut Operation,
    statuses: &[StatusCode],
) -> Vec<(Option<OpenApiStatusCode>, OpenApiResponse)> {
    let mut added = Vec::new();
    for status in statuses {
        let key = OpenApiStatusCode::Code(status.as_u16());
        let existing = operation
            .responses
            .as_mut()
            .and_then(|responses| responses.responses.get_mut(&key));
        match existing {
            Some(ReferenceOr::Item(response)) => {
                if !response.description.contains(INVALID_REQUEST_DESCRIPTION) {
                    response.description =
                        format!("{}; {INVALID_REQUEST_DESCRIPTION}", response.description);
                }
                let media = invalid_request_media(ctx);
                let slot = response
                    .content
                    .entry("application/json".to_string())
                    .or_insert_with(|| MediaType {
                        schema: media.schema.clone(),
                        ..Default::default()
                    });
                slot.examples.extend(media.examples);
            }
            // A `$ref` response can't be edited in place; leave it alone.
            Some(ReferenceOr::Reference { .. }) => {}
            None => {
                let mut response = OpenApiResponse {
                    description: INVALID_REQUEST_DESCRIPTION.to_string(),
                    ..Default::default()
                };
                response
                    .content
                    .insert("application/json".to_string(), invalid_request_media(ctx));
                added.push((Some(key), response));
            }
        }
    }
    added
}

const BODY_REJECTIONS: [StatusCode; 3] = [
    StatusCode::BAD_REQUEST,
    StatusCode::UNSUPPORTED_MEDIA_TYPE,
    StatusCode::UNPROCESSABLE_ENTITY,
];

impl<T: JsonSchema> OperationInput for ApiJson<T> {
    fn operation_input(ctx: &mut GenContext, operation: &mut Operation) {
        Json::<T>::operation_input(ctx, operation);
    }

    fn inferred_early_responses(
        ctx: &mut GenContext,
        operation: &mut Operation,
    ) -> Vec<(Option<OpenApiStatusCode>, OpenApiResponse)> {
        rejection_responses(ctx, operation, &BODY_REJECTIONS)
    }
}

impl<T: JsonSchema> OperationInput for ApiForm<T> {
    fn operation_input(ctx: &mut GenContext, operation: &mut Operation) {
        Form::<T>::operation_input(ctx, operation);
    }

    fn inferred_early_responses(
        ctx: &mut GenContext,
        operation: &mut Operation,
    ) -> Vec<(Option<OpenApiStatusCode>, OpenApiResponse)> {
        rejection_responses(ctx, operation, &BODY_REJECTIONS)
    }
}

impl<T: JsonSchema> OperationInput for ApiQuery<T> {
    fn operation_input(ctx: &mut GenContext, operation: &mut Operation) {
        Query::<T>::operation_input(ctx, operation);
    }

    fn inferred_early_responses(
        ctx: &mut GenContext,
        operation: &mut Operation,
    ) -> Vec<(Option<OpenApiStatusCode>, OpenApiResponse)> {
        rejection_responses(ctx, operation, &[StatusCode::BAD_REQUEST])
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiForm, ApiJson, ApiPath, ApiQuery};
    use axum::body::Body;
    use axum::extract::{FromRequest, FromRequestParts};
    use axum::http::{Request, StatusCode, header};
    use axum::response::IntoResponse;
    use serde::Deserialize;
    use serde_json::Value;

    #[derive(Debug, Deserialize, schemars::JsonSchema)]
    struct Payload {
        name: String,
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).expect("rejection body is json")
    }

    async fn assert_rejected(rejection: impl IntoResponse, status: StatusCode) {
        let resp = rejection.into_response();
        assert_eq!(resp.status(), status);
        let body = body_json(resp).await;
        assert_eq!(body["details"], "invalid request");
        assert_eq!(body["reason"], "InvalidRequest");
        assert!(body["timestamp"].is_string());
    }

    fn post(content_type: &str, body: &'static str) -> Request<Body> {
        Request::post("/")
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn json_accepts_a_valid_body() {
        let ApiJson(p) =
            ApiJson::<Payload>::from_request(post("application/json", r#"{"name":"a"}"#), &())
                .await
                .unwrap();
        assert_eq!(p.name, "a");
    }

    #[tokio::test]
    async fn json_rejects_a_missing_field_as_json() {
        let err = ApiJson::<Payload>::from_request(post("application/json", "{}"), &())
            .await
            .unwrap_err();
        assert_rejected(err, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn json_rejects_a_wrong_content_type_as_json() {
        let err = ApiJson::<Payload>::from_request(post("text/plain", r#"{"name":"a"}"#), &())
            .await
            .unwrap_err();
        assert_rejected(err, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;
    }

    #[tokio::test]
    async fn form_accepts_a_valid_body() {
        let ApiForm(p) = ApiForm::<Payload>::from_request(
            post("application/x-www-form-urlencoded", "name=a"),
            &(),
        )
        .await
        .unwrap();
        assert_eq!(p.name, "a");
    }

    #[tokio::test]
    async fn form_rejects_a_missing_field_as_json() {
        let err = ApiForm::<Payload>::from_request(
            post("application/x-www-form-urlencoded", "other=a"),
            &(),
        )
        .await
        .unwrap_err();
        assert_rejected(err, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn query_accepts_a_valid_query() {
        let (mut parts, _) = Request::get("/?name=a").body(()).unwrap().into_parts();
        let ApiQuery(p) = ApiQuery::<Payload>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(p.name, "a");
    }

    #[tokio::test]
    async fn query_rejects_a_missing_field_as_json() {
        let (mut parts, _) = Request::get("/").body(()).unwrap().into_parts();
        let err = ApiQuery::<Payload>::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert_rejected(err, StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn path_without_route_params_is_a_server_fault_not_an_invalid_request() {
        // No matched route, so axum has no path params to extract: a
        // misconfigured route, not bad client input.
        let (mut parts, _) = Request::get("/").body(()).unwrap().into_parts();
        let err = ApiPath::<String>::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();

        let resp = err.into_response();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        assert_eq!(body["reason"], "InternalError");
        assert_eq!(body["details"], "internal server error");
    }

    fn documented_statuses<T: aide::OperationInput>() -> Vec<u16> {
        let mut op = aide::openapi::Operation::default();
        let responses = aide::generate::in_context(|ctx| T::inferred_early_responses(ctx, &mut op));
        responses
            .into_iter()
            .map(|(status, response)| {
                assert_eq!(response.description, "invalid request");
                assert!(response.content.contains_key("application/json"));
                match status {
                    Some(aide::openapi::StatusCode::Code(code)) => Some(code),
                    _ => None,
                }
                .expect("a concrete status code")
            })
            .collect()
    }

    fn documented_400(op: &aide::openapi::Operation) -> &aide::openapi::Response {
        let item = op
            .responses
            .as_ref()
            .and_then(|r| r.responses.get(&aide::openapi::StatusCode::Code(400)))
            .and_then(|r| r.as_item());
        item.expect("an inline 400 response")
    }

    #[test]
    fn a_status_the_endpoint_already_documents_gains_the_invalid_request_example() {
        let mut op = aide::openapi::Operation::default();
        let own = aide::openapi::Response {
            description: "bad redirect".to_string(),
            ..Default::default()
        };
        op.responses = Some(aide::openapi::Responses::default());
        if let Some(responses) = op.responses.as_mut() {
            responses.responses.insert(
                aide::openapi::StatusCode::Code(400),
                aide::openapi::ReferenceOr::Item(own),
            );
        }

        let returned = aide::generate::in_context(|ctx| {
            <ApiQuery<Payload> as aide::OperationInput>::inferred_early_responses(ctx, &mut op)
        });

        // Already documented: merged in place, not returned (aide would drop it).
        assert!(returned.is_empty());
        let merged = documented_400(&op);
        assert_eq!(merged.description, "bad redirect; invalid request");
        let media = merged
            .content
            .get("application/json")
            .expect("json content");
        assert!(media.examples.contains_key("InvalidRequest"));
    }

    #[test]
    fn merging_into_an_existing_status_is_idempotent() {
        let mut op = aide::openapi::Operation::default();
        let mut responses = aide::openapi::Responses::default();
        responses.responses.insert(
            aide::openapi::StatusCode::Code(400),
            aide::openapi::ReferenceOr::Item(aide::openapi::Response {
                description: "bad redirect".to_string(),
                ..Default::default()
            }),
        );
        op.responses = Some(responses);

        for _ in 0..2 {
            aide::generate::in_context(|ctx| {
                <ApiQuery<Payload> as aide::OperationInput>::inferred_early_responses(ctx, &mut op)
            });
        }

        let merged = documented_400(&op);
        assert_eq!(merged.description, "bad redirect; invalid request");
    }

    #[test]
    fn the_rejection_responses_are_documented_in_the_openapi_spec() {
        assert_eq!(documented_statuses::<ApiJson<Payload>>(), [400, 415, 422]);
        assert_eq!(documented_statuses::<ApiForm<Payload>>(), [400, 415, 422]);
        assert_eq!(documented_statuses::<ApiQuery<Payload>>(), [400]);
    }
}
