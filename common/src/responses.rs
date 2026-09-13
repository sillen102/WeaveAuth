use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct ErrorResponse {
    /// The timestamp when the error occurred.
    pub timestamp: DateTime<Utc>,
    /// A machine-readable error code or reason, typically the name of an enum variant.
    pub reason: String,
    /// A human-readable description of the error.
    pub details: String,
}

impl ErrorResponse {
    pub fn new(details: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            reason: reason.into(),
            details: details.into(),
        }
    }
}

mod axum_impls {
    use aide::OperationOutput;
    use aide::generate::GenContext;
    use aide::openapi::{MediaType, Operation, SchemaObject};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use http::header;
    use schemars::JsonSchema;
    use serde::Serialize;

    /// A response type for returning JSON data with status code 201.
    #[derive(Debug)]
    pub struct CreatedJson<T>(pub T);

    impl<T> IntoResponse for CreatedJson<T>
    where
        T: Serialize,
    {
        fn into_response(self) -> Response {
            (StatusCode::CREATED, axum::Json(self.0)).into_response()
        }
    }

    impl<T: JsonSchema> OperationOutput for CreatedJson<T> {
        type Inner = T;

        fn inferred_responses(
            ctx: &mut GenContext,
            _operation: &mut Operation,
        ) -> Vec<(Option<aide::openapi::StatusCode>, aide::openapi::Response)> {
            let json_schema = ctx.schema.subschema_for::<T>();
            vec![(
                Some(aide::openapi::StatusCode::Code(201)),
                aide::openapi::Response {
                    description: "Created".into(),
                    content: {
                        let mut map = aide::openapi::Response::default().content;
                        map.insert(
                            "application/json".into(),
                            MediaType {
                                schema: Some(SchemaObject {
                                    json_schema,
                                    example: None,
                                    external_docs: None,
                                }),
                                ..Default::default()
                            },
                        );
                        map
                    },
                    ..Default::default()
                },
            )]
        }
    }

    /// A response type for returning response with status code 204.
    pub struct NoContent;

    impl IntoResponse for NoContent {
        fn into_response(self) -> Response {
            StatusCode::NO_CONTENT.into_response()
        }
    }

    impl OperationOutput for NoContent {
        type Inner = ();

        fn inferred_responses(
            _ctx: &mut GenContext,
            _operation: &mut Operation,
        ) -> Vec<(Option<aide::openapi::StatusCode>, aide::openapi::Response)> {
            vec![(
                Some(aide::openapi::StatusCode::Code(204)),
                aide::openapi::Response {
                    description: "No Content".into(),
                    ..Default::default()
                },
            )]
        }
    }

    /// WebP image response body.
    pub struct WebpImage(pub Vec<u8>);

    impl IntoResponse for WebpImage {
        fn into_response(self) -> Response {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "image/webp")],
                self.0,
            )
                .into_response()
        }
    }

    impl OperationOutput for WebpImage {
        type Inner = Self;

        fn inferred_responses(
            _ctx: &mut GenContext,
            _operation: &mut Operation,
        ) -> Vec<(Option<aide::openapi::StatusCode>, aide::openapi::Response)> {
            vec![(
                Some(aide::openapi::StatusCode::Code(StatusCode::OK.as_u16())),
                aide::openapi::Response {
                    description: "WebP image".into(),
                    ..Default::default()
                },
            )]
        }
    }

    /// A response type for returning PDF binary data.
    #[derive(Debug)]
    pub struct PdfResponse {
        pub data: Vec<u8>,
    }

    impl IntoResponse for PdfResponse {
        fn into_response(self) -> Response {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/pdf")],
                self.data,
            )
                .into_response()
        }
    }

    impl OperationOutput for PdfResponse {
        type Inner = Self;

        fn inferred_responses(
            _ctx: &mut GenContext,
            _operation: &mut Operation,
        ) -> Vec<(Option<aide::openapi::StatusCode>, aide::openapi::Response)> {
            vec![(
                Some(aide::openapi::StatusCode::Code(StatusCode::OK.as_u16())),
                aide::openapi::Response {
                    description: "PDF file".into(),
                    ..Default::default()
                },
            )]
        }
    }
}

pub use axum_impls::*;
