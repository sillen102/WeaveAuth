use common_macros::ErrorResponses;
use thiserror::Error;

#[derive(Debug, Error, ErrorResponses)]
enum Broken {
    #[error("cause: {0}")]
    #[error_response(axum::http::StatusCode::BAD_GATEWAY)]
    Tuple(String),
}

fn main() {}
