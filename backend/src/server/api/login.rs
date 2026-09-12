pub (crate) use controller::login;

mod controller {
    use aide::transform::TransformOperation;

    // OpenAPI documentation for this route.
    pub(crate) fn doc(op: TransformOperation) -> TransformOperation {
        op.tag("Auth")
            .id("login")
            .summary("Legacy login stub")
            .description("Deprecated placeholder; real authentication must happen before /oauth/authorize issues a code")
    }

    pub (crate) async fn login() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({ "authenticated": true }))
    }
}