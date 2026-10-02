use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use weaveauth_bff::config::Config;
use weaveauth_bff::server::app;

fn docs_config() -> Config {
    Config {
        port: 8080,
        bff_url: "http://bff.test".into(),
        backend_url: "http://backend.test".into(),
        session_cookie_name: "wa_session".into(),
        routes: vec![],
        trusted_origins: vec![],
        rate_limit_max_attempts: 1000,
        rate_limit_window_secs: 60,
        expiry_sweep_interval_secs: 60,
        docs_enabled: true,
    }
}

/// aide drops spec problems (a conflicting inferred response, say) unless a
/// handler is registered, so a docs regression would otherwise be silent.
#[tokio::test]
async fn openapi_generation_reports_no_errors_and_documents_invalid_request() -> anyhow::Result<()>
{
    aide::generate::on_error(|err| panic!("openapi generation error: {err}"));
    let app = app(docs_config()).unwrap();

    let resp = app
        .oneshot(
            Request::get("/openapi.json")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    0,
                ))))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let spec: serde_json::Value = serde_json::from_slice(&bytes)?;
    let examples = &spec["paths"]["/register"]["post"]["responses"]["400"]["content"]["application/json"]
        ["examples"];
    assert!(examples["InvalidRequest"].is_object(), "{spec}");
    Ok(())
}
