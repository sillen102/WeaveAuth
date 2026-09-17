//! `/docs` and `/openapi.json` are unauthenticated descriptions of the auth
//! surface on the internet-facing service, so they're opt-in per deployment.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use std::net::SocketAddr;
use tower::ServiceExt;
use weaveauth_bff::config::Config;
use weaveauth_bff::server::app;

const DOCS_PATHS: [&str; 3] = ["/docs", "/docs/scalar.js", "/openapi.json"];

fn test_config(docs_enabled: bool) -> Config {
    Config {
        port: 8080,
        bff_url: "http://bff.test".into(),
        backend_url: "http://backend.test".into(),
        session_cookie_name: "wa_session".into(),
        routes: vec![],
        trusted_origins: vec!["http://login.test".into()],
        rate_limit_max_attempts: 1000,
        rate_limit_window_secs: 60,
        expiry_sweep_interval_secs: 60,
        docs_enabled,
    }
}

fn get(path: &str) -> anyhow::Result<Request<Body>> {
    let mut req = Request::get(path).body(Body::empty())?;
    req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    Ok(req)
}

#[tokio::test]
async fn does_not_serve_docs_by_default() -> anyhow::Result<()> {
    assert!(!test_config(false).docs_enabled);

    for path in DOCS_PATHS {
        let app = app(test_config(false))?;
        let resp = app.oneshot(get(path)?).await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path} was served with docs disabled");
    }
    Ok(())
}

#[tokio::test]
async fn serves_docs_when_enabled() -> anyhow::Result<()> {
    for path in DOCS_PATHS {
        let app = app(test_config(true))?;
        let resp = app.oneshot(get(path)?).await?;
        assert_eq!(resp.status(), StatusCode::OK, "{path} was not served with docs enabled");
    }
    Ok(())
}

// Toggling docs must not change the API itself -- `/register` stays mounted
// (and documented) either way.
#[tokio::test]
async fn the_register_route_exists_regardless_of_the_docs_flag() -> anyhow::Result<()> {
    for docs_enabled in [false, true] {
        let app = app(test_config(docs_enabled))?;
        let resp = app.oneshot(get("/register")?).await?;
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "/register should exist (POST-only) with docs_enabled={docs_enabled}"
        );
    }
    Ok(())
}
