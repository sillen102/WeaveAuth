// Standalone test double: serves a demo HTML page showing the Authorization
// header it received (401 if none was sent). Used to verify the bff's
// cookie -> Bearer token proxy swap actually reaches a downstream service.
//
// Run: cargo run
// Port: $PORT, default 10001.

use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::Html;
use axum::routing::any;
use axum::Router;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(10001);

    let app = Router::new().fallback(any(handler));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap();
    println!("downstream-service listening on :{port}");
    axum::serve(listener, app).await.unwrap();
}

async fn handler(req: Request) -> Result<Html<String>, StatusCode> {
    let authorization = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Downstream Service</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }}
    code {{ background: #f1f1f1; padding: 0.2rem 0.4rem; border-radius: 0.25rem; word-break: break-all; }}
  </style>
</head>
<body>
  <h1>Downstream Service</h1>
  <p>You reached this page through the bff's proxy. It received:</p>
  <p><code>Authorization: {authorization}</code></p>
</body>
</html>"#
    )))
}
