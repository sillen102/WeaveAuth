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
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

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

/// Decodes one base64url JWT segment (header or payload) and pretty-prints it
/// as JSON; falls back to the raw segment text if it isn't valid JSON.
fn decode_segment(segment: &str) -> String {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(segment) else {
        return "<not valid base64url>".to_string();
    };
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(json) => serde_json::to_string_pretty(&json).unwrap_or_default(),
        Err(_) => String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn handler(req: Request) -> Result<Html<String>, StatusCode> {
    let authorization = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = authorization
        .strip_prefix("Bearer ")
        .unwrap_or(authorization);
    let decoded = match token.split('.').collect::<Vec<_>>().as_slice() {
        [header, payload, ..] => format!(
            "<h2>Header</h2>\n<pre>{}</pre>\n<h2>Payload</h2>\n<pre>{}</pre>",
            decode_segment(header),
            decode_segment(payload)
        ),
        _ => "<p><em>Not a JWT (expected header.payload.signature)</em></p>".to_string(),
    };

    Ok(Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Downstream Service</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }}
    code {{ background: #f1f1f1; padding: 0.2rem 0.4rem; border-radius: 0.25rem; word-break: break-all; }}
    pre {{ background: #f1f1f1; padding: 0.75rem; border-radius: 0.25rem; overflow-x: auto; }}
  </style>
</head>
<body>
  <h1>Downstream Service</h1>
  <p>You reached this page through the bff's proxy. It received:</p>
  <p><code>Authorization: {authorization}</code></p>
  {decoded}
</body>
</html>"#
    )))
}
