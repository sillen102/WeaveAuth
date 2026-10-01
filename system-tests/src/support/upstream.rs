//! A stub upstream service for the proxy flow -- echoes back whatever
//! `Authorization` header it received (and whether a `Cookie` header leaked
//! through, which it never should have) so a test can assert on exactly
//! what bff forwarded, without needing a real protected API behind it.

use axum::extract::Path;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::Router;

pub async fn start() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new().route(
        "/whoami/{id}",
        get(|Path(id): Path<String>, headers: HeaderMap| async move {
            let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let has_cookie = headers.contains_key("cookie");
            format!("id={id} auth={auth} cookie={has_cookie}")
        }),
    );
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((format!("http://{addr}"), handle))
}
