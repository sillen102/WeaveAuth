use axum::Router;
use tower_http::services::ServeDir;

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("WA_LOGIN_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let files = ServeDir::new(STATIC_DIR);
    let router =
        Router::new().nest_service("/static", files.clone()).fallback_service(files);
    let listener =
        tokio::net::TcpListener::bind(("0.0.0.0", port)).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}