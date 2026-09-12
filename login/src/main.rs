use weaveauth_login::{app, Config};

#[tokio::main]
async fn main() {
    let config = Config::load();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port))
        .await
        .unwrap();
    axum::serve(listener, app(config)).await.unwrap();
}