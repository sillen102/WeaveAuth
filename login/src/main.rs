use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use weaveauth_login::{app, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::load()?;
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port))
        .await?;
    axum::serve(listener, app(config)).await?;
    Ok(())
}
