use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use weaveauth::config::Config;
use weaveauth::server::app_start;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load()?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    app_start(&config).await
}
