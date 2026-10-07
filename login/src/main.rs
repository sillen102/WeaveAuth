use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use weaveauth_login::{Config, serve};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    serve(Config::load()?).await
}
