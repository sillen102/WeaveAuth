use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use weaveauth::config::Config;
use weaveauth::server::app_start;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // This process holds the signing keys and client secrets. Non-dumpable
    // hides its `/proc/<pid>/environ` and memory even from processes running
    // as the same user: bff, login, and any plugin configured as this uid.
    // First, so the window in which they're readable is as short as it gets.
    #[cfg(target_os = "linux")]
    let dumpable =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);

    let config = Config::load()?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    #[cfg(target_os = "linux")]
    if let Err(error) = dumpable {
        tracing::warn!(%error, "could not mark this process non-dumpable");
    }

    app_start(&config).await
}
