use weaveauth_hooks::cli::{self, Command};
use weaveauth_hooks::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Holds API keys and sees passwords: hide environ and memory from same-user processes, first.
    #[cfg(target_os = "linux")]
    let dumpable =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);

    let config = Config::load()?;

    cli::init_tracing();

    #[cfg(target_os = "linux")]
    if let Err(error) = dumpable {
        tracing::warn!(%error, "could not mark this process non-dumpable");
    }

    cli::run(Command::parse(std::env::args().skip(1))?, &config).await
}
