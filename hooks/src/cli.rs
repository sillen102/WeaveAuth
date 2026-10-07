//! The `weaveauth-hooks` command line: serve.

use crate::config::Config;

const USAGE: &str = "usage: weaveauth-hooks [serve]";

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Serve,
}

impl Command {
    /// `args` are the arguments after the program name.
    pub fn parse(mut args: impl Iterator<Item = String>) -> anyhow::Result<Self> {
        let command = match args.next().as_deref() {
            None | Some("serve") => Self::Serve,
            Some(_) => anyhow::bail!(USAGE),
        };
        anyhow::ensure!(args.next().is_none(), USAGE);
        Ok(command)
    }
}

pub async fn run(command: Command, config: &Config) -> anyhow::Result<()> {
    match command {
        Command::Serve => serve(config).await,
    }
}

/// Serves until the process ends.
async fn serve(config: &Config) -> anyhow::Result<()> {
    crate::server::app_start(config).await
}

/// Logs to stderr at `RUST_LOG`'s level, `info` when unset.
pub fn init_tracing() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // A second call (a test, say) keeps the subscriber that is already set.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> anyhow::Result<Command> {
        Command::parse(args.iter().map(|arg| arg.to_string()))
    }

    #[test]
    fn serving_is_the_default() {
        assert_eq!(parse(&[]).unwrap(), Command::Serve);
        assert_eq!(parse(&["serve"]).unwrap(), Command::Serve);
    }

    #[tokio::test]
    async fn serving_without_api_keys_is_refused_before_binding_anything() {
        assert!(run(Command::Serve, &Config::default()).await.is_err());
    }

    #[test]
    fn tracing_can_be_initialised_twice() {
        init_tracing();
        init_tracing();
    }

    #[test]
    fn anything_else_is_a_usage_error() {
        for args in [&["serve", "extra"][..], &["frobnicate"]] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }
}
