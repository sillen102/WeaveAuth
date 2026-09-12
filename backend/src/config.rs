use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
}

impl Config {
    pub fn load() -> Result<Self, anyhow::Error> {
        let port = env::var("WA_PORT")
            .unwrap_or_else(|_| "1983".into())
            .parse()?;

        Ok(Self {
            port,
        })
    }
}
