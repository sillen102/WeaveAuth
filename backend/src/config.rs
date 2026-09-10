use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub claim_enrichment_url: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let port = env::var("WA_PORT")
            .unwrap_or_else(|_| "1983".into())
            .parse()?;

        let claim_enrichment_url = env::var("WA_CLAIM_ENRICHMENT_URL").ok();

        Ok(Self {
            port,
            claim_enrichment_url,
        })
    }
}
