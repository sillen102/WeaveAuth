use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub cors_origins: Vec<String>,
    pub claim_enrichment_url: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let port = env::var("PORT")
            .unwrap_or_else(|_| "1983".into())
            .parse()?;

        let cors_origins = env::var("CORS_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:1984".into())
            .split(',')
            .map(str::trim)
            .map(String::from)
            .collect();

        let claim_enrichment_url = env::var("CLAIM_ENRICHMENT_URL").ok();

        Ok(Self {
            port,
            cors_origins,
            claim_enrichment_url,
        })
    }
}
