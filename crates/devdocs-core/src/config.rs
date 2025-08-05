use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub api_key: String,
    pub sampling_rate: f64,
    pub max_body_size: usize,
    pub excluded_paths: Vec<String>,
    pub gemini_api_key: Option<String>,
    pub enable_pii_filtering: bool,
    pub server_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_key: env::var("DEVDOCS_API_KEY").unwrap_or_default(),
            sampling_rate: 0.1, // 10% sampling by default
            max_body_size: 10 * 1024 * 1024, // 10MB
            excluded_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/favicon.ico".to_string(),
            ],
            gemini_api_key: env::var("GEMINI_API_KEY").ok(),
            enable_pii_filtering: true,
            server_url: "https://api.devdocs.pro".to_string(),
        }
    }
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut config = Self::default();
        
        if let Ok(rate) = env::var("DEVDOCS_SAMPLING_RATE") {
            config.sampling_rate = rate.parse()?;
        }
        
        if let Ok(size) = env::var("DEVDOCS_MAX_BODY_SIZE") {
            config.max_body_size = size.parse()?;
        }
        
        Ok(config)
    }
    
    pub fn should_sample(&self) -> bool {
        rand::random::<f64>() < self.sampling_rate
    }
}
