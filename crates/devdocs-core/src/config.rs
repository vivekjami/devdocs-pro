use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub api_key: String,
    pub sampling_rate: f64,
    pub max_body_size: usize,
    pub excluded_paths: Vec<String>,
    pub gemini_api_key: Option<String>,
    pub enable_pii_filtering: bool,
    pub server_url: String,
    pub body_capture: BodyCaptureConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyCaptureConfig {
    pub enabled: bool,
    pub max_size: usize,
    pub max_memory_size: usize,
    pub temp_dir: PathBuf,
    pub enable_compression_detection: bool,
    pub enable_decompression: bool,
    pub capture_request_bodies: bool,
    pub capture_response_bodies: bool,
}

impl Default for BodyCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: 10 * 1024 * 1024,   // 10MB
            max_memory_size: 1024 * 1024, // 1MB
            temp_dir: std::env::temp_dir().join("devdocs-bodies"),
            enable_compression_detection: true,
            enable_decompression: true,
            capture_request_bodies: true,
            capture_response_bodies: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_key: env::var("DEVDOCS_API_KEY").unwrap_or_default(),
            sampling_rate: 0.1,              // 10% sampling by default
            max_body_size: 10 * 1024 * 1024, // 10MB
            excluded_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/favicon.ico".to_string(),
            ],
            gemini_api_key: env::var("GEMINI_API_KEY").ok(),
            enable_pii_filtering: true,
            server_url: "https://api.devdocs.pro".to_string(),
            body_capture: BodyCaptureConfig::default(),
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
            config.body_capture.max_size = config.max_body_size;
        }

        if let Ok(temp_dir) = env::var("DEVDOCS_TEMP_DIR") {
            config.body_capture.temp_dir = PathBuf::from(temp_dir);
        }

        if let Ok(capture_bodies) = env::var("DEVDOCS_CAPTURE_BODIES") {
            config.body_capture.enabled = capture_bodies.parse().unwrap_or(true);
        }

        Ok(config)
    }

    pub fn should_sample(&self) -> bool {
        rand::random::<f64>() < self.sampling_rate
    }
}
