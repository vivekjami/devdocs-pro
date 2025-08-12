use crate::security::MasterSecurityConfig;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub api_key: String,
    pub sampling_rate: f64,
    pub max_body_size: Option<usize>,
    pub excluded_paths: Vec<String>,
    pub gemini_api_key: Option<String>,
    pub enable_pii_filtering: bool,
    pub server_url: String,
    pub body_capture: BodyCaptureConfig,
    /// Comprehensive security configuration
    pub security: MasterSecurityConfig,
    /// AI analysis configuration
    pub enable_ai_analysis: bool,
    pub min_samples_for_inference: Option<usize>,
    /// API metadata
    pub api_title: Option<String>,
    pub api_version: Option<String>,
    pub api_description: Option<String>,
    pub base_url: Option<String>,
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
            sampling_rate: 0.1,                    // 10% sampling by default
            max_body_size: Some(10 * 1024 * 1024), // 10MB
            excluded_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/favicon.ico".to_string(),
            ],
            gemini_api_key: env::var("GEMINI_API_KEY").ok(),
            enable_pii_filtering: true,
            server_url: "https://api.devdocs.pro".to_string(),
            body_capture: BodyCaptureConfig::default(),
            security: MasterSecurityConfig::default(),
            enable_ai_analysis: true,
            min_samples_for_inference: Some(5),
            api_title: None,
            api_version: None,
            api_description: None,
            base_url: None,
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
            let parsed_size = size.parse()?;
            config.max_body_size = Some(parsed_size);
            config.body_capture.max_size = parsed_size;
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

    pub fn is_path_excluded(&self, path: &str) -> bool {
        self.excluded_paths
            .iter()
            .any(|excluded| path.starts_with(excluded))
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.sampling_rate) {
            return Err("Sampling rate must be between 0.0 and 1.0".to_string());
        }

        if let Some(size) = self.max_body_size {
            if size == 0 {
                return Err("Max body size must be greater than 0".to_string());
            }
        }

        if self.server_url.is_empty() {
            return Err("Server URL cannot be empty".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.sampling_rate, 0.1);
        assert_eq!(config.max_body_size, Some(10 * 1024 * 1024));
        assert!(!config.excluded_paths.is_empty());
        assert_eq!(config.enable_pii_filtering, true);
        assert_eq!(config.server_url, "https://api.devdocs.pro");
    }

    #[test]
    fn test_body_capture_config_default() {
        let config = BodyCaptureConfig::default();
        assert_eq!(config.enabled, true);
        assert_eq!(config.max_size, 10 * 1024 * 1024);
        assert_eq!(config.max_memory_size, 1024 * 1024);
        assert_eq!(config.enable_compression_detection, true);
        assert_eq!(config.enable_decompression, true);
        assert_eq!(config.capture_request_bodies, true);
        assert_eq!(config.capture_response_bodies, true);
    }

    #[test]
    fn test_config_from_env_default() {
        // Clear environment variables first
        env::remove_var("DEVDOCS_API_KEY");
        env::remove_var("DEVDOCS_SAMPLING_RATE");
        env::remove_var("DEVDOCS_MAX_BODY_SIZE");
        env::remove_var("DEVDOCS_TEMP_DIR");
        env::remove_var("DEVDOCS_CAPTURE_BODIES");

        let config = Config::from_env().unwrap();
        assert_eq!(config.sampling_rate, 0.1);
        assert_eq!(config.max_body_size, Some(10 * 1024 * 1024));
        assert!(config.body_capture.enabled);
    }

    #[test]
    fn test_config_from_env_with_variables() {
        env::set_var("DEVDOCS_SAMPLING_RATE", "0.5");
        env::set_var("DEVDOCS_MAX_BODY_SIZE", "5242880"); // 5MB
        env::set_var("DEVDOCS_CAPTURE_BODIES", "false");

        let config = Config::from_env().unwrap();
        assert_eq!(config.sampling_rate, 0.5);
        assert_eq!(config.max_body_size, Some(5242880));
        assert_eq!(config.body_capture.enabled, false);

        // Clean up
        env::remove_var("DEVDOCS_SAMPLING_RATE");
        env::remove_var("DEVDOCS_MAX_BODY_SIZE");
        env::remove_var("DEVDOCS_CAPTURE_BODIES");
    }

    #[test]
    fn test_config_from_env_invalid_sampling_rate() {
        env::set_var("DEVDOCS_SAMPLING_RATE", "invalid");
        let result = Config::from_env();
        assert!(result.is_err());
        env::remove_var("DEVDOCS_SAMPLING_RATE");
    }

    #[test]
    fn test_config_from_env_invalid_body_size() {
        env::set_var("DEVDOCS_MAX_BODY_SIZE", "invalid");
        let result = Config::from_env();
        assert!(result.is_err());
        env::remove_var("DEVDOCS_MAX_BODY_SIZE");
    }

    #[test]
    fn test_path_exclusion() {
        let config = Config {
            excluded_paths: vec!["/health".to_string(), "/api/internal".to_string()],
            ..Default::default()
        };

        assert!(config.is_path_excluded("/health"));
        assert!(config.is_path_excluded("/health/check"));
        assert!(config.is_path_excluded("/api/internal/metrics"));
        assert!(!config.is_path_excluded("/api/users"));
        assert!(!config.is_path_excluded("/public"));
    }

    #[test]
    fn test_should_sample_with_zero_rate() {
        let config = Config {
            sampling_rate: 0.0,
            ..Default::default()
        };

        // With 0% sampling, should never sample
        for _ in 0..100 {
            assert!(!config.should_sample());
        }
    }

    #[test]
    fn test_should_sample_with_full_rate() {
        let config = Config {
            sampling_rate: 1.0,
            ..Default::default()
        };

        // With 100% sampling, should always sample
        for _ in 0..100 {
            assert!(config.should_sample());
        }
    }

    #[test]
    fn test_config_validation_success() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_invalid_sampling_rate() {
        let mut config = Config::default();
        config.sampling_rate = -0.1;
        assert!(config.validate().is_err());
        assert_eq!(
            config.validate().unwrap_err(),
            "Sampling rate must be between 0.0 and 1.0"
        );

        config.sampling_rate = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_zero_body_size() {
        let mut config = Config::default();
        config.max_body_size = Some(0);
        assert!(config.validate().is_err());
        assert_eq!(
            config.validate().unwrap_err(),
            "Max body size must be greater than 0"
        );
    }

    #[test]
    fn test_config_validation_empty_server_url() {
        let mut config = Config::default();
        config.server_url = "".to_string();
        assert!(config.validate().is_err());
        assert_eq!(config.validate().unwrap_err(), "Server URL cannot be empty");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(serialized.contains("sampling_rate"));

        let deserialized: Config = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.sampling_rate, config.sampling_rate);
        assert_eq!(deserialized.max_body_size, config.max_body_size);
    }

    #[test]
    fn test_body_capture_config_serialization() {
        let config = BodyCaptureConfig::default();
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(serialized.contains("enabled"));

        let deserialized: BodyCaptureConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.enabled, config.enabled);
        assert_eq!(deserialized.max_size, config.max_size);
    }

    #[test]
    fn test_config_clone() {
        let config1 = Config::default();
        let config2 = config1.clone();

        assert_eq!(config1.sampling_rate, config2.sampling_rate);
        assert_eq!(config1.max_body_size, config2.max_body_size);
        assert_eq!(config1.excluded_paths, config2.excluded_paths);
    }

    #[test]
    fn test_config_debug() {
        let config = Config::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Config"));
        assert!(debug_str.contains("sampling_rate"));
    }

    #[test]
    fn test_gemini_api_key_from_env() {
        env::set_var("GEMINI_API_KEY", "test_gemini_key");
        let config = Config::default();
        assert_eq!(config.gemini_api_key, Some("test_gemini_key".to_string()));
        env::remove_var("GEMINI_API_KEY");
    }

    #[test]
    fn test_devdocs_api_key_from_env() {
        env::set_var("DEVDOCS_API_KEY", "test_devdocs_key");
        let config = Config::default();
        assert_eq!(config.api_key, "test_devdocs_key");
        env::remove_var("DEVDOCS_API_KEY");
    }

    #[test]
    fn test_body_capture_temp_dir() {
        let config = BodyCaptureConfig::default();
        assert!(config.temp_dir.to_string_lossy().contains("devdocs-bodies"));
    }

    #[test]
    fn test_config_pii_filtering() {
        let config = Config::default();
        assert_eq!(config.enable_pii_filtering, true);

        let config_no_pii = Config {
            enable_pii_filtering: false,
            ..Default::default()
        };
        assert_eq!(config_no_pii.enable_pii_filtering, false);
    }
}
