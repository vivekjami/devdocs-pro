//! Common utilities for language bindings

use crate::BindingConfig;
use devdocs_core::{Config, DevDocs, Result};
use devdocs_middleware::DevDocsMiddleware;
use std::sync::Arc;
use tracing::info;

/// Common middleware wrapper for all language bindings
pub struct CommonMiddleware {
    /// DevDocs middleware instance
    middleware: DevDocsMiddleware,
    
    /// Configuration
    config: BindingConfig,
}

impl CommonMiddleware {
    /// Create a new common middleware instance
    pub fn new(config: BindingConfig) -> Result<Self> {
        info!("Initializing DevDocs middleware with API key: {}", 
              mask_api_key(&config.api_key));
        
        let core_config = config.to_core_config()?;
        let middleware = DevDocsMiddleware::new(core_config);
        
        Ok(Self {
            middleware,
            config,
        })
    }
    
    /// Get the middleware instance
    #[must_use]
    pub fn middleware(&self) -> &DevDocsMiddleware {
        &self.middleware
    }
    
    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &BindingConfig {
        &self.config
    }
    
    /// Check if a path should be excluded
    pub fn should_exclude_path(&self, path: &str) -> bool {
        if let Some(ref excluded_paths) = self.config.excluded_paths {
            excluded_paths.iter().any(|excluded| path.starts_with(excluded))
        } else {
            false
        }
    }
    
    /// Check if a content type should be excluded
    pub fn should_exclude_content_type(&self, content_type: &str) -> bool {
        if let Some(ref excluded_types) = self.config.excluded_content_types {
            excluded_types.iter().any(|excluded| content_type.starts_with(excluded))
        } else {
            false
        }
    }
}

/// Framework integration trait
pub trait FrameworkIntegration {
    /// Framework name
    fn framework_name(&self) -> &'static str;
    
    /// Initialize the integration
    fn initialize(&mut self) -> Result<()>;
    
    /// Check if the integration is active
    fn is_active(&self) -> bool;
}

/// Mask API key for logging (show only first 8 characters)
fn mask_api_key(api_key: &str) -> String {
    if api_key.len() > 8 {
        format!("{}...", &api_key[..8])
    } else {
        "***".to_string()
    }
}

/// Common error types for bindings
#[derive(thiserror::Error, Debug)]
pub enum BindingError {
    /// Core DevDocs error
    #[error("DevDocs error: {0}")]
    Core(#[from] devdocs_core::DevDocsError),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    /// Framework integration error
    #[error("Framework integration error: {0}")]
    Framework(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type for binding operations
pub type BindingResult<T> = std::result::Result<T, BindingError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_masking() {
        assert_eq!(mask_api_key("short"), "***");
        assert_eq!(mask_api_key("12345678"), "***");
        assert_eq!(mask_api_key("12345678901234567890"), "12345678...");
    }

    #[test]
    fn test_binding_config_creation() {
        let config = BindingConfig::new("test_api_key".to_string());
        assert_eq!(config.api_key, "test_api_key");
        assert!(config.sampling_rate.is_none());
        assert!(config.pii_detection.is_none());
    }

    #[test]
    fn test_core_config_conversion() {
        let binding_config = BindingConfig {
            api_key: "test_key".to_string(),
            sampling_rate: Some(0.5),
            max_body_size: Some(2048),
            pii_detection: Some(false),
            excluded_paths: None,
            excluded_content_types: None,
        };
        
        let core_config = binding_config.to_core_config().unwrap();
        assert_eq!(core_config.api_key, "test_key");
        assert_eq!(core_config.sampling_rate, 0.5);
        assert_eq!(core_config.max_body_size, 2048);
        assert!(!core_config.pii_detection);
    }
}
