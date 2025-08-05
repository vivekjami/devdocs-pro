//! DevDocs Pro Language Bindings
//!
//! This crate provides language-specific bindings for integrating DevDocs Pro
//! with various web frameworks and programming languages.

// Set strict linting rules to maintain code quality
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod common;

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "nodejs")]
pub mod nodejs;

#[cfg(feature = "golang")]
pub mod golang;

use devdocs_core::{Config, DevDocsError, Result};
use serde::{Deserialize, Serialize};

/// Common configuration for language bindings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingConfig {
    /// API key for authentication
    pub api_key: String,
    
    /// Sampling rate (0.0 - 1.0)
    pub sampling_rate: Option<f64>,
    
    /// Maximum body size to capture
    pub max_body_size: Option<usize>,
    
    /// Enable PII detection
    pub pii_detection: Option<bool>,
    
    /// Paths to exclude from capture
    pub excluded_paths: Option<Vec<String>>,
    
    /// Content types to exclude
    pub excluded_content_types: Option<Vec<String>>,
}

impl BindingConfig {
    /// Create a new binding configuration with API key
    #[must_use]
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            sampling_rate: None,
            max_body_size: None,
            pii_detection: None,
            excluded_paths: None,
            excluded_content_types: None,
        }
    }
    
    /// Convert to DevDocs core configuration
    pub fn to_core_config(&self) -> Result<Config> {
        let storage = devdocs_core::StorageConfig {
            storage_type: devdocs_core::StorageType::Memory,
            storage_path: None,
            db_connection: None,
            max_size: Some(100 * 1024 * 1024), // 100MB default
            retention_period: Some(24 * 60 * 60), // 24 hours default
        };
        
        Ok(Config {
            api_key: self.api_key.clone(),
            max_body_size: self.max_body_size.unwrap_or(1024 * 1024),
            sampling_rate: self.sampling_rate.unwrap_or(1.0),
            pii_detection: self.pii_detection.unwrap_or(true),
            storage,
        })
    }
}

/// Version information
pub mod version {
    /// Current version of the DevDocs Pro bindings
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
}
