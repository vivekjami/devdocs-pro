//! DevDocs Pro core library
//!
//! This crate provides the core functionality for API documentation generation
//! from HTTP traffic. It includes schema inference, traffic analysis, and
//! storage capabilities with a focus on data integrity.

// Set strict linting rules to maintain code quality
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::sync::Arc;
use thiserror::Error;

pub mod analysis;
pub mod models;
pub mod schema;
pub mod storage;

/// Core error types for DevDocs Pro
#[derive(Error, Debug)]
pub enum DevDocsError {
    /// Errors related to schema inference
    #[error("Schema error: {0}")]
    Schema(String),
    
    /// Errors related to data storage
    #[error("Storage error: {0}")]
    Storage(String),
    
    /// Errors related to request/response processing
    #[error("Processing error: {0}")]
    Processing(String),
    
    /// Security-related errors
    #[error("Security error: {0}")]
    Security(String),
    
    /// Data integrity errors
    #[error("Data integrity error: {0}")]
    DataIntegrity(String),
    
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Result type for DevDocs Pro operations
pub type Result<T> = std::result::Result<T, DevDocsError>;

/// Core configuration for DevDocs Pro
#[derive(Debug, Clone)]
pub struct Config {
    /// API key for authentication
    pub api_key: String,
    
    /// Maximum size of request/response bodies to capture
    pub max_body_size: usize,
    
    /// Sampling rate (0.0 - 1.0) for request capture
    pub sampling_rate: f64,
    
    /// Enable PII detection and filtering
    pub pii_detection: bool,
    
    /// Storage configuration
    pub storage: StorageConfig,
}

/// Storage configuration options
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Storage type (memory, disk, database)
    pub storage_type: StorageType,
    
    /// Path for disk storage
    pub storage_path: Option<String>,
    
    /// Database connection string
    pub db_connection: Option<String>,
    
    /// Maximum storage size in bytes
    pub max_size: Option<usize>,
    
    /// Data retention period in seconds
    pub retention_period: Option<u64>,
}

/// Available storage types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    /// In-memory storage (volatile)
    Memory,
    
    /// Persistent disk storage
    Disk,
    
    /// Database storage
    Database,
}

/// DevDocs core instance that coordinates all functionality
pub struct DevDocs {
    config: Config,
    // Additional fields will be added as the implementation progresses
}

impl DevDocs {
    /// Create a new DevDocs instance with the provided configuration
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self { config }
    }
    
    /// Get a reference to the current configuration
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }
    
    // Additional methods will be added as the implementation progresses
}

/// Version information
pub mod version {
    /// Current version of the DevDocs Pro core
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
    
    /// Build information, populated during CI build
    pub const BUILD_INFO: &str = option_env!("BUILD_INFO").unwrap_or("development");
}
