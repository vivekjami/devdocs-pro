//! DevDocs Pro HTTP Middleware
//!
//! This crate provides HTTP middleware for intercepting and analyzing API traffic
//! to generate real-time documentation. It includes sampling strategies, security
//! filters, and data integrity guarantees.

// Set strict linting rules to maintain code quality
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod interceptor;
pub mod sampling;
pub mod security;

use devdocs_core::{Config, DevDocs, Result};
use std::sync::Arc;

/// DevDocs middleware instance
pub struct DevDocsMiddleware {
    /// Core DevDocs instance
    core: Arc<DevDocs>,
}

impl DevDocsMiddleware {
    /// Create a new middleware instance
    #[must_use]
    pub fn new(config: Config) -> Self {
        let core = Arc::new(DevDocs::new(config));
        Self { core }
    }

    /// Get a reference to the core DevDocs instance
    #[must_use]
    pub fn core(&self) -> &Arc<DevDocs> {
        &self.core
    }
}

/// Version information
pub mod version {
    /// Current version of the DevDocs Pro middleware
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
}
