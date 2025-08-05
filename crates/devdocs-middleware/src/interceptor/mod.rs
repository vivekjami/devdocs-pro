//! HTTP request/response interception functionality

pub mod tower;

use devdocs_core::models::{HttpTransaction, Request, Response};
use devdocs_core::Result;

/// HTTP interceptor trait for capturing traffic
pub trait HttpInterceptor: Send + Sync {
    /// Intercept an HTTP request
    fn intercept_request(&self, request: &Request) -> Result<()>;

    /// Intercept an HTTP response
    fn intercept_response(&self, response: &Response) -> Result<()>;

    /// Process a complete HTTP transaction
    fn process_transaction(&self, transaction: HttpTransaction) -> Result<()>;
}

/// Configuration for HTTP interception
#[derive(Debug, Clone)]
pub struct InterceptorConfig {
    /// Maximum body size to capture (in bytes)
    pub max_body_size: usize,

    /// Whether to capture request headers
    pub capture_headers: bool,

    /// Whether to capture request bodies
    pub capture_request_body: bool,

    /// Whether to capture response bodies
    pub capture_response_body: bool,

    /// Content types to always exclude from capture
    pub excluded_content_types: Vec<String>,

    /// Paths to exclude from capture
    pub excluded_paths: Vec<String>,
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            max_body_size: 1024 * 1024, // 1MB
            capture_headers: true,
            capture_request_body: true,
            capture_response_body: true,
            excluded_content_types: vec![
                "image/".to_string(),
                "video/".to_string(),
                "audio/".to_string(),
                "application/octet-stream".to_string(),
            ],
            excluded_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/favicon.ico".to_string(),
            ],
        }
    }
}

impl InterceptorConfig {
    /// Check if a content type should be excluded
    pub fn should_exclude_content_type(&self, content_type: &str) -> bool {
        self.excluded_content_types
            .iter()
            .any(|excluded| content_type.starts_with(excluded))
    }

    /// Check if a path should be excluded
    pub fn should_exclude_path(&self, path: &str) -> bool {
        self.excluded_paths.iter().any(|excluded| path == excluded)
    }

    /// Check if body size exceeds limit
    pub fn exceeds_size_limit(&self, size: usize) -> bool {
        size > self.max_body_size
    }
}
