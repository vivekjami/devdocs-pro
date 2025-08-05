//! HTTP request data structures with integrity validation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents an HTTP request with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// HTTP method (GET, POST, PUT, etc.)
    pub method: String,

    /// Request path (without query parameters)
    pub path: String,

    /// Query parameters
    pub query_params: HashMap<String, String>,

    /// HTTP headers
    pub headers: HashMap<String, String>,

    /// Request body content
    pub body: String,

    /// Content type of the request
    pub content_type: Option<String>,

    /// Additional metadata
    pub metadata: RequestMetadata,
}

/// Additional metadata for HTTP requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Unique request ID for correlation
    pub id: Uuid,

    /// IP address of the client
    pub client_ip: Option<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// Request size in bytes
    pub size_bytes: usize,

    /// Timestamp when request was received
    pub timestamp: u64,

    /// Whether PII was detected and filtered
    pub pii_filtered: bool,
}

impl Request {
    /// Create a new request with basic information
    #[must_use]
    pub fn new(method: String, path: String, body: String) -> Self {
        let id = Uuid::new_v4();
        let size_bytes = body.len();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let metadata = RequestMetadata {
            id,
            client_ip: None,
            user_agent: None,
            size_bytes,
            timestamp,
            pii_filtered: false,
        };

        Self {
            method,
            path,
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body,
            content_type: None,
            metadata,
        }
    }

    /// Add a header to the request
    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    /// Add a query parameter to the request
    pub fn with_query_param(mut self, key: String, value: String) -> Self {
        self.query_params.insert(key, value);
        self
    }

    /// Set the content type
    pub fn with_content_type(mut self, content_type: String) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// Get the full URL path including query parameters
    #[must_use]
    pub fn full_path(&self) -> String {
        if self.query_params.is_empty() {
            self.path.clone()
        } else {
            let query_string = self
                .query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            format!("{}?{}", self.path, query_string)
        }
    }

    /// Check if the request contains JSON content
    #[must_use]
    pub fn is_json(&self) -> bool {
        self.content_type
            .as_ref()
            .map_or(false, |ct| ct.contains("application/json"))
    }

    /// Check if the request contains form data
    #[must_use]
    pub fn is_form_data(&self) -> bool {
        self.content_type.as_ref().map_or(false, |ct| {
            ct.contains("application/x-www-form-urlencoded")
                || ct.contains("multipart/form-data")
        })
    }
}
