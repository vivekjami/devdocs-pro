//! HTTP response data structures with integrity validation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents an HTTP response with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// HTTP status code
    pub status_code: u16,

    /// Status text (e.g., "OK", "Not Found")
    pub status_text: String,

    /// Response headers
    pub headers: HashMap<String, String>,

    /// Response body content
    pub body: String,

    /// Content type of the response
    pub content_type: Option<String>,

    /// Additional metadata
    pub metadata: ResponseMetadata,
}

/// Additional metadata for HTTP responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    /// Unique response ID for correlation
    pub id: Uuid,

    /// Response size in bytes
    pub size_bytes: usize,

    /// Processing time in milliseconds
    pub processing_time_ms: Option<u64>,

    /// Timestamp when response was generated
    pub timestamp: u64,

    /// Whether PII was detected and filtered
    pub pii_filtered: bool,

    /// Response compression type
    pub compression: Option<String>,
}

impl Response {
    /// Create a new response with basic information
    #[must_use]
    pub fn new(status_code: u16, status_text: String, body: String) -> Self {
        let id = Uuid::new_v4();
        let size_bytes = body.len();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let metadata = ResponseMetadata {
            id,
            size_bytes,
            processing_time_ms: None,
            timestamp,
            pii_filtered: false,
            compression: None,
        };

        Self {
            status_code,
            status_text,
            headers: HashMap::new(),
            body,
            content_type: None,
            metadata,
        }
    }

    /// Add a header to the response
    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    /// Set the content type
    pub fn with_content_type(mut self, content_type: String) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// Set the processing time
    pub fn with_processing_time(mut self, processing_time_ms: u64) -> Self {
        self.metadata.processing_time_ms = Some(processing_time_ms);
        self
    }

    /// Check if the response is successful (2xx status codes)
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Check if the response is a client error (4xx status codes)
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status_code)
    }

    /// Check if the response is a server error (5xx status codes)
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status_code)
    }

    /// Check if the response contains JSON content
    #[must_use]
    pub fn is_json(&self) -> bool {
        self.content_type
            .as_ref()
            .map_or(false, |ct| ct.contains("application/json"))
    }

    /// Check if the response contains HTML content
    #[must_use]
    pub fn is_html(&self) -> bool {
        self.content_type
            .as_ref()
            .map_or(false, |ct| ct.contains("text/html"))
    }

    /// Check if the response contains XML content
    #[must_use]
    pub fn is_xml(&self) -> bool {
        self.content_type.as_ref().map_or(false, |ct| {
            ct.contains("application/xml") || ct.contains("text/xml")
        })
    }
}
