//! Body capture system for HTTP requests and responses
//!
//! This module provides streaming body capture with intelligent content-type
//! detection, compression handling, and memory management for large payloads.

use crate::errors::{DevDocsError, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{body::Incoming, HeaderMap};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Maximum size for in-memory body storage
const MAX_MEMORY_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// Default maximum body size to capture
const DEFAULT_MAX_BODY_SIZE: usize = 100 * 1024 * 1024; // 100MB

/// Helper function to collect body bytes from Hyper 1.0 Incoming
async fn collect_body(body: Incoming) -> Result<Bytes> {
    body.collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|e| DevDocsError::InvalidRequest(format!("Failed to collect body: {}", e)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionType {
    Gzip,
    Deflate,
    Brotli,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContentPriority {
    High,   // JSON, XML - critical for API docs
    Medium, // Form data, text, CSV
    Low,    // Binary, images
    Skip,   // Videos, large archives
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BodyStorage {
    Memory(Vec<u8>),
    File(PathBuf),
    Truncated {
        original_size: usize,
        captured: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedBody {
    pub content_type: Option<String>,
    pub compression: CompressionType,
    pub priority: ContentPriority,
    pub original_size: usize,
    pub storage: BodyStorage,
}

/// Configuration for body capture behavior
#[derive(Debug, Clone)]
pub struct BodyCaptureConfig {
    pub max_size: usize,
    pub max_memory_size: usize,
    pub temp_dir: PathBuf,
    pub enable_compression_detection: bool,
    pub enable_decompression: bool,
}

impl Default for BodyCaptureConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_BODY_SIZE,
            max_memory_size: MAX_MEMORY_SIZE,
            temp_dir: std::env::temp_dir().join("devdocs-bodies"),
            enable_compression_detection: true,
            enable_decompression: true,
        }
    }
}

/// Core body capture functionality
pub struct BodyCapture {
    config: BodyCaptureConfig,
}

impl BodyCapture {
    pub fn new(config: BodyCaptureConfig) -> Self {
        Self { config }
    }

    /// Capture a request body with intelligent handling
    pub async fn capture_request_body(
        &self,
        body: Incoming,
        headers: &HeaderMap,
    ) -> Result<Option<CapturedBody>> {
        self.capture_body(body, headers, "request").await
    }

    /// Capture a response body with intelligent handling
    pub async fn capture_response_body(
        &self,
        body: Incoming,
        headers: &HeaderMap,
    ) -> Result<Option<CapturedBody>> {
        self.capture_body(body, headers, "response").await
    }

    /// Internal method to capture any HTTP body
    async fn capture_body(
        &self,
        body: Incoming,
        headers: &HeaderMap,
        body_type: &str,
    ) -> Result<Option<CapturedBody>> {
        // Analyze content type and priority
        let content_type = extract_content_type(headers);
        let priority = analyze_content_priority(&content_type);

        // Skip low-priority content based on configuration
        if matches!(priority, ContentPriority::Skip) {
            tracing::debug!(
                "Skipping body capture for low-priority content: {:?}",
                content_type
            );
            return Ok(None);
        }

        // Detect compression
        let compression = if self.config.enable_compression_detection {
            detect_compression(headers)
        } else {
            CompressionType::None
        };

        tracing::debug!(
            body_type = body_type,
            content_type = ?content_type,
            compression = ?compression,
            priority = ?priority,
            "Starting body capture"
        );

        // Capture body with size limits
        let body_bytes = match collect_body(body).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!("Failed to read {} body: {}", body_type, e);
                return Ok(None);
            }
        };

        let original_size = body_bytes.len();

        // Check size limits
        if original_size > self.config.max_size {
            tracing::warn!(
                "Body size {} exceeds maximum {}, truncating",
                original_size,
                self.config.max_size
            );

            let truncated = body_bytes.slice(..self.config.max_size.min(body_bytes.len()));
            return Ok(Some(CapturedBody {
                content_type,
                compression: compression.clone(),
                priority,
                original_size,
                storage: BodyStorage::Truncated {
                    original_size,
                    captured: truncated.to_vec(),
                },
            }));
        }

        // Decompress if needed and enabled
        let processed_bytes =
            if self.config.enable_decompression && !matches!(compression, CompressionType::None) {
                match decompress_body(body_bytes.clone(), &compression).await {
                    Ok(decompressed) => {
                        tracing::debug!(
                            "Decompressed body from {} to {} bytes",
                            body_bytes.len(),
                            decompressed.len()
                        );
                        decompressed
                    }
                    Err(e) => {
                        tracing::warn!("Failed to decompress body: {}, using original", e);
                        body_bytes
                    }
                }
            } else {
                body_bytes
            };

        // Decide storage strategy based on size
        let storage = if processed_bytes.len() <= self.config.max_memory_size {
            BodyStorage::Memory(processed_bytes.to_vec())
        } else {
            // Store large bodies in temporary files
            let file_path = self.store_large_body(&processed_bytes, body_type).await?;
            BodyStorage::File(file_path)
        };

        Ok(Some(CapturedBody {
            content_type,
            compression,
            priority,
            original_size,
            storage,
        }))
    }

    /// Store large body data to temporary file
    async fn store_large_body(&self, data: &Bytes, body_type: &str) -> Result<PathBuf> {
        // Ensure temp directory exists
        fs::create_dir_all(&self.config.temp_dir)
            .await
            .map_err(|e| DevDocsError::Io(e))?;

        // Generate unique filename
        let filename = format!(
            "devdocs-{}-{}-{}.bin",
            body_type,
            uuid::Uuid::new_v4(),
            chrono::Utc::now().timestamp()
        );
        let file_path = self.config.temp_dir.join(filename);

        // Write data to file
        let mut file = fs::File::create(&file_path)
            .await
            .map_err(|e| DevDocsError::Io(e))?;

        file.write_all(data)
            .await
            .map_err(|e| DevDocsError::Io(e))?;

        file.sync_all().await.map_err(|e| DevDocsError::Io(e))?;

        tracing::debug!(
            "Stored large body ({} bytes) to file: {:?}",
            data.len(),
            file_path
        );

        Ok(file_path)
    }
}

/// Extract content-type from headers
fn extract_content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(hyper::header::CONTENT_TYPE)?
        .to_str()
        .ok()
        .map(|s| s.to_lowercase())
}

/// Analyze content type to determine capture priority
pub fn analyze_content_priority(content_type: &Option<String>) -> ContentPriority {
    match content_type {
        Some(ct) => {
            let ct = ct.to_lowercase();

            // High priority: API-relevant content
            if ct.contains("application/json")
                || ct.contains("application/xml")
                || ct.contains("text/xml")
                || ct.contains("application/hal+json")
                || ct.contains("application/vnd.api+json")
            {
                ContentPriority::High
            }
            // Medium priority: Form data and text content
            else if ct.contains("application/x-www-form-urlencoded")
                || ct.contains("multipart/form-data")
                || ct.contains("text/plain")
                || ct.contains("text/csv")
                || ct.contains("application/x-yaml")
            {
                ContentPriority::Medium
            }
            // Low priority: Binary content that might be relevant
            else if ct.contains("application/octet-stream")
                || ct.contains("application/pdf")
                || ct.contains("image/")
            {
                ContentPriority::Low
            }
            // Skip: Large media files
            else if ct.contains("video/")
                || ct.contains("audio/")
                || ct.contains("application/zip")
                || ct.contains("application/x-rar")
                || ct.contains("application/x-7z")
            {
                ContentPriority::Skip
            } else {
                // Default to medium for unknown types
                ContentPriority::Medium
            }
        }
        None => ContentPriority::Medium,
    }
}

/// Detect compression type from headers
pub fn detect_compression(headers: &HeaderMap) -> CompressionType {
    if let Some(encoding) = headers.get(hyper::header::CONTENT_ENCODING) {
        if let Ok(encoding_str) = encoding.to_str() {
            let encoding_lower = encoding_str.to_lowercase();

            if encoding_lower.contains("gzip") {
                return CompressionType::Gzip;
            } else if encoding_lower.contains("deflate") {
                return CompressionType::Deflate;
            } else if encoding_lower.contains("br") {
                return CompressionType::Brotli;
            }
        }
    }

    CompressionType::None
}

/// Decompress body based on compression type
pub async fn decompress_body(data: Bytes, compression: &CompressionType) -> Result<Bytes> {
    use std::io::Read;

    match compression {
        CompressionType::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(data.as_ref());
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).map_err(|e| {
                DevDocsError::InvalidRequest(format!("Gzip decompression failed: {}", e))
            })?;
            Ok(Bytes::from(decompressed))
        }
        CompressionType::Deflate => {
            let mut decoder = flate2::read::DeflateDecoder::new(data.as_ref());
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).map_err(|e| {
                DevDocsError::InvalidRequest(format!("Deflate decompression failed: {}", e))
            })?;
            Ok(Bytes::from(decompressed))
        }
        CompressionType::Brotli => {
            // For now, return original data - brotli decompression would require additional dependency
            tracing::warn!("Brotli decompression not yet implemented");
            Ok(data)
        }
        CompressionType::None => Ok(data),
    }
}

impl CapturedBody {
    /// Get the body data, reading from file if necessary
    pub async fn get_data(&self) -> Result<Bytes> {
        match &self.storage {
            BodyStorage::Memory(data) => Ok(Bytes::from(data.clone())),
            BodyStorage::File(path) => {
                let data = fs::read(path).await.map_err(|e| DevDocsError::Io(e))?;
                Ok(Bytes::from(data))
            }
            BodyStorage::Truncated { captured, .. } => Ok(Bytes::from(captured.clone())),
        }
    }

    /// Get body as UTF-8 string if possible
    pub async fn get_text(&self) -> Result<String> {
        let data = self.get_data().await?;
        String::from_utf8(data.to_vec())
            .map_err(|e| DevDocsError::InvalidRequest(format!("Body is not valid UTF-8: {}", e)))
    }

    /// Check if body was truncated due to size limits
    pub fn is_truncated(&self) -> bool {
        matches!(self.storage, BodyStorage::Truncated { .. })
    }

    /// Get the size of captured data
    pub fn captured_size(&self) -> usize {
        match &self.storage {
            BodyStorage::Memory(data) => data.len(),
            BodyStorage::Truncated { captured, .. } => captured.len(),
            BodyStorage::File(_) => 0, // Would need to read file to get size
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::CONTENT_ENCODING;

    #[test]
    fn test_analyze_content_priority() {
        // High priority content types
        assert!(matches!(
            analyze_content_priority(&Some("application/json".to_string())),
            ContentPriority::High
        ));

        assert!(matches!(
            analyze_content_priority(&Some("application/xml".to_string())),
            ContentPriority::High
        ));

        // Medium priority content types
        assert!(matches!(
            analyze_content_priority(&Some("application/x-www-form-urlencoded".to_string())),
            ContentPriority::Medium
        ));

        assert!(matches!(
            analyze_content_priority(&Some("text/plain".to_string())),
            ContentPriority::Medium
        ));

        // Skip content types
        assert!(matches!(
            analyze_content_priority(&Some("video/mp4".to_string())),
            ContentPriority::Skip
        ));
    }

    #[test]
    fn test_detect_compression() {
        let mut headers = HeaderMap::new();

        // Test gzip detection
        headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());
        assert!(matches!(
            detect_compression(&headers),
            CompressionType::Gzip
        ));

        // Test deflate detection
        headers.insert(CONTENT_ENCODING, "deflate".parse().unwrap());
        assert!(matches!(
            detect_compression(&headers),
            CompressionType::Deflate
        ));

        // Test no compression
        headers.remove(CONTENT_ENCODING);
        assert!(matches!(
            detect_compression(&headers),
            CompressionType::None
        ));
    }
}
