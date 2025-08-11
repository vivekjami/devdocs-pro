//! Endpoint detection and pattern recognition
//!
//! This module analyzes HTTP traffic to detect API endpoints, group similar
//! requests, and identify RESTful patterns.

use crate::analysis::AnalysisConfig;
use crate::errors::DevDocsError;
use crate::models::{ApiEndpoint, TrafficSample};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Endpoint pattern information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointPattern {
    /// Original path pattern
    pub pattern: String,
    /// HTTP method
    pub method: String,
    /// Parameter names extracted from path
    pub path_parameters: Vec<String>,
    /// Query parameters seen
    pub query_parameters: Vec<String>,
    /// Content types seen in requests
    pub request_content_types: Vec<String>,
    /// Content types seen in responses
    pub response_content_types: Vec<String>,
}

/// Endpoint detection engine
pub struct EndpointDetector {
    config: AnalysisConfig,
    uuid_regex: Regex,
    number_regex: Regex,
    date_regex: Regex,
}

impl EndpointDetector {
    /// Create a new endpoint detector
    pub fn new(config: &AnalysisConfig) -> Result<Self, DevDocsError> {
        let uuid_regex = Regex::new(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ).map_err(|e| DevDocsError::Configuration(format!("Failed to compile UUID regex: {}", e)))?;
        
        let number_regex = Regex::new(r"/\d+")
            .map_err(|e| DevDocsError::Configuration(format!("Failed to compile number regex: {}", e)))?;
        
        let date_regex = Regex::new(r"/\d{4}-\d{2}-\d{2}")
            .map_err(|e| DevDocsError::Configuration(format!("Failed to compile date regex: {}", e)))?;

        Ok(Self {
            config: config.clone(),
            uuid_regex,
            number_regex,
            date_regex,
        })
    }

    /// Detect endpoints from traffic samples
    pub async fn detect_endpoints(&self, samples: &[TrafficSample]) -> Result<Vec<ApiEndpoint>, DevDocsError> {
        let mut endpoint_map: HashMap<String, ApiEndpoint> = HashMap::new();

        for sample in samples {
            let pattern = self.extract_endpoint_pattern(&sample.request.path, &sample.request.method);
            let key = format!("{}:{}", sample.request.method, pattern);

            let endpoint = endpoint_map.entry(key).or_insert_with(|| {
                ApiEndpoint::new(pattern, sample.request.method.clone())
            });

            // Update endpoint statistics
            if let Some(response) = &sample.response {
                endpoint.increment_request(
                    response.processing_time_ms as f64,
                    response.status_code,
                );
            } else {
                // Handle cases where we only have request data
                endpoint.increment_request(0.0, 0);
            }
        }

        let mut endpoints: Vec<ApiEndpoint> = endpoint_map.into_values().collect();
        
        // Sort by request count (most popular first)
        endpoints.sort_by(|a, b| b.request_count.cmp(&a.request_count));

        Ok(endpoints)
    }

    /// Extract endpoint pattern from path and method
    pub fn extract_endpoint_pattern(&self, path: &str, method: &str) -> String {
        let mut pattern = path.to_string();

        // Replace UUIDs with {id}
        pattern = self.uuid_regex.replace_all(&pattern, "/{id}").to_string();

        // Replace dates with {date}
        pattern = self.date_regex.replace_all(&pattern, "/{date}").to_string();

        // Replace numbers with {id} (but be smart about versioning)
        if !pattern.contains("/v") && !pattern.contains("/api/v") {
            pattern = self.number_regex.replace_all(&pattern, "/{id}").to_string();
        }

        // Handle common REST patterns
        pattern = self.normalize_rest_patterns(&pattern, method);

        pattern
    }

    /// Normalize REST patterns for better grouping
    fn normalize_rest_patterns(&self, pattern: &str, method: &str) -> String {
        let normalized = pattern.to_string();

        // Handle collection vs resource patterns
        match method {
            "GET" => {
                // GET /users/{id} vs GET /users
                if normalized.ends_with("/{id}") {
                    // This is a resource endpoint
                } else if normalized.ends_with('s') {
                    // This might be a collection endpoint
                }
            }
            "POST" => {
                // POST /users (create)
                if normalized.ends_with("/{id}") {
                    // Unusual pattern, might be a sub-resource creation
                }
            }
            "PUT" | "PATCH" => {
                // PUT/PATCH /users/{id} (update)
                if !normalized.ends_with("/{id}") {
                    // Might need to add {id} pattern
                }
            }
            "DELETE" => {
                // DELETE /users/{id} (delete)
                if !normalized.ends_with("/{id}") {
                    // Might be bulk delete
                }
            }
            _ => {}
        }

        normalized
    }

    /// Analyze endpoint patterns to extract parameter information
    pub fn analyze_endpoint_patterns(&self, samples: &[TrafficSample]) -> Result<Vec<EndpointPattern>, DevDocsError> {
        let mut pattern_map: HashMap<String, EndpointPattern> = HashMap::new();

        for sample in samples {
            let pattern_key = self.extract_endpoint_pattern(&sample.request.path, &sample.request.method);
            let key = format!("{}:{}", sample.request.method, pattern_key);

            let endpoint_pattern = pattern_map.entry(key).or_insert_with(|| {
                EndpointPattern {
                    pattern: pattern_key.clone(),
                    method: sample.request.method.clone(),
                    path_parameters: self.extract_path_parameters(&pattern_key),
                    query_parameters: Vec::new(),
                    request_content_types: Vec::new(),
                    response_content_types: Vec::new(),
                }
            });

            // Collect query parameters
            for param_name in sample.request.query_params.keys() {
                if !endpoint_pattern.query_parameters.contains(param_name) {
                    endpoint_pattern.query_parameters.push(param_name.clone());
                }
            }

            // Collect request content types
            if let Some(content_type) = sample.request.headers.get("content-type") {
                if !endpoint_pattern.request_content_types.contains(content_type) {
                    endpoint_pattern.request_content_types.push(content_type.clone());
                }
            }

            // Collect response content types
            if let Some(response) = &sample.response {
                if let Some(content_type) = response.headers.get("content-type") {
                    if !endpoint_pattern.response_content_types.contains(content_type) {
                        endpoint_pattern.response_content_types.push(content_type.clone());
                    }
                }
            }
        }

        Ok(pattern_map.into_values().collect())
    }

    /// Extract path parameters from a pattern
    fn extract_path_parameters(&self, pattern: &str) -> Vec<String> {
        let param_regex = Regex::new(r"\{([^}]+)\}").unwrap();
        param_regex
            .captures_iter(pattern)
            .map(|cap| cap[1].to_string())
            .collect()
    }

    /// Detect API versioning patterns
    pub fn detect_api_versions(&self, samples: &[TrafficSample]) -> Vec<String> {
        let version_regex = Regex::new(r"/v(\d+(?:\.\d+)?)").unwrap();
        let mut versions = std::collections::HashSet::new();

        for sample in samples {
            if let Some(captures) = version_regex.captures(&sample.request.path) {
                if let Some(version) = captures.get(1) {
                    versions.insert(format!("v{}", version.as_str()));
                }
            }
        }

        let mut version_list: Vec<String> = versions.into_iter().collect();
        version_list.sort();
        version_list
    }

    /// Detect authentication patterns from headers
    pub fn detect_auth_patterns(&self, samples: &[TrafficSample]) -> Vec<String> {
        let mut auth_patterns = std::collections::HashSet::new();

        for sample in samples {
            // Check Authorization header
            if let Some(auth_header) = sample.request.headers.get("authorization") {
                if auth_header.starts_with("Bearer ") {
                    auth_patterns.insert("Bearer Token".to_string());
                } else if auth_header.starts_with("Basic ") {
                    auth_patterns.insert("Basic Auth".to_string());
                } else if auth_header.starts_with("Digest ") {
                    auth_patterns.insert("Digest Auth".to_string());
                }
            }

            // Check for API key patterns
            if sample.request.headers.contains_key("x-api-key") ||
               sample.request.headers.contains_key("api-key") ||
               sample.request.query_params.contains_key("api_key") ||
               sample.request.query_params.contains_key("apikey") {
                auth_patterns.insert("API Key".to_string());
            }

            // Check for session cookies
            if let Some(cookie_header) = sample.request.headers.get("cookie") {
                if cookie_header.contains("session") || cookie_header.contains("JSESSIONID") {
                    auth_patterns.insert("Session Cookie".to_string());
                }
            }
        }

        auth_patterns.into_iter().collect()
    }

    /// Update configuration
    pub fn update_config(&mut self, config: &AnalysisConfig) -> Result<(), DevDocsError> {
        self.config = config.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HttpRequest, HttpResponse};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_endpoint_detector_creation() {
        let config = AnalysisConfig::default();
        let detector = EndpointDetector::new(&config);
        assert!(detector.is_ok());
    }

    #[test]
    fn test_endpoint_pattern_extraction() {
        let config = AnalysisConfig::default();
        let detector = EndpointDetector::new(&config).unwrap();

        // Test UUID replacement
        assert_eq!(
            detector.extract_endpoint_pattern("/users/550e8400-e29b-41d4-a716-446655440000", "GET"),
            "/users/{id}"
        );

        // Test number replacement
        assert_eq!(
            detector.extract_endpoint_pattern("/users/123", "GET"),
            "/users/{id}"
        );

        // Test date replacement
        assert_eq!(
            detector.extract_endpoint_pattern("/reports/2023-12-01", "GET"),
            "/reports/{date}"
        );

        // Test version preservation
        assert_eq!(
            detector.extract_endpoint_pattern("/api/v1/users/123", "GET"),
            "/api/v1/users/{id}"
        );
    }

    #[test]
    fn test_path_parameter_extraction() {
        let config = AnalysisConfig::default();
        let detector = EndpointDetector::new(&config).unwrap();

        let params = detector.extract_path_parameters("/users/{id}/posts/{postId}");
        assert_eq!(params, vec!["id", "postId"]);

        let params = detector.extract_path_parameters("/api/v1/users");
        assert!(params.is_empty());
    }

    #[tokio::test]
    async fn test_endpoint_detection() {
        let config = AnalysisConfig::default();
        let detector = EndpointDetector::new(&config).unwrap();

        let mut samples = Vec::new();
        
        // Create sample requests
        for i in 1..=5 {
            let request = HttpRequest::new(
                "GET".to_string(),
                format!("/users/{}", i),
                format!("corr-{}", i),
            );
            let response = HttpResponse::new(request.id, 200)
                .with_processing_time(100);
            
            let sample = TrafficSample::new(request, "/users/{id}".to_string())
                .with_response(response);
            samples.push(sample);
        }

        let endpoints = detector.detect_endpoints(&samples).await.unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path_pattern, "/users/{id}");
        assert_eq!(endpoints[0].method, "GET");
        assert_eq!(endpoints[0].request_count, 5);
    }

    #[test]
    fn test_api_version_detection() {
        let config = AnalysisConfig::default();
        let detector = EndpointDetector::new(&config).unwrap();

        let samples = vec![
            TrafficSample::new(
                HttpRequest::new("GET".to_string(), "/api/v1/users".to_string(), "corr-1".to_string()),
                "/api/v1/users".to_string(),
            ),
            TrafficSample::new(
                HttpRequest::new("GET".to_string(), "/api/v2/users".to_string(), "corr-2".to_string()),
                "/api/v2/users".to_string(),
            ),
            TrafficSample::new(
                HttpRequest::new("GET".to_string(), "/api/v1.1/posts".to_string(), "corr-3".to_string()),
                "/api/v1.1/posts".to_string(),
            ),
        ];

        let versions = detector.detect_api_versions(&samples);
        assert_eq!(versions, vec!["v1", "v1.1", "v2"]);
    }

    #[test]
    fn test_auth_pattern_detection() {
        let config = AnalysisConfig::default();
        let detector = EndpointDetector::new(&config).unwrap();

        let mut headers1 = HashMap::new();
        headers1.insert("authorization".to_string(), "Bearer token123".to_string());

        let mut headers2 = HashMap::new();
        headers2.insert("x-api-key".to_string(), "key123".to_string());

        let mut headers3 = HashMap::new();
        headers3.insert("authorization".to_string(), "Basic dXNlcjpwYXNz".to_string());

        let samples = vec![
            TrafficSample::new(
                HttpRequest::new("GET".to_string(), "/api/users".to_string(), "corr-1".to_string())
                    .with_headers(headers1),
                "/api/users".to_string(),
            ),
            TrafficSample::new(
                HttpRequest::new("GET".to_string(), "/api/posts".to_string(), "corr-2".to_string())
                    .with_headers(headers2),
                "/api/posts".to_string(),
            ),
            TrafficSample::new(
                HttpRequest::new("GET".to_string(), "/api/comments".to_string(), "corr-3".to_string())
                    .with_headers(headers3),
                "/api/comments".to_string(),
            ),
        ];

        let auth_patterns = detector.detect_auth_patterns(&samples);
        assert!(auth_patterns.contains(&"Bearer Token".to_string()));
        assert!(auth_patterns.contains(&"API Key".to_string()));
        assert!(auth_patterns.contains(&"Basic Auth".to_string()));
    }

    #[test]
    fn test_endpoint_pattern_analysis() {
        let config = AnalysisConfig::default();
        let detector = EndpointDetector::new(&config).unwrap();

        let mut query_params = HashMap::new();
        query_params.insert("page".to_string(), "1".to_string());
        query_params.insert("limit".to_string(), "10".to_string());

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let request = HttpRequest::new("GET".to_string(), "/users/123".to_string(), "corr-1".to_string())
            .with_query_params(query_params)
            .with_headers(headers.clone());

        let response = HttpResponse::new(request.id, 200)
            .with_headers(headers);

        let sample = TrafficSample::new(request, "/users/{id}".to_string())
            .with_response(response);

        let patterns = detector.analyze_endpoint_patterns(&[sample]).unwrap();
        assert_eq!(patterns.len(), 1);
        
        let pattern = &patterns[0];
        assert_eq!(pattern.pattern, "/users/{id}");
        assert_eq!(pattern.method, "GET");
        assert_eq!(pattern.path_parameters, vec!["id"]);
        assert!(pattern.query_parameters.contains(&"page".to_string()));
        assert!(pattern.query_parameters.contains(&"limit".to_string()));
        assert!(pattern.request_content_types.contains(&"application/json".to_string()));
        assert!(pattern.response_content_types.contains(&"application/json".to_string()));
    }
}