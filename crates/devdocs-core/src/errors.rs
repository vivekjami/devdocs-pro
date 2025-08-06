use thiserror::Error;

#[derive(Error, Debug)]
pub enum DevDocsError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Body too large: {size} > {limit}")]
    BodyTooLarge { size: usize, limit: usize },

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("AI processing error: {0}")]
    AiProcessing(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Schema inference error: {0}")]
    SchemaInference(String),

    #[error("Traffic analysis error: {0}")]
    TrafficAnalysis(String),
}

impl DevDocsError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            DevDocsError::Network(_) | DevDocsError::Timeout(_) | DevDocsError::RateLimit(_)
        )
    }

    pub fn error_code(&self) -> u32 {
        match self {
            DevDocsError::Config(_) => 1001,
            DevDocsError::Network(_) => 1002,
            DevDocsError::Serialization(_) => 1003,
            DevDocsError::Io(_) => 1004,
            DevDocsError::BodyTooLarge { .. } => 1005,
            DevDocsError::InvalidRequest(_) => 1006,
            DevDocsError::AiProcessing(_) => 1007,
            DevDocsError::RateLimit(_) => 1008,
            DevDocsError::Authentication(_) => 1009,
            DevDocsError::Timeout(_) => 1010,
            DevDocsError::SchemaInference(_) => 1011,
            DevDocsError::TrafficAnalysis(_) => 1012,
        }
    }
}

pub type Result<T> = std::result::Result<T, DevDocsError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_config_error() {
        let error = DevDocsError::Config("Invalid config".to_string());
        assert_eq!(error.to_string(), "Configuration error: Invalid config");
        assert_eq!(error.error_code(), 1001);
        assert!(!error.is_retryable());
    }

    #[tokio::test]
    async fn test_network_error() {
        // Create a reqwest error by making a request to invalid URL
        let error = reqwest::get("http://invalid.url.that.does.not.exist.123456789").await.unwrap_err();
        let devdocs_error = DevDocsError::Network(error);
        assert!(devdocs_error.to_string().contains("Network error"));
        assert_eq!(devdocs_error.error_code(), 1002);
        assert!(devdocs_error.is_retryable());
    }

    #[test]
    fn test_serialization_error() {
        // Create a JSON parse error by parsing invalid JSON
        let result: std::result::Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let serde_error = result.unwrap_err();
        let error = DevDocsError::Serialization(serde_error);
        assert!(error.to_string().contains("Serialization error"));
        assert_eq!(error.error_code(), 1003);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_io_error() {
        let io_error = io::Error::new(io::ErrorKind::NotFound, "File not found");
        let error = DevDocsError::Io(io_error);
        assert!(error.to_string().contains("IO error"));
        assert_eq!(error.error_code(), 1004);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_body_too_large_error() {
        let error = DevDocsError::BodyTooLarge { size: 1000, limit: 500 };
        assert_eq!(error.to_string(), "Body too large: 1000 > 500");
        assert_eq!(error.error_code(), 1005);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_invalid_request_error() {
        let error = DevDocsError::InvalidRequest("Missing header".to_string());
        assert_eq!(error.to_string(), "Invalid request: Missing header");
        assert_eq!(error.error_code(), 1006);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_ai_processing_error() {
        let error = DevDocsError::AiProcessing("Model failed".to_string());
        assert_eq!(error.to_string(), "AI processing error: Model failed");
        assert_eq!(error.error_code(), 1007);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_rate_limit_error() {
        let error = DevDocsError::RateLimit("Too many requests".to_string());
        assert_eq!(error.to_string(), "Rate limit exceeded: Too many requests");
        assert_eq!(error.error_code(), 1008);
        assert!(error.is_retryable());
    }

    #[test]
    fn test_authentication_error() {
        let error = DevDocsError::Authentication("Invalid API key".to_string());
        assert_eq!(error.to_string(), "Authentication failed: Invalid API key");
        assert_eq!(error.error_code(), 1009);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_timeout_error() {
        let error = DevDocsError::Timeout("Request timed out".to_string());
        assert_eq!(error.to_string(), "Timeout error: Request timed out");
        assert_eq!(error.error_code(), 1010);
        assert!(error.is_retryable());
    }

    #[test]
    fn test_schema_inference_error() {
        let error = DevDocsError::SchemaInference("Failed to infer schema".to_string());
        assert_eq!(error.to_string(), "Schema inference error: Failed to infer schema");
        assert_eq!(error.error_code(), 1011);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_traffic_analysis_error() {
        let error = DevDocsError::TrafficAnalysis("Analysis failed".to_string());
        assert_eq!(error.to_string(), "Traffic analysis error: Analysis failed");
        assert_eq!(error.error_code(), 1012);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_result_type() {
        fn test_function() -> Result<i32> {
            Ok(42)
        }
        
        let result = test_function();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        
        fn error_function() -> Result<i32> {
            Err(DevDocsError::Config("Test error".to_string()))
        }
        
        let error_result = error_function();
        assert!(error_result.is_err());
    }

    #[test]
    fn test_error_from_conversion() {
        let io_error = io::Error::new(io::ErrorKind::PermissionDenied, "Access denied");
        let devdocs_error: DevDocsError = io_error.into();
        assert!(matches!(devdocs_error, DevDocsError::Io(_)));
    }

    #[test]
    fn test_error_debug() {
        let error = DevDocsError::Config("Test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Config"));
        assert!(debug_str.contains("Test"));
    }

    #[test]
    fn test_is_retryable_combinations() {
        // Retryable errors
        assert!(DevDocsError::RateLimit("test".to_string()).is_retryable());
        assert!(DevDocsError::Timeout("test".to_string()).is_retryable());
        
        // Non-retryable errors
        assert!(!DevDocsError::Config("test".to_string()).is_retryable());
        assert!(!DevDocsError::InvalidRequest("test".to_string()).is_retryable());
        assert!(!DevDocsError::Authentication("test".to_string()).is_retryable());
        assert!(!DevDocsError::AiProcessing("test".to_string()).is_retryable());
        assert!(!DevDocsError::SchemaInference("test".to_string()).is_retryable());
        assert!(!DevDocsError::TrafficAnalysis("test".to_string()).is_retryable());
        assert!(!DevDocsError::BodyTooLarge { size: 100, limit: 50 }.is_retryable());
    }

    #[test]
    fn test_all_error_codes_unique() {
        let errors = vec![
            DevDocsError::Config("".to_string()),
            DevDocsError::InvalidRequest("".to_string()),
            DevDocsError::BodyTooLarge { size: 0, limit: 0 },
            DevDocsError::AiProcessing("".to_string()),
            DevDocsError::RateLimit("".to_string()),
            DevDocsError::Authentication("".to_string()),
            DevDocsError::Timeout("".to_string()),
            DevDocsError::SchemaInference("".to_string()),
            DevDocsError::TrafficAnalysis("".to_string()),
        ];
        
        let mut codes = std::collections::HashSet::new();
        for error in errors {
            let code = error.error_code();
            assert!(codes.insert(code), "Duplicate error code: {}", code);
        }
    }
}
