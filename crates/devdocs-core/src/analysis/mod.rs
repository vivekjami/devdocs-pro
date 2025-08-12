//! Traffic analysis and schema inference engine
//!
//! This module provides comprehensive analysis of HTTP traffic to automatically
//! generate API documentation from real requests and responses.

pub mod ai_processor;
pub mod endpoint_detector;
pub mod schema_inference;
pub mod traffic_analyzer;

use crate::errors::DevDocsError;
use crate::models::{ApiEndpoint, TrafficSample};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Configuration for traffic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Enable schema inference from traffic
    pub schema_inference_enabled: bool,
    /// Minimum samples required for schema inference
    pub min_samples_for_inference: usize,
    /// Enable AI-powered documentation generation
    pub ai_documentation_enabled: bool,
    /// Confidence threshold for schema inference (0.0-1.0)
    pub confidence_threshold: f64,
    /// Maximum request body size to analyze (bytes)
    pub max_body_size: usize,
    /// Enable endpoint pattern detection
    pub endpoint_detection_enabled: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            schema_inference_enabled: true,
            min_samples_for_inference: 5,
            ai_documentation_enabled: true,
            confidence_threshold: 0.8,
            max_body_size: 10 * 1024 * 1024, // 10MB
            endpoint_detection_enabled: true,
        }
    }
}

/// Result of traffic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Unique identifier for this analysis
    pub id: Uuid,
    /// Detected API endpoints
    pub endpoints: Vec<ApiEndpoint>,
    /// Inferred schemas
    pub schemas: HashMap<String, serde_json::Value>,
    /// AI-generated documentation
    pub documentation: Option<String>,
    /// Analysis confidence score (0.0-1.0)
    pub confidence: f64,
    /// Number of samples analyzed
    pub samples_analyzed: usize,
    /// Analysis timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Main traffic analyzer
pub struct TrafficAnalyzer {
    config: AnalysisConfig,
    schema_inferrer: schema_inference::SchemaInferrer,
    endpoint_detector: endpoint_detector::EndpointDetector,
    ai_processor: ai_processor::AiProcessor,
}

impl TrafficAnalyzer {
    /// Create a new traffic analyzer
    pub fn new(config: AnalysisConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            schema_inferrer: schema_inference::SchemaInferrer::new(&config)?,
            endpoint_detector: endpoint_detector::EndpointDetector::new(&config)?,
            ai_processor: ai_processor::AiProcessor::new(&config)?,
            config,
        })
    }

    /// Analyze a batch of traffic samples
    pub async fn analyze_traffic(
        &mut self,
        samples: Vec<TrafficSample>,
    ) -> Result<AnalysisResult, DevDocsError> {
        if samples.len() < self.config.min_samples_for_inference {
            return Err(DevDocsError::InvalidRequest(format!(
                "Insufficient samples for analysis. Need at least {}, got {}",
                self.config.min_samples_for_inference,
                samples.len()
            )));
        }

        let analysis_id = Uuid::new_v4();
        tracing::info!("Starting traffic analysis with {} samples", samples.len());

        // Step 1: Detect endpoints and group requests
        let endpoints = if self.config.endpoint_detection_enabled {
            self.endpoint_detector.detect_endpoints(&samples).await?
        } else {
            Vec::new()
        };

        // Step 2: Infer schemas from request/response data
        let schemas = if self.config.schema_inference_enabled {
            self.schema_inferrer.infer_schemas(&samples).await?
        } else {
            HashMap::new()
        };

        // Step 3: Generate AI-powered documentation
        let documentation = if self.config.ai_documentation_enabled {
            Some(
                self.ai_processor
                    .generate_documentation(&endpoints, &schemas)
                    .await?,
            )
        } else {
            None
        };

        // Calculate overall confidence based on sample size and consistency
        let confidence = self.calculate_confidence(&samples, &endpoints, &schemas);

        Ok(AnalysisResult {
            id: analysis_id,
            endpoints,
            schemas,
            documentation,
            confidence,
            samples_analyzed: samples.len(),
            timestamp: chrono::Utc::now(),
        })
    }

    /// Calculate confidence score for the analysis
    fn calculate_confidence(
        &self,
        samples: &[TrafficSample],
        endpoints: &[ApiEndpoint],
        schemas: &HashMap<String, serde_json::Value>,
    ) -> f64 {
        let sample_factor = (samples.len() as f64 / 100.0).min(1.0);
        let endpoint_factor = if endpoints.is_empty() { 0.0 } else { 0.8 };
        let schema_factor = if schemas.is_empty() { 0.0 } else { 0.9 };

        (sample_factor + endpoint_factor + schema_factor) / 3.0
    }

    /// Get analysis configuration
    pub fn config(&self) -> &AnalysisConfig {
        &self.config
    }

    /// Update analysis configuration
    pub fn update_config(&mut self, config: AnalysisConfig) -> Result<(), DevDocsError> {
        self.config = config;
        self.schema_inferrer.update_config(&self.config)?;
        self.endpoint_detector.update_config(&self.config)?;
        self.ai_processor.update_config(&self.config)?;
        Ok(())
    }
}

pub use ai_processor::AiProcessor;
pub use endpoint_detector::EndpointDetector;
pub use schema_inference::{FieldInfo, FieldType, SchemaInferrer, ValidationConstraints};
pub use traffic_analyzer::{EndpointAnalysis, EndpointDocumentation};
