//! DevDocs Pro Middleware
//!
//! Framework-agnostic HTTP middleware for capturing API traffic and generating documentation

pub mod ai_processor;
pub mod correlation;
pub mod interceptor;
pub mod processor;

pub use ai_processor::{AIProcessorService, DocumentationUpdate};
pub use correlation::CorrelationTracker;
pub use interceptor::{DevDocsLayer, HttpInterceptor};
pub use processor::TrafficProcessor;

use devdocs_core::{
    analysis::AnalysisConfig, documentation::DocumentationConfig, Config, TrafficSample,
};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Main entry point for the DevDocs middleware
pub struct DevDocsMiddleware {
    pub config: Arc<Config>,
    pub sample_receiver: mpsc::UnboundedReceiver<TrafficSample>,
    pub correlation_tracker: CorrelationTracker,
    pub traffic_processor: TrafficProcessor,
}

impl DevDocsMiddleware {
    pub fn new(config: Config) -> Result<(DevDocsLayer, Self), devdocs_core::DevDocsError> {
        let (layer, sample_receiver) = DevDocsLayer::new(config.clone());

        let correlation_tracker = CorrelationTracker::new(
            std::time::Duration::from_secs(60),  // cleanup every minute
            std::time::Duration::from_secs(300), // 5 minute timeout
        );

        // Create analysis configuration
        let analysis_config = AnalysisConfig {
            schema_inference_enabled: true,
            min_samples_for_inference: config.min_samples_for_inference.unwrap_or(5),
            ai_documentation_enabled: config.gemini_api_key.is_some(),
            confidence_threshold: 0.8,
            max_body_size: config.max_body_size.unwrap_or(10 * 1024 * 1024),
            endpoint_detection_enabled: true,
        };

        // Create documentation configuration
        let doc_config = DocumentationConfig {
            title: config
                .api_title
                .clone()
                .unwrap_or_else(|| "API Documentation".to_string()),
            version: config
                .api_version
                .clone()
                .unwrap_or_else(|| "1.0.0".to_string()),
            description: config.api_description.clone(),
            base_url: config.base_url.clone(),
            contact: None, // TODO: Add contact info to config
            license: None, // TODO: Add license info to config
            enable_interactive: true,
            enable_realtime_updates: true,
            custom_css: None,
            logo_url: None,
        };

        // Create traffic processor
        let traffic_processor = TrafficProcessor::new(analysis_config, doc_config)?;

        let middleware = Self {
            config: Arc::new(config),
            sample_receiver,
            correlation_tracker,
            traffic_processor,
        };

        Ok((layer, middleware))
    }

    pub async fn start_processing(&mut self) -> Result<(), devdocs_core::DevDocsError> {
        self.correlation_tracker.start_cleanup_task();

        tracing::info!("Starting DevDocs Pro middleware processing");

        // Process samples
        while let Some(sample) = self.sample_receiver.recv().await {
            if let Err(e) = self.process_sample(sample).await {
                tracing::error!("Failed to process sample: {}", e);
            }
        }

        Ok(())
    }

    async fn process_sample(
        &mut self,
        sample: TrafficSample,
    ) -> Result<(), devdocs_core::DevDocsError> {
        tracing::debug!(
            endpoint = %sample.endpoint_pattern,
            method = %sample.request.method,
            status = ?sample.response.as_ref().map(|r| r.status_code),
            "Processing traffic sample"
        );

        // Add sample to processor
        self.traffic_processor.add_sample(sample).await?;

        // Check if we should trigger analysis
        if self.traffic_processor.should_analyze() {
            tracing::info!("Triggering traffic analysis and documentation generation");

            match self.traffic_processor.analyze_and_generate_docs().await {
                Ok(documentation) => {
                    tracing::info!(
                        "Generated documentation with {} endpoints",
                        documentation
                            .openapi_spec
                            .get("paths")
                            .and_then(|p| p.as_object())
                            .map(|o| o.len())
                            .unwrap_or(0)
                    );

                    // TODO: Save or serve the generated documentation
                    // This could be saved to a file, served via HTTP, or sent to a documentation service
                }
                Err(e) => {
                    tracing::error!("Failed to generate documentation: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Get current statistics
    pub fn get_stats(&self) -> MiddlewareStats {
        MiddlewareStats {
            samples_processed: self.traffic_processor.sample_count(),
            endpoints_discovered: self.traffic_processor.endpoint_count(),
            schemas_inferred: self.traffic_processor.schema_count(),
            last_analysis: self.traffic_processor.last_analysis_time(),
        }
    }
}

/// Middleware statistics
#[derive(Debug, Clone)]
pub struct MiddlewareStats {
    pub samples_processed: usize,
    pub endpoints_discovered: usize,
    pub schemas_inferred: usize,
    pub last_analysis: Option<chrono::DateTime<chrono::Utc>>,
}

// Re-export core types for convenience
pub use devdocs_core::{DevDocsError, HttpRequest, HttpResponse};
