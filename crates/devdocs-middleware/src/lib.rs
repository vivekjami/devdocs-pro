//! DevDocs Pro Middleware
//!
//! Framework-agnostic HTTP middleware for capturing API traffic

pub mod ai_processor;
pub mod correlation;
pub mod interceptor;

pub use ai_processor::{AIProcessorService, DocumentationUpdate};
pub use correlation::CorrelationTracker;
pub use interceptor::{DevDocsLayer, HttpInterceptor};

use devdocs_core::{Config, TrafficSample};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Main entry point for the DevDocs middleware
pub struct DevDocsMiddleware {
    pub config: Arc<Config>,
    pub sample_receiver: mpsc::UnboundedReceiver<TrafficSample>,
    pub correlation_tracker: CorrelationTracker,
    pub ai_processor: Option<AIProcessorService>,
}

impl DevDocsMiddleware {
    pub fn new(config: Config) -> (DevDocsLayer, Self) {
        let (layer, sample_receiver) = DevDocsLayer::new(config.clone());

        let correlation_tracker = CorrelationTracker::new(
            std::time::Duration::from_secs(60),  // cleanup every minute
            std::time::Duration::from_secs(300), // 5 minute timeout
        );

        // Create AI processor if Gemini API key is configured
        let ai_processor = config.gemini_api_key.clone().map(|api_key| {
            // Create a separate channel for AI processing
            let (_ai_sender, ai_receiver) = mpsc::unbounded_channel();
            AIProcessorService::new(ai_receiver, api_key)
        });

        let middleware = Self {
            config: Arc::new(config),
            sample_receiver,
            correlation_tracker,
            ai_processor,
        };

        (layer, middleware)
    }

    pub async fn start_processing(&mut self) {
        self.correlation_tracker.start_cleanup_task();

        // Start AI processor if available
        if let Some(mut ai_processor) = self.ai_processor.take() {
            tokio::spawn(async move {
                ai_processor.start_processing().await;
            });

            // Process samples with AI analysis
            while let Some(sample) = self.sample_receiver.recv().await {
                self.process_sample_with_ai(sample).await;
            }
        } else {
            // Process samples without AI
            while let Some(sample) = self.sample_receiver.recv().await {
                self.process_sample(sample).await;
            }
        }
    }

    async fn process_sample_with_ai(&self, sample: TrafficSample) {
        tracing::info!(
            endpoint = %sample.endpoint_pattern,
            method = %sample.request.method,
            status = ?sample.response.as_ref().map(|r| r.status_code),
            "Processing traffic sample with AI analysis"
        );

        // Forward sample to AI processor
        // Note: In a real implementation, we'd need to properly wire the channels
        // For now, we'll log that AI processing would happen here
        tracing::debug!("Sample forwarded to AI processor for documentation generation");
    }

    async fn process_sample(&self, sample: TrafficSample) {
        tracing::info!(
            endpoint = %sample.endpoint_pattern,
            method = %sample.request.method,
            status = ?sample.response.as_ref().map(|r| r.status_code),
            "Processing traffic sample"
        );

        // TODO: Add actual processing logic
        // This will be expanded in later days with:
        // - Schema inference
        // - AI analysis
        // - Documentation generation
    }
}

// Re-export core types for convenience
pub use devdocs_core::{DevDocsError, HttpRequest, HttpResponse};
