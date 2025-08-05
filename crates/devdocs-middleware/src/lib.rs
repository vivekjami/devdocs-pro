//! DevDocs Pro Middleware
//! 
//! Framework-agnostic HTTP middleware for capturing API traffic

pub mod interceptor;
pub mod correlation;

pub use interceptor::{HttpInterceptor, DevDocsLayer};
pub use correlation::CorrelationTracker;

use devdocs_core::{Config, TrafficSample};
use tokio::sync::mpsc;
use std::sync::Arc;

/// Main entry point for the DevDocs middleware
pub struct DevDocsMiddleware {
    pub config: Arc<Config>,
    pub sample_receiver: mpsc::UnboundedReceiver<TrafficSample>,
    pub correlation_tracker: CorrelationTracker,
}

impl DevDocsMiddleware {
    pub fn new(config: Config) -> (DevDocsLayer, Self) {
        let (layer, sample_receiver) = DevDocsLayer::new(config.clone());
        
        let correlation_tracker = CorrelationTracker::new(
            std::time::Duration::from_secs(60), // cleanup every minute
            std::time::Duration::from_secs(300), // 5 minute timeout
        );
        
        let middleware = Self {
            config: Arc::new(config),
            sample_receiver,
            correlation_tracker,
        };
        
        (layer, middleware)
    }

    pub async fn start_processing(&mut self) {
        self.correlation_tracker.start_cleanup_task();
        
        while let Some(sample) = self.sample_receiver.recv().await {
            self.process_sample(sample).await;
        }
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
pub use devdocs_core::{HttpRequest, HttpResponse, DevDocsError};
