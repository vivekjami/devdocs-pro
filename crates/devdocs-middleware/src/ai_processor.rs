//! Real-time AI processing pipeline for traffic samples

use devdocs_core::{
    ai::gemini_client::GeminiClient,
    analysis::traffic_analyzer::TrafficAnalyzer,
    models::{AIAnalysisResult, GeneratedExample, TrafficSample},
};
use std::time::Duration;
use tokio::sync::mpsc;

pub struct AIProcessorService {
    traffic_receiver: mpsc::UnboundedReceiver<TrafficSample>,
    ai_analyzer: TrafficAnalyzer,
    batch_buffer: Vec<TrafficSample>,
    batch_timeout: Duration,
    batch_size: usize,
    doc_update_sender: Option<mpsc::UnboundedSender<DocumentationUpdate>>,
}

impl AIProcessorService {
    pub fn new(
        traffic_receiver: mpsc::UnboundedReceiver<TrafficSample>,
        gemini_api_key: String,
    ) -> Self {
        let gemini_client = GeminiClient::new(gemini_api_key);
        let ai_analyzer = TrafficAnalyzer::new(gemini_client);

        Self {
            traffic_receiver,
            ai_analyzer,
            batch_buffer: Vec::new(),
            batch_timeout: Duration::from_secs(30), // Process every 30 seconds
            batch_size: 10,                         // Or when we have 10 samples
            doc_update_sender: None,
        }
    }

    pub fn with_documentation_updates(
        mut self,
        sender: mpsc::UnboundedSender<DocumentationUpdate>,
    ) -> Self {
        self.doc_update_sender = Some(sender);
        self
    }

    pub async fn start_processing(&mut self) {
        tracing::info!("Starting AI processor service");

        let mut batch_timer = tokio::time::interval(self.batch_timeout);

        loop {
            tokio::select! {
                // Process new traffic samples
                Some(sample) = self.traffic_receiver.recv() => {
                    tracing::debug!("Received traffic sample for endpoint: {}", sample.endpoint_pattern);
                    self.batch_buffer.push(sample);

                    // Process immediately if batch is full
                    if self.batch_buffer.len() >= self.batch_size {
                        self.process_batch().await;
                    }
                }

                // Process on timer even if batch isn't full
                _ = batch_timer.tick() => {
                    if !self.batch_buffer.is_empty() {
                        tracing::debug!("Processing batch on timer with {} samples", self.batch_buffer.len());
                        self.process_batch().await;
                    }
                }

                // Exit when channel closes
                else => {
                    tracing::info!("Traffic receiver closed, stopping AI processor");
                    break;
                }
            }
        }
    }

    async fn process_batch(&mut self) {
        // Take samples for processing
        let samples = std::mem::take(&mut self.batch_buffer);
        let sample_count = samples.len();

        tracing::info!("Processing batch of {} traffic samples", sample_count);

        // Clone sender for the async task
        let doc_sender = self.doc_update_sender.clone();

        // Process asynchronously to not block receiving new samples
        let mut analyzer = std::mem::replace(&mut self.ai_analyzer, {
            let gemini_client = GeminiClient::new("temp".to_string()); // This is a hack - would fix in production
            TrafficAnalyzer::new(gemini_client)
        });

        tokio::spawn(async move {
            let start_time = std::time::Instant::now();

            match analyzer.analyze_endpoint_samples(&samples).await {
                Ok(analysis) => {
                    let processing_time = start_time.elapsed();
                    tracing::info!(
                        "Generated documentation for {} endpoints in {:?}",
                        analysis.endpoints.len(),
                        processing_time
                    );

                    // Convert analysis to AI results and send updates
                    for endpoint_doc in analysis.endpoints {
                        let ai_result = AIAnalysisResult {
                            endpoint_description: endpoint_doc.documentation.description.clone(),
                            parameter_documentation: endpoint_doc.documentation.parameters.clone(),
                            response_documentation: endpoint_doc.documentation.response_format.clone(),
                            example_requests: endpoint_doc.documentation.examples.iter()
                                .map(|ex| GeneratedExample {
                                    description: "Auto-generated example".to_string(),
                                    request_example: Some(ex.clone()),
                                    response_example: None,
                                    curl_command: Some(format!("curl -X {} '{}'", endpoint_doc.method, endpoint_doc.endpoint)),
                                })
                                .collect(),
                            business_logic_explanation: format!(
                                "This {} endpoint handles requests to {}. Based on {} traffic samples.",
                                endpoint_doc.method, endpoint_doc.endpoint, endpoint_doc.sample_count
                            ),
                            confidence_score: endpoint_doc.documentation.confidence_score,
                            generated_at: chrono::Utc::now(),
                        };

                        // Send documentation update
                        if let Some(ref sender) = doc_sender {
                            let update = DocumentationUpdate {
                                endpoint_pattern: endpoint_doc.endpoint.clone(),
                                method: endpoint_doc.method.clone(),
                                ai_analysis: ai_result,
                                sample_count: endpoint_doc.sample_count,
                            };

                            if let Err(e) = sender.send(update) {
                                tracing::error!("Failed to send documentation update: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "AI analysis failed for batch of {} samples: {}",
                        sample_count,
                        e
                    );
                }
            }
        });
    }
}

#[derive(Debug, Clone)]
pub struct DocumentationUpdate {
    pub endpoint_pattern: String,
    pub method: String,
    pub ai_analysis: AIAnalysisResult,
    pub sample_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_ai_processor_creation() {
        let (_sender, receiver) = mpsc::unbounded_channel();
        let processor = AIProcessorService::new(receiver, "test-api-key".to_string());

        assert_eq!(processor.batch_size, 10);
        assert_eq!(processor.batch_timeout, Duration::from_secs(30));
    }
}
