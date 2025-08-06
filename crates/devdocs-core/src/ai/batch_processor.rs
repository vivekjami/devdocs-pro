//! Batch processing system for optimizing AI API usage

use crate::ai::gemini_client::{GeminiClient, GeminiPrompt, PromptType};
use crate::ai::prompts::EndpointSummary;
use crate::analysis::traffic_analyzer::{AIDocumentation, EndpointDocumentation};
use crate::errors::{DevDocsError, Result};
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, Instant};

pub struct AIBatchProcessor {
    gemini_client: GeminiClient,
    max_batch_size: usize,
    rate_limit_delay: Duration,
    last_batch_time: Option<Instant>,
}

impl AIBatchProcessor {
    pub fn new(gemini_client: GeminiClient) -> Self {
        Self {
            gemini_client,
            max_batch_size: 5, // Process up to 5 endpoints at once
            rate_limit_delay: Duration::from_secs(1),
            last_batch_time: None,
        }
    }

    pub async fn process_endpoints_batch(
        &mut self,
        requests: Vec<EndpointAnalysisRequest>,
    ) -> Result<Vec<GeneratedDocumentation>> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();

        // Process endpoints in batches to optimize API usage
        for batch in requests.chunks(self.max_batch_size) {
            // Rate limiting between batches
            if let Some(last_time) = self.last_batch_time {
                let elapsed = last_time.elapsed();
                if elapsed < self.rate_limit_delay {
                    tokio::time::sleep(self.rate_limit_delay - elapsed).await;
                }
            }

            tracing::info!("Processing batch of {} endpoints", batch.len());

            // Create optimized batch prompt
            let batch_prompt = self.create_batch_prompt(batch)?;

            // Send to Gemini
            match self.gemini_client.generate_content(&batch_prompt).await {
                Ok(ai_response) => {
                    // Parse the batch response
                    let batch_results = self.parse_batch_response(ai_response, batch)?;
                    results.extend(batch_results);

                    tracing::info!("Successfully processed batch of {} endpoints", batch.len());
                }
                Err(e) => {
                    tracing::error!("Batch processing failed: {}", e);

                    // Create fallback documentation for failed batch
                    for request in batch {
                        results.push(GeneratedDocumentation {
                            endpoint_id: request.id.clone(),
                            documentation: AIDocumentation::fallback(
                                &request.path,
                                &request.method,
                            ),
                            processing_time_ms: 0,
                            success: false,
                        });
                    }
                }
            }

            self.last_batch_time = Some(Instant::now());
        }

        Ok(results)
    }

    fn create_batch_prompt(&self, batch: &[EndpointAnalysisRequest]) -> Result<GeminiPrompt> {
        let endpoints_summary: Vec<EndpointSummary> = batch
            .iter()
            .map(|req| EndpointSummary {
                method: req.method.clone(),
                path: req.path.clone(),
                sample_count: req.sample_count,
                request_schema: req.request_schema.clone(),
                response_examples: req.response_examples.clone(),
            })
            .collect();

        Ok(GeminiPrompt::for_batch_analysis(&endpoints_summary))
    }

    fn parse_batch_response(
        &self,
        ai_response: crate::ai::gemini_client::GeminiResponse,
        batch: &[EndpointAnalysisRequest],
    ) -> Result<Vec<GeneratedDocumentation>> {
        let text = ai_response
            .get_text()
            .ok_or_else(|| DevDocsError::InvalidRequest("No text in AI response".into()))?;

        // Try to parse as JSON array
        match serde_json::from_str::<Vec<AIDocumentation>>(&text) {
            Ok(docs) => {
                // Match docs with original requests
                let mut results = Vec::new();
                for (i, doc) in docs.into_iter().enumerate() {
                    if let Some(request) = batch.get(i) {
                        results.push(GeneratedDocumentation {
                            endpoint_id: request.id.clone(),
                            documentation: doc,
                            processing_time_ms: 0, // Would track actual time in production
                            success: true,
                        });
                    }
                }
                Ok(results)
            }
            Err(_) => {
                // Fallback: try to parse individual sections
                tracing::warn!("Failed to parse batch response as JSON, using fallback parsing");

                let mut results = Vec::new();
                for request in batch {
                    results.push(GeneratedDocumentation {
                        endpoint_id: request.id.clone(),
                        documentation: AIDocumentation::from_markdown(&text),
                        processing_time_ms: 0,
                        success: false,
                    });
                }
                Ok(results)
            }
        }
    }

    pub async fn process_single_endpoint(
        &mut self,
        request: EndpointAnalysisRequest,
    ) -> Result<GeneratedDocumentation> {
        let start_time = Instant::now();

        // Create single endpoint prompt (more detailed than batch)
        let prompt = GeminiPrompt {
            prompt_type: PromptType::EndpointAnalysis,
            content: format!(
                "Analyze this API endpoint in detail:\n\n\
                 Method: {}\n\
                 Path: {}\n\
                 Samples: {}\n\
                 Request Schema: {}\n\
                 Response Examples: {}\n\n\
                 Generate comprehensive documentation including purpose, parameters, \
                 request/response formats, error scenarios, and usage examples.\n\n\
                 Format as JSON with fields: description, parameters, request_format, \
                 response_format, error_scenarios, examples",
                request.method,
                request.path,
                request.sample_count,
                request.request_schema.as_deref().unwrap_or("None"),
                request.response_examples.join("; ")
            ),
            temperature: 0.2,
            max_tokens: 1500,
        };

        match self.gemini_client.generate_content(&prompt).await {
            Ok(ai_response) => {
                let text = ai_response
                    .get_text()
                    .ok_or_else(|| DevDocsError::InvalidRequest("No text in AI response".into()))?;

                let documentation = if let Ok(doc) = serde_json::from_str::<AIDocumentation>(&text)
                {
                    doc
                } else {
                    AIDocumentation::from_markdown(&text)
                };

                Ok(GeneratedDocumentation {
                    endpoint_id: request.id,
                    documentation,
                    processing_time_ms: start_time.elapsed().as_millis() as u64,
                    success: true,
                })
            }
            Err(e) => {
                tracing::error!("Single endpoint processing failed: {}", e);

                Ok(GeneratedDocumentation {
                    endpoint_id: request.id.clone(),
                    documentation: AIDocumentation::fallback(&request.path, &request.method),
                    processing_time_ms: start_time.elapsed().as_millis() as u64,
                    success: false,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointAnalysisRequest {
    pub id: String,
    pub method: String,
    pub path: String,
    pub sample_count: usize,
    pub request_schema: Option<String>,
    pub response_examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedDocumentation {
    pub endpoint_id: String,
    pub documentation: AIDocumentation,
    pub processing_time_ms: u64,
    pub success: bool,
}

impl From<&EndpointDocumentation> for EndpointAnalysisRequest {
    fn from(doc: &EndpointDocumentation) -> Self {
        Self {
            id: format!("{}:{}", doc.method, doc.endpoint),
            method: doc.method.clone(),
            path: doc.endpoint.clone(),
            sample_count: doc.sample_count,
            request_schema: doc
                .request_schema
                .as_ref()
                .map(|schema| serde_json::to_string(schema).unwrap_or_default()),
            response_examples: vec!["Example not available".to_string()], // Would extract real examples
        }
    }
}
