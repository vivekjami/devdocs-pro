//! Traffic analysis pipeline for AI-powered documentation generation

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::ai::gemini_client::{GeminiClient, GeminiPrompt};
use crate::analysis::schema_inference::{SchemaInferrer, JsonSchema};
use crate::models::TrafficSample;
use crate::errors::{DevDocsError, Result};

pub struct TrafficAnalyzer {
    gemini_client: GeminiClient,
    schema_inferrer: SchemaInferrer,
}

impl TrafficAnalyzer {
    pub fn new(gemini_client: GeminiClient) -> Self {
        Self {
            gemini_client,
            schema_inferrer: SchemaInferrer::new(),
        }
    }
    
    pub async fn analyze_endpoint_samples(&mut self, samples: &[TrafficSample]) -> Result<EndpointAnalysis> {
        if samples.is_empty() {
            return Err(DevDocsError::InvalidRequest("No samples to analyze".into()));
        }
        
        // Group samples by endpoint pattern
        let grouped = self.group_by_endpoint(samples);
        
        let mut results = Vec::new();
        
        // Process each endpoint
        for (endpoint, endpoint_samples) in grouped {
            tracing::info!("Analyzing endpoint: {} with {} samples", endpoint, endpoint_samples.len());
            
            // Extract method (GET, POST, etc.)
            let method = self.extract_common_method(&endpoint_samples);
            
            // Extract request bodies for schema inference
            let request_bodies: Vec<_> = endpoint_samples.iter()
                .filter_map(|s| s.request.body.as_ref())
                .collect();
                
            // Extract response bodies for schema inference
            let response_bodies: Vec<_> = endpoint_samples.iter()
                .filter_map(|s| s.response.as_ref())
                .filter_map(|r| r.body.as_ref())
                .collect();
                
            // Infer schemas from bodies
            let request_schema = if !request_bodies.is_empty() {
                self.schema_inferrer.infer_from_json_bodies(&request_bodies).await.ok()
            } else {
                None
            };
            
            let response_schema = if !response_bodies.is_empty() {
                self.schema_inferrer.infer_from_json_bodies(&response_bodies).await.ok()
            } else {
                None
            };
            
            // Create AI prompt for this endpoint
            let prompt = GeminiPrompt::for_endpoint_analysis(
                &endpoint, 
                &method, 
                &endpoint_samples
            );
            
            // Send to Gemini for analysis
            match self.gemini_client.generate_content(&prompt).await {
                Ok(ai_response) => {
                    // Extract documentation from AI response
                    let documentation = self.extract_documentation(ai_response)?;
                    
                    results.push(EndpointDocumentation {
                        endpoint: endpoint.clone(),
                        method: method.clone(),
                        documentation,
                        request_schema,
                        response_schema,
                        sample_count: endpoint_samples.len(),
                        traffic_patterns: self.analyze_traffic_patterns(&endpoint_samples),
                    });
                    
                    tracing::info!("Successfully analyzed endpoint: {} {}", method, endpoint);
                }
                Err(e) => {
                    tracing::error!("Failed to analyze endpoint {} {}: {}", method, endpoint, e);
                    
                    // Create fallback documentation
                    results.push(EndpointDocumentation {
                        endpoint: endpoint.clone(),
                        method: method.clone(),
                        documentation: AIDocumentation::fallback(&endpoint, &method),
                        request_schema,
                        response_schema,
                        sample_count: endpoint_samples.len(),
                        traffic_patterns: self.analyze_traffic_patterns(&endpoint_samples),
                    });
                }
            }
        }
        
        Ok(EndpointAnalysis { 
            endpoints: results,
            total_samples: samples.len(),
            analysis_timestamp: chrono::Utc::now(),
        })
    }
    
    fn group_by_endpoint(&self, samples: &[TrafficSample]) -> HashMap<String, Vec<TrafficSample>> {
        let mut grouped = HashMap::new();
        
        for sample in samples {
            let key = sample.endpoint_pattern.clone();
            grouped.entry(key).or_insert_with(Vec::new).push(sample.clone());
        }
        
        grouped
    }
    
    fn extract_common_method(&self, samples: &[TrafficSample]) -> String {
        // Find the most common method in the samples
        let mut method_counts = HashMap::new();
        
        for sample in samples {
            *method_counts.entry(sample.request.method.clone()).or_insert(0) += 1;
        }
        
        method_counts.into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(method, _)| method)
            .unwrap_or_else(|| "GET".to_string())
    }
    
    fn extract_documentation(&self, ai_response: crate::ai::gemini_client::GeminiResponse) -> Result<AIDocumentation> {
        let text = ai_response.get_text()
            .ok_or_else(|| DevDocsError::InvalidRequest("No text in AI response".into()))?;
        
        // Try to parse as JSON first
        if let Ok(doc) = serde_json::from_str::<AIDocumentation>(&text) {
            return Ok(doc);
        }
        
        // Fallback: extract from markdown format
        Ok(AIDocumentation::from_markdown(&text))
    }
    
    fn analyze_traffic_patterns(&self, samples: &[TrafficSample]) -> TrafficPatterns {
        let mut status_codes = HashMap::new();
        let mut response_times = Vec::new();
        let mut error_count = 0;
        
        for sample in samples {
            if let Some(response) = &sample.response {
                *status_codes.entry(response.status_code).or_insert(0) += 1;
                response_times.push(response.processing_time_ms);
                
                if response.status_code >= 400 {
                    error_count += 1;
                }
            }
        }
        
        // Calculate response time statistics
        response_times.sort_unstable();
        let avg_response_time = response_times.iter().sum::<u64>() / response_times.len() as u64;
        let median_response_time = response_times.get(response_times.len() / 2).copied().unwrap_or(0);
        
        TrafficPatterns {
            request_count: samples.len(),
            status_code_distribution: status_codes,
            avg_response_time_ms: avg_response_time,
            median_response_time_ms: median_response_time,
            error_rate: error_count as f64 / samples.len() as f64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointAnalysis {
    pub endpoints: Vec<EndpointDocumentation>,
    pub total_samples: usize,
    pub analysis_timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointDocumentation {
    pub endpoint: String,
    pub method: String,
    pub documentation: AIDocumentation,
    pub request_schema: Option<JsonSchema>,
    pub response_schema: Option<JsonSchema>,
    pub sample_count: usize,
    pub traffic_patterns: TrafficPatterns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIDocumentation {
    pub description: String,
    pub parameters: HashMap<String, String>,
    pub request_format: String,
    pub response_format: String,
    pub error_scenarios: Vec<String>,
    pub examples: Vec<String>,
    pub confidence_score: f64,
}

impl AIDocumentation {
    pub fn fallback(endpoint: &str, method: &str) -> Self {
        Self {
            description: format!("{} endpoint for {}", method, endpoint),
            parameters: HashMap::new(),
            request_format: "Request format not analyzed".to_string(),
            response_format: "Response format not analyzed".to_string(),
            error_scenarios: vec!["Analysis failed - manual documentation needed".to_string()],
            examples: Vec::new(),
            confidence_score: 0.0,
        }
    }
    
    pub fn from_markdown(text: &str) -> Self {
        // Simple extraction from markdown - in production would be more robust
        Self {
            description: Self::extract_section(text, "Purpose").unwrap_or_else(|| 
                "AI-generated documentation parsing failed".to_string()),
            parameters: HashMap::new(), // Would parse from markdown
            request_format: Self::extract_section(text, "Request Format").unwrap_or_default(),
            response_format: Self::extract_section(text, "Response Format").unwrap_or_default(),
            error_scenarios: Vec::new(), // Would parse from markdown
            examples: Vec::new(), // Would parse from markdown
            confidence_score: 0.5, // Lower confidence for fallback parsing
        }
    }
    
    fn extract_section(text: &str, section: &str) -> Option<String> {
        // Simple section extraction - would be more sophisticated in production
        let result = text.lines()
            .skip_while(|line| !line.contains(section))
            .skip(1)
            .take_while(|line| !line.starts_with('#'))
            .map(|line| line.trim())
            .collect::<Vec<_>>()
            .join(" ");
            
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPatterns {
    pub request_count: usize,
    pub status_code_distribution: HashMap<u16, usize>,
    pub avg_response_time_ms: u64,
    pub median_response_time_ms: u64,
    pub error_rate: f64,
}
