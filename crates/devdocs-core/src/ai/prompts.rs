//! Prompt engineering framework for API documentation generation

use crate::ai::gemini_client::{GeminiPrompt, PromptType};
use crate::models::TrafficSample;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

impl GeminiPrompt {
    pub fn for_endpoint_analysis(endpoint: &str, method: &str, samples: &[TrafficSample]) -> Self {
        // Extract request examples
        let request_examples = Self::extract_request_examples(samples, 2);

        // Extract response examples
        let response_examples = Self::extract_response_examples(samples, 2);

        // Analyze status codes
        let status_codes = Self::analyze_status_codes(samples);

        // Build rich context prompt
        let content = format!(
            "You are an expert API documentation writer. Analyze this API endpoint based on real production traffic data:\n\n\
             **Endpoint Details:**\n\
             - Method: {}\n\
             - Path: {}\n\
             - Traffic Samples: {} requests\n\n\
             **Request Examples:**\n{}\n\n\
             **Response Examples:**\n{}\n\n\
             **Status Code Distribution:**\n{}\n\n\
             **Task:** Generate comprehensive API documentation that includes:\n\n\
             1. **Purpose**: A clear, concise description of what this endpoint does\n\
             2. **Parameters**: Detailed descriptions of all parameters with types and validation rules\n\
             3. **Request Format**: Structure and examples of valid requests\n\
             4. **Response Format**: Structure and examples of successful responses\n\
             5. **Error Scenarios**: Common error cases and their meanings\n\
             6. **Usage Examples**: Practical code examples showing how to use this endpoint\n\n\
             **Guidelines:**\n\
             - Use clear, developer-friendly language\n\
             - Include specific data types and validation rules\n\
             - Provide realistic examples based on the actual traffic data\n\
             - Focus on practical developer experience\n\
             - Format your response as structured markdown\n\n\
             **Response Format:**\n\
             Format your response as a JSON object with these fields:\n\
             ```json\n\
             {{\n\
               \"description\": \"Clear description of endpoint purpose\",\n\
               \"parameters\": {{\"param_name\": \"description with type info\"}},\n\
               \"request_format\": \"Description of request structure\",\n\
               \"response_format\": \"Description of response structure\",\n\
               \"error_scenarios\": [\"list of common error cases\"],\n\
               \"examples\": [\"practical usage examples\"]\n\
             }}\n\
             ```",
            method, endpoint, samples.len(), request_examples, response_examples, status_codes
        );

        Self {
            prompt_type: PromptType::EndpointAnalysis,
            content,
            temperature: 0.2, // Low temperature for consistent documentation
            max_tokens: 2048,
        }
    }

    pub fn for_schema_inference(json_samples: &[String]) -> Self {
        let samples_text = json_samples
            .iter()
            .enumerate()
            .map(|(i, sample)| format!("Sample {}:\n{}\n", i + 1, sample))
            .collect::<Vec<_>>()
            .join("\n");

        let content = format!(
            "Analyze these JSON samples and generate a comprehensive JSON schema:\n\n\
             {samples_text}\n\n\
             Generate a JSON Schema that describes the structure, including:\n\
             1. Data types for all fields\n\
             2. Required vs optional fields\n\
             3. Validation constraints (min/max, patterns, etc.)\n\
             4. Field descriptions based on usage patterns\n\
             5. Enum values where applicable\n\n\
             Format your response as a valid JSON Schema object."
        );

        Self {
            prompt_type: PromptType::SchemaInference,
            content,
            temperature: 0.1, // Very low temperature for schema consistency
            max_tokens: 1500,
        }
    }

    pub fn for_batch_analysis(endpoints: &[EndpointSummary]) -> Self {
        let endpoints_text = endpoints
            .iter()
            .map(|ep| {
                format!(
                    "ENDPOINT: {} {}\n\
                 Samples: {}\n\
                 Request Schema: {}\n\
                 Response Examples: {}\n",
                    ep.method,
                    ep.path,
                    ep.sample_count,
                    ep.request_schema.as_deref().unwrap_or("None"),
                    ep.response_examples.join("; ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n---\n");

        let content = format!(
            "Analyze these {} API endpoints and generate documentation for each:\n\n\
             {}\n\n\
             For each endpoint, generate:\n\
             1. Clear purpose description\n\
             2. Parameter documentation\n\
             3. Response format description\n\
             4. Common error scenarios\n\n\
             Format as JSON array with one object per endpoint.",
            endpoints.len(),
            endpoints_text
        );

        Self {
            prompt_type: PromptType::BatchEndpointAnalysis,
            content,
            temperature: 0.2,
            max_tokens: 4096,
        }
    }

    fn extract_request_examples(samples: &[TrafficSample], limit: usize) -> String {
        let examples: Vec<String> = samples
            .iter()
            .filter_map(|sample| {
                sample.request.body.as_ref().and_then(|body| {
                    if body.priority == crate::body_capture::ContentPriority::High {
                        // Try to get JSON body text
                        Some(format!(
                            "Headers: {}\nBody: (captured {} bytes)",
                            sample
                                .request
                                .headers
                                .iter()
                                .map(|(k, v)| format!("{k}: {v}"))
                                .collect::<Vec<_>>()
                                .join(", "),
                            body.captured_size()
                        ))
                    } else {
                        None
                    }
                })
            })
            .take(limit)
            .collect();

        if examples.is_empty() {
            "No high-priority request examples available".to_string()
        } else {
            examples.join("\n\n")
        }
    }

    fn extract_response_examples(samples: &[TrafficSample], limit: usize) -> String {
        let examples: Vec<String> = samples
            .iter()
            .filter_map(|sample| {
                sample.response.as_ref().and_then(|response| {
                    response.body.as_ref().and_then(|body| {
                        if body.priority == crate::body_capture::ContentPriority::High {
                            Some(format!(
                                "Status: {}\nHeaders: {}\nBody: (captured {} bytes)",
                                response.status_code,
                                response
                                    .headers
                                    .iter()
                                    .map(|(k, v)| format!("{k}: {v}"))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                body.captured_size()
                            ))
                        } else {
                            None
                        }
                    })
                })
            })
            .take(limit)
            .collect();

        if examples.is_empty() {
            "No high-priority response examples available".to_string()
        } else {
            examples.join("\n\n")
        }
    }

    fn analyze_status_codes(samples: &[TrafficSample]) -> String {
        let mut status_counts: HashMap<u16, usize> = HashMap::new();

        for sample in samples {
            if let Some(response) = &sample.response {
                *status_counts.entry(response.status_code).or_insert(0) += 1;
            }
        }

        let mut status_list: Vec<_> = status_counts.into_iter().collect();
        status_list.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending

        status_list
            .into_iter()
            .map(|(code, count)| format!("{code}: {count} times"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSummary {
    pub method: String,
    pub path: String,
    pub sample_count: usize,
    pub request_schema: Option<String>,
    pub response_examples: Vec<String>,
}
