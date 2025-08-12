//! AI-powered documentation generation using Google Gemini
//!
//! This module integrates with Google Gemini Pro to generate intelligent
//! API documentation from analyzed traffic patterns and schemas.

use crate::analysis::AnalysisConfig;
use crate::errors::DevDocsError;
use crate::models::ApiEndpoint;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

/// Gemini API configuration
#[derive(Debug, Clone)]
pub struct GeminiConfig {
    /// API key for Google Gemini
    pub api_key: String,
    /// API endpoint URL
    pub endpoint: String,
    /// Model to use (e.g., "gemini-pro")
    pub model: String,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum tokens per request
    pub max_tokens: u32,
    /// Temperature for generation (0.0-1.0)
    pub temperature: f32,
}

impl Default for GeminiConfig {
    fn default() -> Self {
        Self {
            api_key: std::env::var("GEMINI_API_KEY").unwrap_or_default(),
            endpoint: "https://generativelanguage.googleapis.com/v1beta/models".to_string(),
            model: "gemini-2.5-flash".to_string(),
            timeout: Duration::from_secs(30),
            max_tokens: 4096,
            temperature: 0.3,
        }
    }
}

/// Gemini API request structure
#[derive(Debug, Serialize)]
struct GeminiRequest {
    contents: Vec<Content>,
    #[serde(rename = "generationConfig")]
    generation_config: GenerationConfig,
}

#[derive(Debug, Serialize)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Debug, Serialize)]
struct Part {
    text: String,
}

#[derive(Debug, Serialize)]
struct GenerationConfig {
    temperature: f32,
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
}

/// Gemini API response structure
#[derive(Debug, Deserialize)]
struct GeminiResponse {
    candidates: Vec<Candidate>,
}

#[derive(Debug, Deserialize)]
struct Candidate {
    content: ResponseContent,
}

#[derive(Debug, Deserialize)]
struct ResponseContent {
    parts: Vec<ResponsePart>,
}

#[derive(Debug, Deserialize)]
struct ResponsePart {
    text: String,
}

/// AI processor for generating documentation
pub struct AiProcessor {
    config: AnalysisConfig,
    gemini_config: GeminiConfig,
    client: Client,
}

impl AiProcessor {
    /// Create a new AI processor
    pub fn new(config: &AnalysisConfig) -> Result<Self, DevDocsError> {
        let gemini_config = GeminiConfig::default();

        if gemini_config.api_key.is_empty() {
            return Err(DevDocsError::Configuration(
                "GEMINI_API_KEY environment variable is required".to_string(),
            ));
        }

        let client = Client::builder()
            .timeout(gemini_config.timeout)
            .build()
            .map_err(|e| {
                DevDocsError::NetworkError(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self {
            config: config.clone(),
            gemini_config,
            client,
        })
    }

    /// Generate comprehensive documentation using AI
    pub async fn generate_documentation(
        &self,
        endpoints: &[ApiEndpoint],
        schemas: &HashMap<String, Value>,
    ) -> Result<String, DevDocsError> {
        if !self.config.ai_documentation_enabled {
            return Ok("AI documentation generation is disabled".to_string());
        }

        // Create context-rich prompt for Gemini
        let prompt = self.build_documentation_prompt(endpoints, schemas);

        // Call Gemini API
        let response = self.call_gemini_api(&prompt).await?;

        Ok(response)
    }

    /// Build a comprehensive prompt for documentation generation
    fn build_documentation_prompt(
        &self,
        endpoints: &[ApiEndpoint],
        schemas: &HashMap<String, Value>,
    ) -> String {
        let mut prompt = String::new();

        prompt.push_str("You are an expert API documentation writer. Generate comprehensive, professional API documentation based on the following analyzed traffic data.\n\n");

        // Add context about the API
        prompt.push_str("## API Analysis Context\n");
        prompt.push_str(&format!(
            "- Total endpoints analyzed: {}\n",
            endpoints.len()
        ));
        prompt.push_str(&format!("- Schemas inferred: {}\n", schemas.len()));
        prompt.push('\n');

        // Add endpoint information
        if !endpoints.is_empty() {
            prompt.push_str("## Detected Endpoints\n");
            for endpoint in endpoints {
                let success_rate = endpoint.success_rate();
                prompt.push_str(&format!(
                    "- {} {}: {} requests, avg response time: {:.1}ms, success rate: {:.1}%\n",
                    endpoint.method,
                    endpoint.path_pattern,
                    endpoint.request_count,
                    endpoint.avg_response_time_ms,
                    success_rate
                ));
            }
            prompt.push('\n');
        }

        // Add schema information
        if !schemas.is_empty() {
            prompt.push_str("## Inferred Schemas\n");
            for (name, schema) in schemas {
                prompt.push_str(&format!("### {name}\n"));
                prompt.push_str("```json\n");
                prompt.push_str(&serde_json::to_string_pretty(schema).unwrap_or_default());
                prompt.push_str("\n```\n\n");
            }
        }

        // Add generation instructions
        prompt.push_str("## Documentation Requirements\n");
        prompt.push_str("Generate professional API documentation that includes:\n");
        prompt.push_str(
            "1. **API Overview**: Brief description of the API's purpose and capabilities\n",
        );
        prompt.push_str(
            "2. **Authentication**: Inferred authentication methods from traffic patterns\n",
        );
        prompt.push_str("3. **Endpoints**: Detailed documentation for each endpoint including:\n");
        prompt.push_str("   - Purpose and functionality\n");
        prompt.push_str("   - Request parameters and body schema\n");
        prompt.push_str("   - Response schema and status codes\n");
        prompt.push_str("   - Example requests and responses (realistic data)\n");
        prompt.push_str("   - Error handling and common failure scenarios\n");
        prompt.push_str(
            "4. **Data Models**: Documentation for all schemas with field descriptions\n",
        );
        prompt.push_str("5. **Usage Examples**: Practical examples showing common workflows\n");
        prompt.push_str("6. **Best Practices**: Recommendations for API usage\n\n");

        prompt.push_str("Format the documentation in clean Markdown with proper headings, code blocks, and tables where appropriate. ");
        prompt.push_str("Make it comprehensive but easy to understand for developers.\n");

        prompt
    }

    /// Call the Gemini API with the given prompt
    async fn call_gemini_api(&self, prompt: &str) -> Result<String, DevDocsError> {
        let url = format!(
            "{}/{}:generateContent?key={}",
            self.gemini_config.endpoint, self.gemini_config.model, self.gemini_config.api_key
        );

        let request = GeminiRequest {
            contents: vec![Content {
                parts: vec![Part {
                    text: prompt.to_string(),
                }],
            }],
            generation_config: GenerationConfig {
                temperature: self.gemini_config.temperature,
                max_output_tokens: self.gemini_config.max_tokens,
            },
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| DevDocsError::NetworkError(format!("Failed to call Gemini API: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(DevDocsError::NetworkError(format!(
                "Gemini API returned error {status}: {error_text}"
            )));
        }

        let gemini_response: GeminiResponse = response.json().await.map_err(|e| {
            DevDocsError::NetworkError(format!("Failed to parse Gemini response: {e}"))
        })?;

        if gemini_response.candidates.is_empty() {
            return Err(DevDocsError::NetworkError(
                "Gemini API returned no candidates".to_string(),
            ));
        }

        let candidate = &gemini_response.candidates[0];
        if candidate.content.parts.is_empty() {
            return Err(DevDocsError::NetworkError(
                "Gemini API returned no content parts".to_string(),
            ));
        }

        Ok(candidate.content.parts[0].text.clone())
    }

    /// Generate endpoint-specific documentation
    pub async fn generate_endpoint_documentation(
        &self,
        endpoint: &ApiEndpoint,
        request_schema: Option<&Value>,
        response_schema: Option<&Value>,
    ) -> Result<String, DevDocsError> {
        let mut prompt = String::new();

        prompt.push_str("Generate detailed documentation for this API endpoint:\n\n");
        prompt.push_str(&format!(
            "**Endpoint**: {} {}\n",
            endpoint.method, endpoint.path_pattern
        ));
        prompt.push_str(&format!("**Request Count**: {}\n", endpoint.request_count));
        prompt.push_str(&format!(
            "**Average Response Time**: {:.1}ms\n",
            endpoint.avg_response_time_ms
        ));
        prompt.push_str(&format!(
            "**Success Rate**: {:.1}%\n\n",
            endpoint.success_rate()
        ));

        if let Some(schema) = request_schema {
            prompt.push_str("**Request Schema**:\n```json\n");
            prompt.push_str(&serde_json::to_string_pretty(schema).unwrap_or_default());
            prompt.push_str("\n```\n\n");
        }

        if let Some(schema) = response_schema {
            prompt.push_str("**Response Schema**:\n```json\n");
            prompt.push_str(&serde_json::to_string_pretty(schema).unwrap_or_default());
            prompt.push_str("\n```\n\n");
        }

        prompt.push_str("Please provide:\n");
        prompt.push_str("1. A clear description of what this endpoint does\n");
        prompt.push_str("2. Parameter descriptions (path, query, body)\n");
        prompt.push_str("3. Response format explanation\n");
        prompt.push_str("4. Example request and response\n");
        prompt.push_str("5. Common error scenarios\n");
        prompt.push_str("6. Usage recommendations\n");

        self.call_gemini_api(&prompt).await
    }

    /// Generate OpenAPI specification using AI
    pub async fn generate_openapi_spec(
        &self,
        endpoints: &[ApiEndpoint],
        schemas: &HashMap<String, Value>,
    ) -> Result<Value, DevDocsError> {
        let mut prompt = String::new();

        prompt.push_str("Generate a complete OpenAPI 3.0 specification based on the following API analysis:\n\n");

        // Add endpoint information
        for endpoint in endpoints {
            prompt.push_str(&format!(
                "- {} {}: {} requests, {:.1}ms avg response time\n",
                endpoint.method,
                endpoint.path_pattern,
                endpoint.request_count,
                endpoint.avg_response_time_ms
            ));
        }

        // Add schemas
        if !schemas.is_empty() {
            prompt.push_str("\nSchemas:\n");
            for (name, schema) in schemas {
                prompt.push_str(&format!(
                    "- {}: {}\n",
                    name,
                    serde_json::to_string(schema).unwrap_or_default()
                ));
            }
        }

        prompt.push_str("\nGenerate a valid OpenAPI 3.0 specification in JSON format. Include:\n");
        prompt.push_str("- info section with title, version, description\n");
        prompt.push_str("- paths for all endpoints with parameters, request/response schemas\n");
        prompt.push_str("- components section with reusable schemas\n");
        prompt.push_str("- appropriate HTTP status codes\n");
        prompt.push_str("- realistic examples\n");

        let response = self.call_gemini_api(&prompt).await?;

        // Try to parse the response as JSON
        serde_json::from_str(&response)
            .map_err(|e| DevDocsError::InvalidRequest(format!("Failed to parse OpenAPI spec: {e}")))
    }

    /// Update configuration
    pub fn update_config(&mut self, config: &AnalysisConfig) -> Result<(), DevDocsError> {
        self.config = config.clone();
        Ok(())
    }

    /// Test Gemini API connectivity
    pub async fn test_connection(&self) -> Result<bool, DevDocsError> {
        let simple_prompt = "Respond with 'OK' if you can read this message.";
        let response = self.call_gemini_api(simple_prompt).await?;
        Ok(response.trim().to_uppercase().contains("OK"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_gemini_config_default() {
        // Set a test API key for the test
        std::env::set_var("GEMINI_API_KEY", "test_key");

        let config = GeminiConfig::default();
        assert_eq!(config.api_key, "test_key");
        assert_eq!(config.model, "gemini-2.5-flash");
        assert_eq!(config.temperature, 0.3);
        assert_eq!(config.max_tokens, 4096);

        // Clean up
        std::env::remove_var("GEMINI_API_KEY");
    }

    #[test]
    fn test_ai_processor_creation_without_api_key() {
        // Save the current API key if it exists
        let original_key = std::env::var("GEMINI_API_KEY").ok();

        // Set empty API key
        std::env::set_var("GEMINI_API_KEY", "");

        let config = AnalysisConfig::default();
        let processor = AiProcessor::new(&config);
        assert!(processor.is_err());

        if let Err(DevDocsError::Configuration(msg)) = processor {
            assert!(msg.contains("GEMINI_API_KEY"));
        } else {
            panic!("Expected Configuration error");
        }

        // Restore the original API key if it existed
        if let Some(key) = original_key {
            std::env::set_var("GEMINI_API_KEY", key);
        } else {
            std::env::remove_var("GEMINI_API_KEY");
        }
    }

    #[test]
    fn test_ai_processor_creation_with_api_key() {
        std::env::set_var("GEMINI_API_KEY", "test_key");

        let config = AnalysisConfig::default();
        let processor = AiProcessor::new(&config);
        assert!(processor.is_ok());

        std::env::remove_var("GEMINI_API_KEY");
    }

    #[test]
    fn test_documentation_prompt_building() {
        std::env::set_var("GEMINI_API_KEY", "test_key");

        let config = AnalysisConfig::default();
        let processor = AiProcessor::new(&config).unwrap();

        let endpoints = vec![ApiEndpoint::new(
            "/users/{id}".to_string(),
            "GET".to_string(),
        )];

        let mut schemas = HashMap::new();
        schemas.insert(
            "User".to_string(),
            serde_json::json!({
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                }
            }),
        );

        let prompt = processor.build_documentation_prompt(&endpoints, &schemas);

        assert!(prompt.contains("API Analysis Context"));
        assert!(prompt.contains("Total endpoints analyzed: 1"));
        assert!(prompt.contains("Schemas inferred: 1"));
        assert!(prompt.contains("GET /users/{id}"));
        assert!(prompt.contains("User"));
        assert!(prompt.contains("Documentation Requirements"));

        std::env::remove_var("GEMINI_API_KEY");
    }

    #[test]
    fn test_gemini_request_serialization() {
        let request = GeminiRequest {
            contents: vec![Content {
                parts: vec![Part {
                    text: "Test prompt".to_string(),
                }],
            }],
            generation_config: GenerationConfig {
                temperature: 0.5,
                max_output_tokens: 1000,
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Test prompt"));
        assert!(json.contains("generationConfig"));
        assert!(json.contains("maxOutputTokens"));
    }

    #[test]
    fn test_gemini_response_deserialization() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": "Generated documentation"
                    }]
                }
            }]
        }"#;

        let response: GeminiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.candidates.len(), 1);
        assert_eq!(response.candidates[0].content.parts.len(), 1);
        assert_eq!(
            response.candidates[0].content.parts[0].text,
            "Generated documentation"
        );
    }

    #[test]
    fn test_config_update() {
        std::env::set_var("GEMINI_API_KEY", "test_key");

        let config = AnalysisConfig::default();
        let mut processor = AiProcessor::new(&config).unwrap();

        let mut new_config = config.clone();
        new_config.ai_documentation_enabled = false;

        let result = processor.update_config(&new_config);
        assert!(result.is_ok());
        assert!(!processor.config.ai_documentation_enabled);

        std::env::remove_var("GEMINI_API_KEY");
    }

    #[tokio::test]
    async fn test_disabled_ai_documentation() {
        std::env::set_var("GEMINI_API_KEY", "test_key");

        let config = AnalysisConfig {
            ai_documentation_enabled: false,
            ..Default::default()
        };

        let processor = AiProcessor::new(&config).unwrap();
        let endpoints = vec![];
        let schemas = HashMap::new();

        let result = processor.generate_documentation(&endpoints, &schemas).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "AI documentation generation is disabled");

        std::env::remove_var("GEMINI_API_KEY");
    }
}
