//! Google Gemini AI client for generating API documentation

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use crate::errors::{DevDocsError, Result};

#[derive(Debug, Clone)]
pub struct GeminiClient {
    client: Client,
    api_key: String,
    model: String,
    base_url: String,
    last_request: Option<Instant>,
    min_request_interval: Duration,
}

impl GeminiClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model: "gemini-pro".to_string(),
            base_url: "https://generativelanguage.googleapis.com/v1/models".to_string(),
            last_request: None,
            min_request_interval: Duration::from_millis(100), // 10 requests/sec max
        }
    }

    pub async fn generate_content(&mut self, prompt: &GeminiPrompt) -> Result<GeminiResponse> {
        // Rate limit enforcement
        self.enforce_rate_limit().await;
        
        // Send request to Gemini API
        let url = format!("{}/{}:generateContent?key={}", 
            self.base_url, self.model, self.api_key);
        
        let request_body = GeminiRequest {
            contents: vec![Content {
                role: "user".to_string(),
                parts: vec![Part { text: prompt.content.clone() }],
            }],
            generation_config: GenerationConfig {
                temperature: Some(prompt.temperature),
                max_output_tokens: Some(prompt.max_tokens),
                top_p: Some(0.8),
                top_k: Some(40),
            },
        };
        
        // Log request (without API key)
        tracing::debug!("Sending request to Gemini API: {:?}", prompt.prompt_type);
        
        // Send request and process response
        let response = self.client.post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| DevDocsError::Network(e.into()))?;
            
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(DevDocsError::InvalidRequest(format!(
                "Gemini API error {}: {}", status, text
            )));
        }
            
        let gemini_response = response
            .json::<GeminiResponse>()
            .await
            .map_err(|e| DevDocsError::InvalidRequest(format!("Failed to parse Gemini response: {}", e)))?;
            
        tracing::debug!("Received Gemini response with {} candidates", 
            gemini_response.candidates.len());
            
        Ok(gemini_response)
    }
    
    async fn enforce_rate_limit(&mut self) {
        if let Some(last_time) = self.last_request {
            let elapsed = last_time.elapsed();
            if elapsed < self.min_request_interval {
                tokio::time::sleep(self.min_request_interval - elapsed).await;
            }
        }
        self.last_request = Some(Instant::now());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiPrompt {
    pub prompt_type: PromptType,
    pub content: String,
    pub temperature: f32,
    pub max_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PromptType {
    EndpointAnalysis,
    SchemaInference,
    ErrorDocumentation,
    WorkflowAnalysis,
    BatchEndpointAnalysis,
}

#[derive(Debug, Serialize)]
struct GeminiRequest {
    contents: Vec<Content>,
    #[serde(rename = "generationConfig")]
    generation_config: GenerationConfig,
}

#[derive(Debug, Serialize)]
struct Content {
    role: String,
    parts: Vec<Part>,
}

#[derive(Debug, Serialize)]
struct Part {
    text: String,
}

#[derive(Debug, Serialize)]
struct GenerationConfig {
    temperature: Option<f32>,
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: Option<u32>,
    #[serde(rename = "topP")]
    top_p: Option<f32>,
    #[serde(rename = "topK")]
    top_k: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct GeminiResponse {
    pub candidates: Vec<Candidate>,
    #[serde(rename = "usageMetadata")]
    pub usage_metadata: Option<UsageMetadata>,
}

#[derive(Debug, Deserialize)]
pub struct Candidate {
    pub content: ResponseContent,
    #[serde(rename = "finishReason")]
    pub finish_reason: Option<String>,
    #[serde(rename = "safetyRatings")]
    pub safety_ratings: Option<Vec<SafetyRating>>,
}

#[derive(Debug, Deserialize)]
pub struct ResponseContent {
    pub parts: Vec<ResponsePart>,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct ResponsePart {
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct UsageMetadata {
    #[serde(rename = "promptTokenCount")]
    pub prompt_token_count: Option<u32>,
    #[serde(rename = "candidatesTokenCount")]
    pub candidates_token_count: Option<u32>,
    #[serde(rename = "totalTokenCount")]
    pub total_token_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct SafetyRating {
    pub category: String,
    pub probability: String,
}

impl GeminiResponse {
    pub fn get_text(&self) -> Option<String> {
        self.candidates
            .first()?
            .content
            .parts
            .first()
            .map(|part| part.text.clone())
    }
}
