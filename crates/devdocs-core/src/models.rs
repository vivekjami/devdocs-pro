use crate::body_capture::CapturedBody;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub id: Uuid,
    pub method: String,
    pub path: String,
    pub query_params: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Option<CapturedBody>,
    pub timestamp: DateTime<Utc>,
    pub correlation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub id: Uuid,
    pub request_id: Uuid,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<CapturedBody>,
    pub timestamp: DateTime<Utc>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub path_pattern: String,
    pub method: String,
    pub request_count: u64,
    pub avg_response_time_ms: f64,
    pub status_codes: HashMap<u16, u64>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub endpoint_pattern: String,
    pub ai_analysis: Option<AIAnalysisResult>, // NEW field for Day 4
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysisResult {
    pub endpoint_description: String,
    pub parameter_documentation: HashMap<String, String>,
    pub response_documentation: String,
    pub example_requests: Vec<GeneratedExample>,
    pub business_logic_explanation: String,
    pub confidence_score: f64,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedExample {
    pub description: String,
    pub request_example: Option<String>,
    pub response_example: Option<String>,
    pub curl_command: Option<String>,
}
