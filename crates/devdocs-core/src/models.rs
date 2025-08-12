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

impl HttpRequest {
    pub fn new(method: String, path: String, correlation_id: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            method,
            path,
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: None,
            timestamp: Utc::now(),
            correlation_id,
        }
    }

    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_query_params(mut self, params: HashMap<String, String>) -> Self {
        self.query_params = params;
        self
    }

    pub fn with_body(mut self, body: CapturedBody) -> Self {
        self.body = Some(body);
        self
    }
}

impl HttpResponse {
    pub fn new(request_id: Uuid, status_code: u16) -> Self {
        Self {
            id: Uuid::new_v4(),
            request_id,
            status_code,
            headers: HashMap::new(),
            body: None,
            timestamp: Utc::now(),
            processing_time_ms: 0,
        }
    }

    pub fn with_processing_time(mut self, time_ms: u64) -> Self {
        self.processing_time_ms = time_ms;
        self
    }

    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_body(mut self, body: CapturedBody) -> Self {
        self.body = Some(body);
        self
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    pub fn is_error(&self) -> bool {
        self.status_code >= 400
    }
}

impl ApiEndpoint {
    pub fn new(path_pattern: String, method: String) -> Self {
        Self {
            path_pattern,
            method,
            request_count: 0,
            avg_response_time_ms: 0.0,
            status_codes: HashMap::new(),
            last_seen: Utc::now(),
        }
    }

    pub fn increment_request(&mut self, response_time_ms: f64, status_code: u16) {
        self.request_count += 1;

        // Update average response time
        self.avg_response_time_ms = ((self.avg_response_time_ms * (self.request_count - 1) as f64)
            + response_time_ms)
            / self.request_count as f64;

        // Update status code counts
        *self.status_codes.entry(status_code).or_insert(0) += 1;

        self.last_seen = Utc::now();
    }

    pub fn success_rate(&self) -> f64 {
        let total_requests = self.status_codes.values().sum::<u64>() as f64;
        if total_requests == 0.0 {
            return 0.0;
        }

        let success_requests = self
            .status_codes
            .iter()
            .filter(|(&code, _)| (200..300).contains(&code))
            .map(|(_, count)| *count)
            .sum::<u64>() as f64;

        success_requests / total_requests * 100.0
    }
}

impl TrafficSample {
    pub fn new(request: HttpRequest, endpoint_pattern: String) -> Self {
        Self {
            request,
            response: None,
            endpoint_pattern,
            ai_analysis: None,
        }
    }

    pub fn with_response(mut self, response: HttpResponse) -> Self {
        self.response = Some(response);
        self
    }

    pub fn with_ai_analysis(mut self, analysis: AIAnalysisResult) -> Self {
        self.ai_analysis = Some(analysis);
        self
    }
}

impl AIAnalysisResult {
    pub fn new(endpoint_description: String, confidence_score: f64) -> Self {
        Self {
            endpoint_description,
            parameter_documentation: HashMap::new(),
            response_documentation: String::new(),
            example_requests: Vec::new(),
            business_logic_explanation: String::new(),
            confidence_score: confidence_score.clamp(0.0, 1.0),
            generated_at: Utc::now(),
        }
    }

    pub fn with_parameters(mut self, params: HashMap<String, String>) -> Self {
        self.parameter_documentation = params;
        self
    }

    pub fn with_response_docs(mut self, docs: String) -> Self {
        self.response_documentation = docs;
        self
    }

    pub fn with_examples(mut self, examples: Vec<GeneratedExample>) -> Self {
        self.example_requests = examples;
        self
    }

    pub fn is_high_confidence(&self) -> bool {
        self.confidence_score >= 0.8
    }
}

impl GeneratedExample {
    pub fn new(description: String) -> Self {
        Self {
            description,
            request_example: None,
            response_example: None,
            curl_command: None,
        }
    }

    pub fn with_request(mut self, request: String) -> Self {
        self.request_example = Some(request);
        self
    }

    pub fn with_response(mut self, response: String) -> Self {
        self.response_example = Some(response);
        self
    }

    pub fn with_curl(mut self, curl: String) -> Self {
        self.curl_command = Some(curl);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_capture::CapturedBody;

    #[test]
    fn test_http_request_new() {
        let request = HttpRequest::new(
            "GET".to_string(),
            "/api/users".to_string(),
            "corr-123".to_string(),
        );

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/users");
        assert_eq!(request.correlation_id, "corr-123");
        assert!(request.query_params.is_empty());
        assert!(request.headers.is_empty());
        assert!(request.body.is_none());
    }

    #[test]
    fn test_http_request_builder() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let mut params = HashMap::new();
        params.insert("page".to_string(), "1".to_string());

        let body = CapturedBody {
            content_type: Some("text/plain".to_string()),
            compression: crate::body_capture::CompressionType::None,
            priority: crate::body_capture::ContentPriority::High,
            original_size: "test body".len(),
            storage: crate::body_capture::BodyStorage::Memory("test body".as_bytes().to_vec()),
        };

        let request = HttpRequest::new(
            "POST".to_string(),
            "/api/test".to_string(),
            "corr-456".to_string(),
        )
        .with_headers(headers.clone())
        .with_query_params(params.clone())
        .with_body(body);

        assert_eq!(request.headers, headers);
        assert_eq!(request.query_params, params);
        assert!(request.body.is_some());
    }

    #[test]
    fn test_http_response_new() {
        let request_id = Uuid::new_v4();
        let response = HttpResponse::new(request_id, 200);

        assert_eq!(response.request_id, request_id);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.processing_time_ms, 0);
        assert!(response.headers.is_empty());
        assert!(response.body.is_none());
    }

    #[test]
    fn test_http_response_builder() {
        let request_id = Uuid::new_v4();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let body = CapturedBody {
            content_type: Some("application/json".to_string()),
            compression: crate::body_capture::CompressionType::None,
            priority: crate::body_capture::ContentPriority::High,
            original_size: "response body".len(),
            storage: crate::body_capture::BodyStorage::Memory("response body".as_bytes().to_vec()),
        };

        let response = HttpResponse::new(request_id, 201)
            .with_processing_time(150)
            .with_headers(headers.clone())
            .with_body(body);

        assert_eq!(response.processing_time_ms, 150);
        assert_eq!(response.headers, headers);
        assert!(response.body.is_some());
    }

    #[test]
    fn test_http_response_status_checks() {
        let request_id = Uuid::new_v4();

        let success_response = HttpResponse::new(request_id, 200);
        assert!(success_response.is_success());
        assert!(!success_response.is_error());

        let error_response = HttpResponse::new(request_id, 404);
        assert!(!error_response.is_success());
        assert!(error_response.is_error());

        let redirect_response = HttpResponse::new(request_id, 302);
        assert!(!redirect_response.is_success());
        assert!(!redirect_response.is_error());
    }

    #[test]
    fn test_api_endpoint_new() {
        let endpoint = ApiEndpoint::new("/api/users/{id}".to_string(), "GET".to_string());

        assert_eq!(endpoint.path_pattern, "/api/users/{id}");
        assert_eq!(endpoint.method, "GET");
        assert_eq!(endpoint.request_count, 0);
        assert_eq!(endpoint.avg_response_time_ms, 0.0);
        assert!(endpoint.status_codes.is_empty());
    }

    #[test]
    fn test_api_endpoint_increment_request() {
        let mut endpoint = ApiEndpoint::new("/api/test".to_string(), "POST".to_string());

        endpoint.increment_request(100.0, 200);
        assert_eq!(endpoint.request_count, 1);
        assert_eq!(endpoint.avg_response_time_ms, 100.0);
        assert_eq!(endpoint.status_codes.get(&200), Some(&1));

        endpoint.increment_request(200.0, 200);
        assert_eq!(endpoint.request_count, 2);
        assert_eq!(endpoint.avg_response_time_ms, 150.0);
        assert_eq!(endpoint.status_codes.get(&200), Some(&2));

        endpoint.increment_request(50.0, 400);
        assert_eq!(endpoint.request_count, 3);
        assert_eq!(endpoint.avg_response_time_ms, (100.0 + 200.0 + 50.0) / 3.0);
        assert_eq!(endpoint.status_codes.get(&400), Some(&1));
    }

    #[test]
    fn test_api_endpoint_success_rate() {
        let mut endpoint = ApiEndpoint::new("/api/test".to_string(), "GET".to_string());

        // No requests yet
        assert_eq!(endpoint.success_rate(), 0.0);

        // Add successful requests
        endpoint.increment_request(100.0, 200);
        endpoint.increment_request(150.0, 201);
        assert_eq!(endpoint.success_rate(), 100.0);

        // Add error request
        endpoint.increment_request(200.0, 404);
        let expected_rate = 2.0 / 3.0 * 100.0; // 2 success out of 3 total
        assert!((endpoint.success_rate() - expected_rate).abs() < 0.01);

        // Add more error requests
        endpoint.increment_request(250.0, 500);
        let expected_rate2 = 2.0 / 4.0 * 100.0; // 2 success out of 4 total
        assert!((endpoint.success_rate() - expected_rate2).abs() < 0.01);
    }

    #[test]
    fn test_traffic_sample_new() {
        let request = HttpRequest::new(
            "GET".to_string(),
            "/api/users".to_string(),
            "corr-123".to_string(),
        );
        let sample = TrafficSample::new(request.clone(), "/api/users".to_string());

        assert_eq!(sample.request.method, request.method);
        assert_eq!(sample.endpoint_pattern, "/api/users");
        assert!(sample.response.is_none());
        assert!(sample.ai_analysis.is_none());
    }

    #[test]
    fn test_traffic_sample_builder() {
        let request = HttpRequest::new(
            "GET".to_string(),
            "/api/users".to_string(),
            "corr-123".to_string(),
        );
        let response = HttpResponse::new(request.id, 200);
        let analysis = AIAnalysisResult::new("Test endpoint".to_string(), 0.9);

        let sample = TrafficSample::new(request, "/api/users".to_string())
            .with_response(response.clone())
            .with_ai_analysis(analysis.clone());

        assert!(sample.response.is_some());
        assert_eq!(sample.response.unwrap().status_code, 200);
        assert!(sample.ai_analysis.is_some());
        assert_eq!(sample.ai_analysis.unwrap().confidence_score, 0.9);
    }

    #[test]
    fn test_ai_analysis_result_new() {
        let analysis = AIAnalysisResult::new("User management endpoint".to_string(), 0.85);

        assert_eq!(analysis.endpoint_description, "User management endpoint");
        assert_eq!(analysis.confidence_score, 0.85);
        assert!(analysis.parameter_documentation.is_empty());
        assert!(analysis.response_documentation.is_empty());
        assert!(analysis.example_requests.is_empty());
    }

    #[test]
    fn test_ai_analysis_result_confidence_clamping() {
        let analysis1 = AIAnalysisResult::new("Test".to_string(), -0.1);
        assert_eq!(analysis1.confidence_score, 0.0);

        let analysis2 = AIAnalysisResult::new("Test".to_string(), 1.5);
        assert_eq!(analysis2.confidence_score, 1.0);
    }

    #[test]
    fn test_ai_analysis_result_builder() {
        let mut params = HashMap::new();
        params.insert("id".to_string(), "User ID".to_string());

        let examples = vec![GeneratedExample::new("Get user by ID".to_string())
            .with_request("{\"id\": 123}".to_string())
            .with_response("{\"user\": {...}}".to_string())];

        let analysis = AIAnalysisResult::new("User endpoint".to_string(), 0.9)
            .with_parameters(params.clone())
            .with_response_docs("Returns user data".to_string())
            .with_examples(examples);

        assert_eq!(analysis.parameter_documentation, params);
        assert_eq!(analysis.response_documentation, "Returns user data");
        assert_eq!(analysis.example_requests.len(), 1);
    }

    #[test]
    fn test_ai_analysis_result_high_confidence() {
        let high_confidence = AIAnalysisResult::new("Test".to_string(), 0.85);
        assert!(high_confidence.is_high_confidence());

        let low_confidence = AIAnalysisResult::new("Test".to_string(), 0.75);
        assert!(!low_confidence.is_high_confidence());
    }

    #[test]
    fn test_generated_example_new() {
        let example = GeneratedExample::new("Test example".to_string());

        assert_eq!(example.description, "Test example");
        assert!(example.request_example.is_none());
        assert!(example.response_example.is_none());
        assert!(example.curl_command.is_none());
    }

    #[test]
    fn test_generated_example_builder() {
        let example = GeneratedExample::new("Get user".to_string())
            .with_request("{\"query\": \"user\"}".to_string())
            .with_response("{\"data\": {...}}".to_string())
            .with_curl("curl -X GET /api/users".to_string());

        assert_eq!(example.description, "Get user");
        assert_eq!(
            example.request_example,
            Some("{\"query\": \"user\"}".to_string())
        );
        assert_eq!(
            example.response_example,
            Some("{\"data\": {...}}".to_string())
        );
        assert_eq!(
            example.curl_command,
            Some("curl -X GET /api/users".to_string())
        );
    }

    #[test]
    fn test_serialization_http_request() {
        let request = HttpRequest::new(
            "POST".to_string(),
            "/api/test".to_string(),
            "corr-123".to_string(),
        );
        let serialized = serde_json::to_string(&request).unwrap();
        assert!(serialized.contains("POST"));
        assert!(serialized.contains("/api/test"));

        let deserialized: HttpRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.method, request.method);
        assert_eq!(deserialized.path, request.path);
    }

    #[test]
    fn test_serialization_ai_analysis_result() {
        let analysis = AIAnalysisResult::new("Test endpoint".to_string(), 0.9);
        let serialized = serde_json::to_string(&analysis).unwrap();
        assert!(serialized.contains("Test endpoint"));
        assert!(serialized.contains("0.9"));

        let deserialized: AIAnalysisResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(
            deserialized.endpoint_description,
            analysis.endpoint_description
        );
        assert_eq!(deserialized.confidence_score, analysis.confidence_score);
    }

    #[test]
    fn test_clone_implementations() {
        let request = HttpRequest::new(
            "GET".to_string(),
            "/test".to_string(),
            "corr-123".to_string(),
        );
        let cloned_request = request.clone();
        assert_eq!(request.method, cloned_request.method);
        assert_eq!(request.path, cloned_request.path);

        let analysis = AIAnalysisResult::new("Test".to_string(), 0.8);
        let cloned_analysis = analysis.clone();
        assert_eq!(
            analysis.endpoint_description,
            cloned_analysis.endpoint_description
        );
        assert_eq!(analysis.confidence_score, cloned_analysis.confidence_score);
    }

    #[test]
    fn test_debug_implementations() {
        let request = HttpRequest::new(
            "GET".to_string(),
            "/test".to_string(),
            "corr-123".to_string(),
        );
        let debug_str = format!("{request:?}");
        assert!(debug_str.contains("HttpRequest"));
        assert!(debug_str.contains("GET"));

        let analysis = AIAnalysisResult::new("Test".to_string(), 0.8);
        let debug_str = format!("{analysis:?}");
        assert!(debug_str.contains("AIAnalysisResult"));
        assert!(debug_str.contains("Test"));
    }
}
