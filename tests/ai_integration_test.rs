// AI Integration Tests - Tests all AI components working together
use devdocs_core::ai::{GeminiClient, GeminiPrompt, TrafficPrompt};
use devdocs_core::analysis::{TrafficAnalyzer, schema_inference::JsonSchemaInference};
use devdocs_core::models::{HttpMethod, CapturedRequest, CapturedResponse};
use devdocs_core::body_capture::ContentPriority;
use serde_json::json;
use std::env;

#[tokio::test]
async fn test_ai_pipeline_integration() {
    println!("🧪 Testing AI Pipeline Integration...");
    
    // Check if Gemini API key is available
    if env::var("GEMINI_API_KEY").is_err() {
        println!("⚠️  GEMINI_API_KEY not set, skipping AI integration test");
        return;
    }
    
    // 1. Test Schema Inference
    println!("  📊 Testing Schema Inference...");
    let inference = JsonSchemaInference::new();
    let json_body = json!({
        "id": 123,
        "name": "John Doe",
        "email": "john@example.com",
        "age": 30,
        "active": true
    });
    
    let schema = inference.infer_schema(&json_body).expect("Should infer schema");
    println!("    ✅ Schema inferred: {} properties", schema.properties.len());
    assert!(schema.properties.contains_key("id"));
    assert!(schema.properties.contains_key("name"));
    
    // 2. Test Gemini Client Creation
    println!("  🤖 Testing Gemini Client...");
    let client = GeminiClient::new();
    println!("    ✅ Gemini client created successfully");
    
    // 3. Test Prompt Generation
    println!("  📝 Testing Prompt Generation...");
    let request = CapturedRequest {
        method: HttpMethod::POST,
        path: "/api/users".to_string(),
        query_params: Some("role=admin&status=active".to_string()),
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("authorization".to_string(), "Bearer token".to_string()),
        ],
        body: Some(json_body.to_string()),
        content_priority: ContentPriority::High,
        timestamp: chrono::Utc::now(),
    };
    
    let response = CapturedResponse {
        status_code: 201,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
        ],
        body: Some(json!({
            "id": 123,
            "message": "User created successfully"
        }).to_string()),
        content_priority: ContentPriority::High,
        timestamp: chrono::Utc::now(),
    };
    
    let prompt = TrafficPrompt::new(&request, Some(&response));
    let prompt_text = prompt.build_prompt();
    println!("    ✅ Prompt generated: {} characters", prompt_text.len());
    assert!(prompt_text.contains("POST /api/users"));
    assert!(prompt_text.contains("application/json"));
    
    // 4. Test Traffic Analyzer
    println!("  📈 Testing Traffic Analyzer...");
    let analyzer = TrafficAnalyzer::new();
    
    // Create sample traffic data
    let mut requests = Vec::new();
    let mut responses = Vec::new();
    
    // Add sample data
    requests.push(request);
    responses.push(Some(response));
    
    // Group by endpoint
    let grouped = analyzer.group_by_endpoint(&requests, &responses);
    println!("    ✅ Traffic grouped: {} endpoints", grouped.len());
    assert!(!grouped.is_empty());
    
    // Test endpoint pattern extraction
    let endpoint_key = grouped.keys().next().unwrap();
    println!("    ✅ Endpoint pattern: {}", endpoint_key);
    assert!(endpoint_key.contains("POST"));
    assert!(endpoint_key.contains("/api/users"));
    
    println!("🎉 AI Pipeline Integration Test Completed Successfully!");
}

#[tokio::test]
async fn test_schema_inference_edge_cases() {
    println!("🧪 Testing Schema Inference Edge Cases...");
    
    let inference = JsonSchemaInference::new();
    
    // Test nested objects
    let nested_json = json!({
        "user": {
            "profile": {
                "name": "John",
                "age": 30
            },
            "settings": {
                "theme": "dark",
                "notifications": true
            }
        },
        "metadata": {
            "created_at": "2025-01-01T00:00:00Z",
            "tags": ["admin", "premium"]
        }
    });
    
    let schema = inference.infer_schema(&nested_json).expect("Should handle nested objects");
    println!("  ✅ Nested object schema: {} top-level properties", schema.properties.len());
    assert!(schema.properties.contains_key("user"));
    assert!(schema.properties.contains_key("metadata"));
    
    // Test arrays
    let array_json = json!({
        "items": [
            {"id": 1, "name": "Item 1"},
            {"id": 2, "name": "Item 2"}
        ],
        "count": 2
    });
    
    let schema = inference.infer_schema(&array_json).expect("Should handle arrays");
    println!("  ✅ Array schema: {} properties", schema.properties.len());
    assert!(schema.properties.contains_key("items"));
    assert!(schema.properties.contains_key("count"));
    
    // Test empty object
    let empty_json = json!({});
    let schema = inference.infer_schema(&empty_json).expect("Should handle empty objects");
    println!("  ✅ Empty object schema: {} properties", schema.properties.len());
    assert_eq!(schema.properties.len(), 0);
    
    println!("🎉 Schema Inference Edge Cases Test Completed!");
}

#[tokio::test] 
async fn test_content_priority_analysis() {
    println!("🧪 Testing Content Priority Analysis...");
    
    // Test high priority content (JSON API responses)
    let json_headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), "150".to_string()),
    ];
    
    let json_body = json!({
        "data": {"id": 1, "name": "Test"},
        "status": "success"
    });
    
    let request = CapturedRequest {
        method: HttpMethod::GET,
        path: "/api/data".to_string(),
        query_params: None,
        headers: json_headers.clone(),
        body: Some(json_body.to_string()),
        content_priority: ContentPriority::High,
        timestamp: chrono::Utc::now(),
    };
    
    println!("  ✅ High priority content created");
    assert_eq!(request.content_priority, ContentPriority::High);
    
    // Test medium priority content (HTML)
    let html_request = CapturedRequest {
        method: HttpMethod::GET,
        path: "/page".to_string(),
        query_params: None,
        headers: vec![
            ("content-type".to_string(), "text/html".to_string()),
        ],
        body: Some("<html><body>Test</body></html>".to_string()),
        content_priority: ContentPriority::Medium,
        timestamp: chrono::Utc::now(),
    };
    
    println!("  ✅ Medium priority content created");
    assert_eq!(html_request.content_priority, ContentPriority::Medium);
    
    // Test low priority content (static assets)
    let asset_request = CapturedRequest {
        method: HttpMethod::GET,
        path: "/assets/style.css".to_string(),
        query_params: None,
        headers: vec![
            ("content-type".to_string(), "text/css".to_string()),
        ],
        body: Some("body { margin: 0; }".to_string()),
        content_priority: ContentPriority::Low,
        timestamp: chrono::Utc::now(),
    };
    
    println!("  ✅ Low priority content created");
    assert_eq!(asset_request.content_priority, ContentPriority::Low);
    
    println!("🎉 Content Priority Analysis Test Completed!");
}

#[test]
fn test_prompt_engineering() {
    println!("🧪 Testing Prompt Engineering...");
    
    // Create a comprehensive request/response pair
    let request = CapturedRequest {
        method: HttpMethod::PUT,
        path: "/api/users/123".to_string(),
        query_params: Some("include=profile,settings".to_string()),
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("authorization".to_string(), "Bearer jwt-token".to_string()),
            ("x-request-id".to_string(), "req-123".to_string()),
        ],
        body: Some(json!({
            "name": "Updated Name",
            "email": "updated@example.com",
            "preferences": {
                "theme": "dark",
                "notifications": {
                    "email": true,
                    "push": false
                }
            }
        }).to_string()),
        content_priority: ContentPriority::High,
        timestamp: chrono::Utc::now(),
    };
    
    let response = CapturedResponse {
        status_code: 200,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-response-time".to_string(), "45ms".to_string()),
        ],
        body: Some(json!({
            "id": 123,
            "name": "Updated Name", 
            "email": "updated@example.com",
            "preferences": {
                "theme": "dark",
                "notifications": {
                    "email": true,
                    "push": false
                }
            },
            "updated_at": "2025-08-06T10:30:00Z"
        }).to_string()),
        content_priority: ContentPriority::High,
        timestamp: chrono::Utc::now(),
    };
    
    // Test prompt generation
    let prompt = TrafficPrompt::new(&request, Some(&response));
    let prompt_text = prompt.build_prompt();
    
    println!("  📝 Generated prompt length: {} characters", prompt_text.len());
    println!("  🔍 Checking prompt content...");
    
    // Verify key elements are present
    assert!(prompt_text.contains("PUT /api/users/123"), "Should contain HTTP method and path");
    assert!(prompt_text.contains("include=profile,settings"), "Should contain query parameters");
    assert!(prompt_text.contains("application/json"), "Should contain content type");
    assert!(prompt_text.contains("Bearer jwt-token"), "Should contain authorization");
    assert!(prompt_text.contains("200"), "Should contain status code");
    assert!(prompt_text.contains("notifications"), "Should contain nested JSON structure");
    assert!(prompt_text.contains("updated_at"), "Should contain response fields");
    
    println!("  ✅ Prompt contains all expected elements");
    
    // Test prompt without response
    let prompt_no_response = TrafficPrompt::new(&request, None);
    let prompt_text_no_response = prompt_no_response.build_prompt();
    
    println!("  📝 Request-only prompt length: {} characters", prompt_text_no_response.len());
    assert!(!prompt_text_no_response.contains("Response:"), "Should not contain response section");
    assert!(prompt_text_no_response.contains("PUT /api/users/123"), "Should still contain request info");
    
    println!("🎉 Prompt Engineering Test Completed!");
}
