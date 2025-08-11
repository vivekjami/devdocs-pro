//! Complete DevDocs Pro example demonstrating all features
//!
//! This example shows how to:
//! 1. Set up the middleware with configuration
//! 2. Capture HTTP traffic
//! 3. Analyze traffic patterns
//! 4. Generate AI-powered documentation
//! 5. Serve interactive documentation

use devdocs_core::{
    Config,
    analysis::{AnalysisConfig, TrafficAnalyzer},
    documentation::{DocumentationConfig, DocumentationGenerator},
    models::{HttpRequest, HttpResponse, TrafficSample},
    body_capture::{CapturedBody, BodyStorage, CompressionType, ContentPriority},
};
use tracing_subscriber;
use devdocs_middleware::TrafficProcessor;
use serde_json::json;
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()

        .init();

    println!("🚀 DevDocs Pro - Complete Example");
    println!("==================================");

    // Step 1: Create configuration
    let config = create_sample_config();
    println!("✅ Configuration created");

    // Step 2: Demonstrate traffic analysis
    demonstrate_traffic_analysis().await?;

    // Step 3: Demonstrate documentation generation
    demonstrate_documentation_generation().await?;

    // Step 4: Demonstrate complete middleware workflow
    demonstrate_middleware_workflow(config).await?;

    println!("\n🎉 Complete example finished successfully!");
    println!("Check the generated documentation files for results.");

    Ok(())
}

/// Create a sample configuration
fn create_sample_config() -> Config {
    Config {
        api_key: "demo-api-key".to_string(),
        sampling_rate: 1.0, // Capture 100% of traffic for demo
        max_body_size: Some(10 * 1024 * 1024), // 10MB
        enable_ai_analysis: true,
        gemini_api_key: std::env::var("GEMINI_API_KEY").ok(),
        min_samples_for_inference: Some(3),
        api_title: Some("Demo API".to_string()),
        api_version: Some("1.0.0".to_string()),
        api_description: Some("A demonstration API for DevDocs Pro".to_string()),
        base_url: Some("https://api.demo.com".to_string()),
        ..Default::default()
    }
}

/// Demonstrate traffic analysis capabilities
async fn demonstrate_traffic_analysis() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📊 Demonstrating Traffic Analysis");
    println!("----------------------------------");

    // Create analysis configuration
    let analysis_config = AnalysisConfig {
        schema_inference_enabled: true,
        min_samples_for_inference: 3,
        ai_documentation_enabled: std::env::var("GEMINI_API_KEY").is_ok(),
        confidence_threshold: 0.8,
        max_body_size: 10 * 1024 * 1024,
        endpoint_detection_enabled: true,
    };

    // Create traffic analyzer
    let mut analyzer = TrafficAnalyzer::new(analysis_config)?;
    println!("✅ Traffic analyzer created");

    // Generate sample traffic data
    let samples = generate_sample_traffic().await;
    println!("✅ Generated {} traffic samples", samples.len());

    // Analyze traffic
    let analysis_result = analyzer.analyze_traffic(samples).await?;
    
    println!("📈 Analysis Results:");
    println!("  - Endpoints discovered: {}", analysis_result.endpoints.len());
    println!("  - Schemas inferred: {}", analysis_result.schemas.len());
    println!("  - Confidence score: {:.2}", analysis_result.confidence);
    println!("  - Samples analyzed: {}", analysis_result.samples_analyzed);

    // Display endpoint details
    for endpoint in &analysis_result.endpoints {
        println!("  📍 {} {} - {} requests, {:.1}ms avg, {:.1}% success",
            endpoint.method,
            endpoint.path_pattern,
            endpoint.request_count,
            endpoint.avg_response_time_ms,
            endpoint.success_rate()
        );
    }

    // Display schema details
    for (name, schema) in &analysis_result.schemas {
        println!("  📋 Schema '{}': {} properties",
            name,
            schema.get("properties")
                .and_then(|p| p.as_object())
                .map(|o| o.len())
                .unwrap_or(0)
        );
    }

    if let Some(ai_docs) = &analysis_result.documentation {
        println!("  🤖 AI Documentation generated ({} characters)", ai_docs.len());
    }

    Ok(())
}

/// Demonstrate documentation generation
async fn demonstrate_documentation_generation() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📚 Demonstrating Documentation Generation");
    println!("------------------------------------------");

    // Create documentation configuration
    let doc_config = DocumentationConfig {
        title: "Demo API Documentation".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Comprehensive API documentation generated from traffic analysis".to_string()),
        base_url: Some("https://api.demo.com".to_string()),
        contact: Some(devdocs_core::documentation::ContactInfo {
            name: Some("API Team".to_string()),
            email: Some("api@demo.com".to_string()),
            url: Some("https://demo.com/contact".to_string()),
        }),
        license: Some(devdocs_core::documentation::LicenseInfo {
            name: "MIT".to_string(),
            url: Some("https://opensource.org/licenses/MIT".to_string()),
        }),
        enable_interactive: true,
        enable_realtime_updates: true,
        custom_css: None,
        logo_url: Some("https://demo.com/logo.png".to_string()),
    };

    // Create documentation generator
    let doc_generator = DocumentationGenerator::new(doc_config)?;
    println!("✅ Documentation generator created");

    // Create sample analysis result
    let analysis_result = create_sample_analysis_result();

    // Generate documentation
    let documentation = doc_generator.generate_documentation(&analysis_result).await?;
    println!("✅ Documentation generated");

    // Display documentation info
    println!("📄 Generated Documentation:");
    println!("  - OpenAPI spec: {} paths",
        documentation.openapi_spec.get("paths")
            .and_then(|p| p.as_object())
            .map(|o| o.len())
            .unwrap_or(0)
    );
    println!("  - HTML content: {} characters", documentation.html_content.len());
    println!("  - Markdown content: {} characters", documentation.markdown_content.len());

    // Save documentation to files
    tokio::fs::write("demo_openapi.json", 
        serde_json::to_string_pretty(&documentation.openapi_spec)?).await?;
    tokio::fs::write("demo_documentation.html", &documentation.html_content).await?;
    tokio::fs::write("demo_documentation.md", &documentation.markdown_content).await?;
    
    println!("💾 Documentation saved to files:");
    println!("  - demo_openapi.json");
    println!("  - demo_documentation.html");
    println!("  - demo_documentation.md");

    Ok(())
}

/// Demonstrate complete middleware workflow
async fn demonstrate_middleware_workflow(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚙️  Demonstrating Complete Middleware Workflow");
    println!("-----------------------------------------------");

    // Create traffic processor (simulating middleware internals)
    let analysis_config = AnalysisConfig {
        schema_inference_enabled: true,
        min_samples_for_inference: 3,
        ai_documentation_enabled: config.gemini_api_key.is_some(),
        confidence_threshold: 0.8,
        max_body_size: 10 * 1024 * 1024,
        endpoint_detection_enabled: true,
    };

    let doc_config = DocumentationConfig {
        title: config.api_title.clone().unwrap_or_else(|| "API Documentation".to_string()),
        version: config.api_version.clone().unwrap_or_else(|| "1.0.0".to_string()),
        description: config.api_description.clone(),
        base_url: config.base_url.clone(),
        contact: None,
        license: None,
        enable_interactive: true,
        enable_realtime_updates: true,
        custom_css: None,
        logo_url: None,
    };

    let processor = TrafficProcessor::new(analysis_config, doc_config)?;
    println!("✅ Traffic processor created");

    // Simulate real-time traffic processing
    println!("🔄 Simulating real-time traffic...");
    
    let samples = generate_sample_traffic().await;
    for (i, sample) in samples.into_iter().enumerate() {
        processor.add_sample(sample).await?;
        
        if i % 2 == 0 {
            let stats = processor.get_sample_stats().await;
            println!("  📊 Stats: {} samples, {} endpoints, {:.1}ms avg response time",
                stats.total_samples,
                stats.endpoint_counts.len(),
                stats.avg_response_time
            );
        }

        // Small delay to simulate real traffic
        sleep(Duration::from_millis(100)).await;
    }

    // Force analysis and documentation generation
    println!("🔍 Triggering analysis and documentation generation...");
    let documentation = processor.force_analysis().await?;

    println!("✅ Workflow completed successfully!");
    println!("📊 Final Results:");
    println!("  - Total samples processed: {}", processor.sample_count());
    println!("  - Unique endpoints: {}", processor.endpoint_count());
    println!("  - Documentation generated at: {}", documentation.generated_at);

    // Save final documentation
    tokio::fs::write("workflow_openapi.json", 
        serde_json::to_string_pretty(&documentation.openapi_spec)?).await?;
    tokio::fs::write("workflow_documentation.html", &documentation.html_content).await?;
    
    println!("💾 Final documentation saved:");
    println!("  - workflow_openapi.json");
    println!("  - workflow_documentation.html");

    Ok(())
}

/// Generate sample traffic data for demonstration
async fn generate_sample_traffic() -> Vec<TrafficSample> {
    let mut samples = Vec::new();

    // Sample 1: GET /users (list users)
    let request1 = HttpRequest::new(
        "GET".to_string(),
        "/users".to_string(),
        "corr-001".to_string(),
    ).with_query_params({
        let mut params = HashMap::new();
        params.insert("page".to_string(), "1".to_string());
        params.insert("limit".to_string(), "10".to_string());
        params
    });

    let response_body1 = json!({
        "users": [
            {"id": 1, "name": "John Doe", "email": "john@example.com", "active": true},
            {"id": 2, "name": "Jane Smith", "email": "jane@example.com", "active": true}
        ],
        "pagination": {
            "page": 1,
            "limit": 10,
            "total": 25
        }
    });

    let captured_body1 = CapturedBody {
        content_type: Some("application/json".to_string()),
        compression: CompressionType::None,
        priority: ContentPriority::High,
        original_size: response_body1.to_string().len(),
        storage: BodyStorage::Memory(response_body1.to_string().into_bytes()),
    };

    let response1 = HttpResponse::new(request1.id, 200)
        .with_processing_time(150)
        .with_body(captured_body1);

    samples.push(TrafficSample::new(request1, "/users".to_string()).with_response(response1));

    // Sample 2: GET /users/{id} (get specific user)
    let request2 = HttpRequest::new(
        "GET".to_string(),
        "/users/123".to_string(),
        "corr-002".to_string(),
    );

    let response_body2 = json!({
        "id": 123,
        "name": "John Doe",
        "email": "john@example.com",
        "active": true,
        "created_at": "2023-01-15T10:30:00Z",
        "profile": {
            "bio": "Software developer",
            "location": "San Francisco"
        }
    });

    let captured_body2 = CapturedBody {
        content_type: Some("application/json".to_string()),
        compression: CompressionType::None,
        priority: ContentPriority::High,
        original_size: response_body2.to_string().len(),
        storage: BodyStorage::Memory(response_body2.to_string().into_bytes()),
    };

    let response2 = HttpResponse::new(request2.id, 200)
        .with_processing_time(75)
        .with_body(captured_body2);

    samples.push(TrafficSample::new(request2, "/users/{id}".to_string()).with_response(response2));

    // Sample 3: POST /users (create user)
    let request_body3 = json!({
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "password": "secure123",
        "profile": {
            "bio": "Product manager",
            "location": "New York"
        }
    });

    let captured_request_body3 = CapturedBody {
        content_type: Some("application/json".to_string()),
        compression: CompressionType::None,
        priority: ContentPriority::High,
        original_size: request_body3.to_string().len(),
        storage: BodyStorage::Memory(request_body3.to_string().into_bytes()),
    };

    let request3 = HttpRequest::new(
        "POST".to_string(),
        "/users".to_string(),
        "corr-003".to_string(),
    ).with_body(captured_request_body3);

    let response_body3 = json!({
        "id": 456,
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "active": true,
        "created_at": "2023-12-01T14:22:00Z"
    });

    let captured_response_body3 = CapturedBody {
        content_type: Some("application/json".to_string()),
        compression: CompressionType::None,
        priority: ContentPriority::High,
        original_size: response_body3.to_string().len(),
        storage: BodyStorage::Memory(response_body3.to_string().into_bytes()),
    };

    let response3 = HttpResponse::new(request3.id, 201)
        .with_processing_time(200)
        .with_body(captured_response_body3);

    samples.push(TrafficSample::new(request3, "/users".to_string()).with_response(response3));

    // Sample 4: PUT /users/{id} (update user)
    let request_body4 = json!({
        "name": "John Doe Updated",
        "email": "john.doe@example.com",
        "profile": {
            "bio": "Senior software developer",
            "location": "San Francisco, CA"
        }
    });

    let captured_request_body4 = CapturedBody {
        content_type: Some("application/json".to_string()),
        compression: CompressionType::None,
        priority: ContentPriority::High,
        original_size: request_body4.to_string().len(),
        storage: BodyStorage::Memory(request_body4.to_string().into_bytes()),
    };

    let request4 = HttpRequest::new(
        "PUT".to_string(),
        "/users/123".to_string(),
        "corr-004".to_string(),
    ).with_body(captured_request_body4);

    let response_body4 = json!({
        "id": 123,
        "name": "John Doe Updated",
        "email": "john.doe@example.com",
        "active": true,
        "updated_at": "2023-12-01T15:45:00Z"
    });

    let captured_response_body4 = CapturedBody {
        content_type: Some("application/json".to_string()),
        compression: CompressionType::None,
        priority: ContentPriority::High,
        original_size: response_body4.to_string().len(),
        storage: BodyStorage::Memory(response_body4.to_string().into_bytes()),
    };

    let response4 = HttpResponse::new(request4.id, 200)
        .with_processing_time(120)
        .with_body(captured_response_body4);

    samples.push(TrafficSample::new(request4, "/users/{id}".to_string()).with_response(response4));

    // Sample 5: DELETE /users/{id} (delete user)
    let request5 = HttpRequest::new(
        "DELETE".to_string(),
        "/users/456".to_string(),
        "corr-005".to_string(),
    );

    let response5 = HttpResponse::new(request5.id, 204)
        .with_processing_time(90);

    samples.push(TrafficSample::new(request5, "/users/{id}".to_string()).with_response(response5));

    samples
}

/// Create a sample analysis result for demonstration
fn create_sample_analysis_result() -> devdocs_core::analysis::AnalysisResult {
    use devdocs_core::models::ApiEndpoint;
    use uuid::Uuid;

    let mut endpoints = Vec::new();
    
    // Create sample endpoints
    let mut endpoint1 = ApiEndpoint::new("/users".to_string(), "GET".to_string());
    endpoint1.increment_request(150.0, 200);
    endpoint1.increment_request(140.0, 200);
    endpoints.push(endpoint1);

    let mut endpoint2 = ApiEndpoint::new("/users/{id}".to_string(), "GET".to_string());
    endpoint2.increment_request(75.0, 200);
    endpoint2.increment_request(80.0, 200);
    endpoint2.increment_request(85.0, 404);
    endpoints.push(endpoint2);

    let mut endpoint3 = ApiEndpoint::new("/users".to_string(), "POST".to_string());
    endpoint3.increment_request(200.0, 201);
    endpoints.push(endpoint3);

    // Create sample schemas
    let mut schemas = HashMap::new();
    schemas.insert("users_response".to_string(), json!({
        "type": "object",
        "properties": {
            "users": {
                "type": "array",
                "items": {
                    "$ref": "#/components/schemas/User"
                }
            },
            "pagination": {
                "$ref": "#/components/schemas/Pagination"
            }
        }
    }));

    schemas.insert("User".to_string(), json!({
        "type": "object",
        "required": ["id", "name", "email"],
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"},
            "active": {"type": "boolean"},
            "created_at": {"type": "string", "format": "date-time"},
            "profile": {
                "$ref": "#/components/schemas/UserProfile"
            }
        }
    }));

    devdocs_core::analysis::AnalysisResult {
        id: Uuid::new_v4(),
        endpoints,
        schemas,
        documentation: Some("# Demo API\n\nThis is a demonstration API showing user management capabilities.".to_string()),
        confidence: 0.95,
        samples_analyzed: 5,
        timestamp: chrono::Utc::now(),
    }
}