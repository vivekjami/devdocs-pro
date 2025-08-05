use devdocs_middleware::DevDocsMiddleware;
use devdocs_core::Config;
use hyper::{Body, Request, Response, StatusCode};
use tower::{ServiceBuilder, service_fn, ServiceExt};
use std::convert::Infallible;

async fn dummy_service(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Hello, World!"))
        .unwrap())
}

#[tokio::test]
async fn test_middleware_integration() {
    let config = Config {
        api_key: "test_key".to_string(),
        sampling_rate: 1.0, // 100% sampling for testing
        ..Default::default()
    };

    let (layer, mut middleware) = DevDocsMiddleware::new(config);
    
    // Create service with middleware
    let service = ServiceBuilder::new()
        .layer(layer)
        .service(service_fn(dummy_service));

    // Test request
    let request = Request::builder()
        .method("GET")
        .uri("/api/users/123?page=1")
        .body(Body::empty())
        .unwrap();

    // Process request in background
    tokio::spawn(async move {
        middleware.start_processing().await;
    });

    let response = service.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_path_exclusion() {
    let config = Config {
        api_key: "test_key".to_string(),
        sampling_rate: 1.0, // 100% sampling for testing
        excluded_paths: vec!["/health".to_string()],
        ..Default::default()
    };

    let (layer, _middleware) = DevDocsMiddleware::new(config);
    
    // Create service with middleware
    let service = ServiceBuilder::new()
        .layer(layer)
        .service(service_fn(dummy_service));

    // Test excluded path
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = service.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
