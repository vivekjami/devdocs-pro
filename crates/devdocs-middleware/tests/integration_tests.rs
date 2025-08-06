use devdocs_core::Config;
use devdocs_middleware::DevDocsMiddleware;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use std::convert::Infallible;
use tower::{service_fn, ServiceBuilder, ServiceExt};

async fn dummy_service<B>(_req: Request<B>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from("Hello, World!")))
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
        .body(Full::new(Bytes::new()))
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
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = service.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
