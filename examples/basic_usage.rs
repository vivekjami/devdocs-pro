use devdocs_middleware::DevDocsMiddleware;
use devdocs_core::Config;
use hyper::{Body, Request, Response, Server};
use hyper::service::make_service_fn;
use tower::ServiceBuilder;
use std::convert::Infallible;
use std::net::SocketAddr;

async fn hello_world(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::from("Hello, World!")))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let config = Config::from_env()?;
    let (layer, mut middleware) = DevDocsMiddleware::new(config);

    // Start middleware processing in background
    tokio::spawn(async move {
        middleware.start_processing().await;
    });

    // Create service with middleware
    let make_svc = make_service_fn(|_conn| {
        let layer = layer.clone();
        async move {
            Ok::<_, Infallible>(
                ServiceBuilder::new()
                    .layer(layer)
                    .service_fn(hello_world)
            )
        }
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let server = Server::bind(&addr).serve(make_svc);

    println!("Server running on http://{}", addr);
    
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }

    Ok(())
}
