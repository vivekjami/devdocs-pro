use devdocs_core::Config;
use devdocs_middleware::DevDocsMiddleware;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response, Result as HyperResult};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn hello_world(_req: Request<Incoming>) -> HyperResult<Response<Full<Bytes>>> {
    Ok(Response::new(Full::new(Bytes::from("Hello, World!"))))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let config = Config::from_env()?;
    let (_layer, mut middleware) = DevDocsMiddleware::new(config)?;

    // Start middleware processing in background (now includes AI processing)
    tokio::spawn(async move {
        println!("Starting DevDocs middleware with AI processing");
        let _ = middleware.start_processing().await;
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;
    println!("Server running on http://{}", addr);

    // For this example, let's use a simpler approach without body capture initially
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            let conn = ConnBuilder::new(TokioExecutor::new());

            if let Err(err) = conn
                .serve_connection_with_upgrades(io, service_fn(hello_world))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
