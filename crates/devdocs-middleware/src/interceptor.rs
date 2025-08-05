use devdocs_core::{Config, HttpRequest, HttpResponse, TrafficSample};
use hyper::{Request, Response};
use std::task::{Context, Poll};
use tower::{Layer, Service};
use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct HttpInterceptor<S> {
    inner: S,
    config: Arc<Config>,
    sample_sender: mpsc::UnboundedSender<TrafficSample>,
}

impl<S> HttpInterceptor<S> {
    pub fn new(
        inner: S, 
        config: Arc<Config>,
        sample_sender: mpsc::UnboundedSender<TrafficSample>
    ) -> Self {
        Self { inner, config, sample_sender }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HttpInterceptor<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Default,
    ResBody: Default,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = InterceptorFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let start_time = std::time::Instant::now();
        let should_sample = self.config.should_sample();
        let correlation_id = Uuid::new_v4().to_string();
        
        // Extract request metadata before moving the request
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        
        // Check if path should be excluded
        let should_exclude = self.config.excluded_paths.iter()
            .any(|excluded| path.starts_with(excluded));
            
        let headers = req.headers().iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect::<HashMap<_, _>>();

        tracing::debug!(
            correlation_id = %correlation_id,
            method = %method,
            path = %path,
            should_sample = should_sample,
            "Processing request"
        );

        let future = self.inner.call(req);
        let config = Arc::clone(&self.config);
        let sender = self.sample_sender.clone();

        InterceptorFuture {
            future,
            start_time,
            should_sample: should_sample && !should_exclude,
            correlation_id,
            method,
            path,
            query,
            headers,
            config,
            sender,
        }
    }
}

pin_project_lite::pin_project! {
    pub struct InterceptorFuture<F> {
        #[pin]
        future: F,
        start_time: std::time::Instant,
        should_sample: bool,
        correlation_id: String,
        method: String,
        path: String,
        query: String,
        headers: HashMap<String, String>,
        config: Arc<Config>,
        sender: mpsc::UnboundedSender<TrafficSample>,
    }
}

impl<F, ResBody, E> std::future::Future for InterceptorFuture<F>
where
    F: std::future::Future<Output = Result<Response<ResBody>, E>>,
    ResBody: Default,
{
    type Output = Result<Response<ResBody>, E>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        
        match this.future.poll(cx) {
            Poll::Ready(result) => {
                let processing_time = this.start_time.elapsed();
                
                if *this.should_sample {
                    match result {
                        Ok(ref response) => {
                            // Create HTTP request record
                            let http_request = HttpRequest {
                                id: Uuid::new_v4(),
                                method: this.method.clone(),
                                path: this.path.clone(),
                                query_params: devdocs_core::utils::parse_query_params(&this.query),
                                headers: this.headers.clone(),
                                body: None, // Will be captured in body processing
                                timestamp: Utc::now(),
                                correlation_id: this.correlation_id.clone(),
                            };

                            // Create HTTP response record
                            let response_headers: HashMap<String, String> = response.headers().iter()
                                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                                .collect();

                            let http_response = HttpResponse {
                                id: Uuid::new_v4(),
                                request_id: http_request.id,
                                status_code: response.status().as_u16(),
                                headers: response_headers,
                                body: None, // Will be captured in body processing
                                timestamp: Utc::now(),
                                processing_time_ms: processing_time.as_millis() as u64,
                            };

                            // Create traffic sample
                            let sample = TrafficSample {
                                request: http_request,
                                response: Some(http_response),
                                endpoint_pattern: devdocs_core::utils::extract_endpoint_pattern(&this.path),
                            };

                            // Send sample for processing (non-blocking)
                            if let Err(e) = this.sender.send(sample) {
                                tracing::error!("Failed to send traffic sample: {}", e);
                            }
                        }
                        Err(_) => {
                            tracing::error!("Request failed for correlation_id: {}", this.correlation_id);
                        }
                    }
                }
                
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// Tower Layer implementation
#[derive(Clone)]
pub struct DevDocsLayer {
    config: Arc<Config>,
    sample_sender: mpsc::UnboundedSender<TrafficSample>,
}

impl DevDocsLayer {
    pub fn new(config: Config) -> (Self, mpsc::UnboundedReceiver<TrafficSample>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let layer = Self {
            config: Arc::new(config),
            sample_sender: sender,
        };
        (layer, receiver)
    }
}

impl<S> Layer<S> for DevDocsLayer {
    type Service = HttpInterceptor<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpInterceptor::new(inner, Arc::clone(&self.config), self.sample_sender.clone())
    }
}
