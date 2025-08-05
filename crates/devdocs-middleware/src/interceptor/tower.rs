//! Tower middleware implementation for HTTP interception

use super::{HttpInterceptor, InterceptorConfig};
use devdocs_core::models::{HttpTransaction, Request, Response};
use devdocs_core::Result;
use http::{Request as HttpRequest, Response as HttpResponse};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tracing::{debug, warn};

/// Tower layer for DevDocs middleware
#[derive(Clone)]
pub struct DevDocsLayer {
    config: InterceptorConfig,
}

impl DevDocsLayer {
    /// Create a new DevDocs layer with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: InterceptorConfig::default(),
        }
    }

    /// Create a new DevDocs layer with custom configuration
    #[must_use]
    pub fn with_config(config: InterceptorConfig) -> Self {
        Self { config }
    }
}

impl Default for DevDocsLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for DevDocsLayer {
    type Service = DevDocsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DevDocsService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower service for DevDocs middleware
#[derive(Clone)]
pub struct DevDocsService<S> {
    inner: S,
    config: InterceptorConfig,
}

impl<S, ReqBody, ResBody> Service<HttpRequest<ReqBody>> for DevDocsService<S>
where
    S: Service<HttpRequest<ReqBody>, Response = HttpResponse<ResBody>>,
    ReqBody: hyper::body::Body + Send + 'static,
    ReqBody::Data: Send,
    ReqBody::Error: std::error::Error + Send + Sync,
    ResBody: hyper::body::Body + Send + 'static,
    ResBody::Data: Send,
    ResBody::Error: std::error::Error + Send + Sync,
{
    type Response = HttpResponse<ResBody>;
    type Error = S::Error;
    type Future = DevDocsFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: HttpRequest<ReqBody>) -> Self::Future {
        // Check if request should be excluded
        let path = request.uri().path();
        let should_exclude = self.config.should_exclude_path(path);

        if should_exclude {
            debug!("Excluding request to path: {}", path);
            return DevDocsFuture {
                inner: self.inner.call(request),
                should_process: false,
            };
        }

        // Check content type if available
        if let Some(content_type) = request
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
        {
            if self.config.should_exclude_content_type(content_type) {
                debug!("Excluding request with content type: {}", content_type);
                return DevDocsFuture {
                    inner: self.inner.call(request),
                    should_process: false,
                };
            }
        }

        debug!("Processing request to path: {}", path);

        DevDocsFuture {
            inner: self.inner.call(request),
            should_process: true,
        }
    }
}

/// Future wrapper for DevDocs processing
pub struct DevDocsFuture<F> {
    inner: F,
    should_process: bool,
}

impl<F, ResBody, E> std::future::Future for DevDocsFuture<F>
where
    F: std::future::Future<Output = Result<HttpResponse<ResBody>, E>>,
{
    type Output = Result<HttpResponse<ResBody>, E>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let inner = unsafe { std::pin::Pin::new_unchecked(&mut this.inner) };

        match inner.poll(cx) {
            Poll::Ready(result) => {
                if this.should_process {
                    if let Ok(response) = &result {
                        debug!("Response status: {}", response.status());
                        // TODO: Process the response and create HttpTransaction
                        // This will be implemented in the next phase
                    }
                }
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Basic HTTP interceptor implementation
pub struct BasicInterceptor {
    config: InterceptorConfig,
}

impl BasicInterceptor {
    /// Create a new basic interceptor
    #[must_use]
    pub fn new(config: InterceptorConfig) -> Self {
        Self { config }
    }
}

impl HttpInterceptor for BasicInterceptor {
    fn intercept_request(&self, request: &Request) -> Result<()> {
        debug!("Intercepted request: {} {}", request.method, request.path);

        if self.config.should_exclude_path(&request.path) {
            debug!("Request excluded by path filter");
            return Ok(());
        }

        if let Some(ref content_type) = request.content_type {
            if self.config.should_exclude_content_type(content_type) {
                debug!("Request excluded by content type filter");
                return Ok(());
            }
        }

        if self.config.exceeds_size_limit(request.body.len()) {
            warn!(
                "Request body size {} exceeds limit {}",
                request.body.len(),
                self.config.max_body_size
            );
            return Ok(());
        }

        // TODO: Process the request
        // This will be implemented in the next phase

        Ok(())
    }

    fn intercept_response(&self, response: &Response) -> Result<()> {
        debug!("Intercepted response: {}", response.status_code);

        if let Some(ref content_type) = response.content_type {
            if self.config.should_exclude_content_type(content_type) {
                debug!("Response excluded by content type filter");
                return Ok(());
            }
        }

        if self.config.exceeds_size_limit(response.body.len()) {
            warn!(
                "Response body size {} exceeds limit {}",
                response.body.len(),
                self.config.max_body_size
            );
            return Ok(());
        }

        // TODO: Process the response
        // This will be implemented in the next phase

        Ok(())
    }

    fn process_transaction(&self, transaction: HttpTransaction) -> Result<()> {
        debug!("Processing transaction: {}", transaction.id);

        // Verify transaction integrity
        if !transaction.verify_integrity() {
            warn!("Transaction {} failed integrity check", transaction.id);
            return Err(devdocs_core::DevDocsError::DataIntegrity(
                "Transaction integrity check failed".into(),
            ));
        }

        // TODO: Send to analysis pipeline
        // This will be implemented in the next phase

        Ok(())
    }
}
