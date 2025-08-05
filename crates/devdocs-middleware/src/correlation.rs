use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, Instant};
use devdocs_core::{HttpRequest, HttpResponse};

#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub request: HttpRequest,
    pub timestamp: Instant,
}

pub struct CorrelationTracker {
    pending_requests: Arc<Mutex<HashMap<String, PendingRequest>>>,
    cleanup_interval: Duration,
    request_timeout: Duration,
}

impl CorrelationTracker {
    pub fn new(cleanup_interval: Duration, request_timeout: Duration) -> Self {
        Self {
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            cleanup_interval,
            request_timeout,
        }
    }

    pub fn track_request(&self, request: HttpRequest) {
        let mut pending = self.pending_requests.lock().unwrap();
        pending.insert(
            request.correlation_id.clone(),
            PendingRequest {
                request,
                timestamp: Instant::now(),
            },
        );
    }

    pub fn correlate_response(&self, correlation_id: &str, _response: HttpResponse) -> Option<HttpRequest> {
        let mut pending = self.pending_requests.lock().unwrap();
        pending.remove(correlation_id).map(|pending_req| pending_req.request)
    }

    pub fn start_cleanup_task(&self) {
        let pending_requests = Arc::clone(&self.pending_requests);
        let cleanup_interval = self.cleanup_interval;
        let request_timeout = self.request_timeout;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                let now = Instant::now();
                let mut pending = pending_requests.lock().unwrap();
                
                // Remove timed-out requests
                pending.retain(|_, pending_req| {
                    now.duration_since(pending_req.timestamp) < request_timeout
                });
                
                let remaining_count = pending.len();
                if remaining_count > 0 {
                    tracing::debug!("Cleaned up timed-out requests, {} remaining", remaining_count);
                }
            }
        });
    }
}
