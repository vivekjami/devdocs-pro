//! Traffic sampling strategies for controlling data collection

use devdocs_core::models::HttpTransaction;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Trait for sampling strategies
pub trait SamplingStrategy: Send + Sync {
    /// Determine if a transaction should be sampled
    fn should_sample(&self, transaction: &HttpTransaction) -> bool;

    /// Get the current sampling rate
    fn sampling_rate(&self) -> f64;

    /// Reset sampling state if applicable
    fn reset(&self);
}

/// Percentage-based sampling strategy
pub struct PercentageSampling {
    /// Sampling rate (0.0 to 1.0)
    rate: f64,
    
    /// Request counter for deterministic sampling
    counter: AtomicUsize,
}

impl PercentageSampling {
    /// Create a new percentage sampling strategy
    #[must_use]
    pub fn new(rate: f64) -> Self {
        let rate = rate.clamp(0.0, 1.0);
        Self {
            rate,
            counter: AtomicUsize::new(0),
        }
    }
}

impl SamplingStrategy for PercentageSampling {
    fn should_sample(&self, _transaction: &HttpTransaction) -> bool {
        if self.rate >= 1.0 {
            return true;
        }
        
        if self.rate <= 0.0 {
            return false;
        }
        
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        let threshold = (1.0 / self.rate) as usize;
        
        count % threshold == 0
    }

    fn sampling_rate(&self) -> f64 {
        self.rate
    }

    fn reset(&self) {
        self.counter.store(0, Ordering::Relaxed);
    }
}

/// Rate-limited sampling strategy
pub struct RateLimitedSampling {
    /// Maximum requests per second
    max_rps: usize,
    
    /// Current second timestamp
    current_second: AtomicUsize,
    
    /// Request count for current second
    current_count: AtomicUsize,
}

impl RateLimitedSampling {
    /// Create a new rate-limited sampling strategy
    #[must_use]
    pub fn new(max_rps: usize) -> Self {
        let current_second = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
            
        Self {
            max_rps,
            current_second: AtomicUsize::new(current_second),
            current_count: AtomicUsize::new(0),
        }
    }
}

impl SamplingStrategy for RateLimitedSampling {
    fn should_sample(&self, _transaction: &HttpTransaction) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
            
        let current_second = self.current_second.load(Ordering::Relaxed);
        
        if now != current_second {
            // New second, reset counters
            self.current_second.store(now, Ordering::Relaxed);
            self.current_count.store(0, Ordering::Relaxed);
        }
        
        let count = self.current_count.fetch_add(1, Ordering::Relaxed);
        count < self.max_rps
    }

    fn sampling_rate(&self) -> f64 {
        // Rate varies based on traffic, return configured max rate
        1.0
    }

    fn reset(&self) {
        self.current_count.store(0, Ordering::Relaxed);
    }
}

/// Endpoint-specific sampling strategy
pub struct EndpointSampling {
    /// Default sampling rate
    default_rate: f64,
    
    /// Per-endpoint sampling rates
    endpoint_rates: std::collections::HashMap<String, f64>,
    
    /// Request counters per endpoint
    counters: std::sync::RwLock<std::collections::HashMap<String, AtomicUsize>>,
}

impl EndpointSampling {
    /// Create a new endpoint-specific sampling strategy
    #[must_use]
    pub fn new(default_rate: f64) -> Self {
        Self {
            default_rate: default_rate.clamp(0.0, 1.0),
            endpoint_rates: std::collections::HashMap::new(),
            counters: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
    
    /// Set sampling rate for a specific endpoint
    pub fn set_endpoint_rate(&mut self, endpoint: String, rate: f64) {
        self.endpoint_rates.insert(endpoint, rate.clamp(0.0, 1.0));
    }
    
    /// Get the endpoint key for a transaction
    fn endpoint_key(&self, transaction: &HttpTransaction) -> String {
        format!("{} {}", transaction.request.method, transaction.request.path)
    }
}

impl SamplingStrategy for EndpointSampling {
    fn should_sample(&self, transaction: &HttpTransaction) -> bool {
        let endpoint = self.endpoint_key(transaction);
        let rate = self.endpoint_rates.get(&endpoint).copied().unwrap_or(self.default_rate);
        
        if rate >= 1.0 {
            return true;
        }
        
        if rate <= 0.0 {
            return false;
        }
        
        // Get or create counter for this endpoint
        let counter = {
            let mut counters = self.counters.write().unwrap();
            counters.entry(endpoint.clone()).or_insert_with(|| AtomicUsize::new(0));
            counters.get(&endpoint).unwrap().clone()
        };
        
        let count = counter.load(Ordering::Relaxed);
        counter.store(count.wrapping_add(1), Ordering::Relaxed);
        
        let threshold = (1.0 / rate) as usize;
        count % threshold == 0
    }

    fn sampling_rate(&self) -> f64 {
        self.default_rate
    }

    fn reset(&self) {
        let mut counters = self.counters.write().unwrap();
        for counter in counters.values() {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

/// Combined sampling strategy that uses multiple strategies
pub struct CombinedSampling {
    strategies: Vec<Box<dyn SamplingStrategy>>,
}

impl CombinedSampling {
    /// Create a new combined sampling strategy
    #[must_use]
    pub fn new() -> Self {
        Self {
            strategies: Vec::new(),
        }
    }
    
    /// Add a sampling strategy
    pub fn add_strategy(mut self, strategy: Box<dyn SamplingStrategy>) -> Self {
        self.strategies.push(strategy);
        self
    }
}

impl Default for CombinedSampling {
    fn default() -> Self {
        Self::new()
    }
}

impl SamplingStrategy for CombinedSampling {
    fn should_sample(&self, transaction: &HttpTransaction) -> bool {
        if self.strategies.is_empty() {
            return true;
        }
        
        // All strategies must agree to sample
        self.strategies.iter().all(|strategy| strategy.should_sample(transaction))
    }

    fn sampling_rate(&self) -> f64 {
        if self.strategies.is_empty() {
            return 1.0;
        }
        
        // Return the most restrictive (lowest) rate
        self.strategies
            .iter()
            .map(|s| s.sampling_rate())
            .fold(1.0, f64::min)
    }

    fn reset(&self) {
        for strategy in &self.strategies {
            strategy.reset();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use devdocs_core::models::{Request, Response};

    fn create_test_transaction() -> HttpTransaction {
        let request = Request::new("GET".to_string(), "/test".to_string(), "".to_string());
        let response = Response::new(200, "OK".to_string(), "".to_string());
        HttpTransaction::new(request, response)
    }

    #[test]
    fn test_percentage_sampling() {
        let strategy = PercentageSampling::new(0.5);
        let transaction = create_test_transaction();
        
        // With 50% sampling, roughly half should be sampled
        let mut sampled = 0;
        for _ in 0..100 {
            if strategy.should_sample(&transaction) {
                sampled += 1;
            }
        }
        
        // Should be around 50, allow some variance
        assert!(sampled >= 40 && sampled <= 60);
    }

    #[test]
    fn test_rate_limited_sampling() {
        let strategy = RateLimitedSampling::new(5);
        let transaction = create_test_transaction();
        
        // First 5 should be sampled
        for _ in 0..5 {
            assert!(strategy.should_sample(&transaction));
        }
        
        // Next 5 should not be sampled (same second)
        for _ in 0..5 {
            assert!(!strategy.should_sample(&transaction));
        }
    }

    #[test]
    fn test_combined_sampling() {
        let percentage = Box::new(PercentageSampling::new(1.0)); // 100%
        let rate_limited = Box::new(RateLimitedSampling::new(2)); // 2 per second
        
        let strategy = CombinedSampling::new()
            .add_strategy(percentage)
            .add_strategy(rate_limited);
        
        let transaction = create_test_transaction();
        
        // Should be limited by rate limiter
        assert!(strategy.should_sample(&transaction));
        assert!(strategy.should_sample(&transaction));
        assert!(!strategy.should_sample(&transaction));
    }
}
