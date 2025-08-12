//! Advanced rate limiting and DDoS protection system

use crate::errors::DevDocsError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Global rate limits
    pub global: GlobalRateLimits,
    /// Per-user rate limits
    pub per_user: PerUserRateLimits,
    /// Per-IP rate limits
    pub per_ip: PerIpRateLimits,
    /// DDoS protection settings
    pub ddos_protection: DdosProtectionConfig,
    /// Burst handling
    pub burst_handling: BurstHandlingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRateLimits {
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub requests_per_day: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerUserRateLimits {
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub requests_per_day: u32,
    pub concurrent_requests: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerIpRateLimits {
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub concurrent_requests: u32,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosProtectionConfig {
    pub enabled: bool,
    pub detection_threshold: u32,
    pub detection_window_seconds: u32,
    pub block_duration_seconds: u32,
    pub auto_block_suspicious_ips: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstHandlingConfig {
    pub allow_bursts: bool,
    pub burst_size: u32,
    pub burst_replenish_rate: u32,
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global: GlobalRateLimits {
                requests_per_second: 1000,
                requests_per_minute: 10000,
                requests_per_hour: 100000,
                requests_per_day: 1000000,
            },
            per_user: PerUserRateLimits {
                requests_per_second: 100,
                requests_per_minute: 1000,
                requests_per_hour: 10000,
                requests_per_day: 100000,
                concurrent_requests: 50,
            },
            per_ip: PerIpRateLimits {
                requests_per_second: 50,
                requests_per_minute: 500,
                requests_per_hour: 5000,
                concurrent_requests: 20,
                whitelist: Vec::new(),
                blacklist: Vec::new(),
            },
            ddos_protection: DdosProtectionConfig {
                enabled: true,
                detection_threshold: 1000,
                detection_window_seconds: 60,
                block_duration_seconds: 3600,
                auto_block_suspicious_ips: true,
            },
            burst_handling: BurstHandlingConfig {
                allow_bursts: true,
                burst_size: 10,
                burst_replenish_rate: 1,
            },
        }
    }
}

/// Simple rate limiter implementation using token bucket algorithm
pub struct RateLimiter {
    config: RateLimitingConfig,
    user_buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    ip_buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
    global_bucket: Arc<RwLock<TokenBucket>>,
    blocked_ips: Arc<RwLock<HashMap<IpAddr, chrono::DateTime<chrono::Utc>>>>,
    request_counts: Arc<RwLock<HashMap<IpAddr, Vec<chrono::DateTime<chrono::Utc>>>>>,
}

/// Simple token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            tokens: capacity as f64,
            capacity: capacity as f64,
            refill_rate: refill_rate as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * self.refill_rate;

        self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
        self.last_refill = now;
    }
}

impl RateLimiter {
    pub fn new(config: &RateLimitingConfig) -> Result<Self, DevDocsError> {
        let global_bucket = TokenBucket::new(
            config.global.requests_per_second,
            config.global.requests_per_second,
        );

        Ok(Self {
            config: config.clone(),
            global_bucket: Arc::new(RwLock::new(global_bucket)),
            user_buckets: Arc::new(RwLock::new(HashMap::new())),
            ip_buckets: Arc::new(RwLock::new(HashMap::new())),
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
            request_counts: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Check if request should be rate limited
    pub async fn check_rate_limit(&self, ip: &str) -> Result<(), DevDocsError> {
        if !self.config.enabled {
            return Ok(());
        }

        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| DevDocsError::RateLimit("Invalid IP address".to_string()))?;

        // Check if IP is blocked
        if self.is_ip_blocked(&ip_addr).await {
            return Err(DevDocsError::RateLimit("IP address is blocked".to_string()));
        }

        // Check if IP is blacklisted
        if self.is_ip_blacklisted(ip) {
            return Err(DevDocsError::RateLimit(
                "IP address is blacklisted".to_string(),
            ));
        }

        // Skip rate limiting for whitelisted IPs
        if self.is_ip_whitelisted(ip) {
            return Ok(());
        }

        // Check global rate limit
        {
            let mut global_bucket = self.global_bucket.write().await;
            if !global_bucket.try_consume(1.0) {
                return Err(DevDocsError::RateLimit(
                    "Global rate limit exceeded".to_string(),
                ));
            }
        }

        // Check per-IP rate limit
        self.check_ip_rate_limit(&ip_addr).await?;

        // Update request tracking for DDoS detection
        if self.config.ddos_protection.enabled {
            self.track_request(&ip_addr).await;
            self.check_ddos_protection(&ip_addr).await?;
        }

        Ok(())
    }

    /// Check rate limit for specific user
    pub async fn check_user_rate_limit(&self, user_id: &str) -> Result<(), DevDocsError> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut user_buckets = self.user_buckets.write().await;

        let bucket = user_buckets.entry(user_id.to_string()).or_insert_with(|| {
            TokenBucket::new(
                self.config.per_user.requests_per_second,
                self.config.per_user.requests_per_second,
            )
        });

        if !bucket.try_consume(1.0) {
            return Err(DevDocsError::RateLimit(
                "User rate limit exceeded".to_string(),
            ));
        }

        Ok(())
    }

    /// Block IP address for specified duration
    pub async fn block_ip(&self, ip: &IpAddr, duration_seconds: u32) {
        let block_until = chrono::Utc::now() + chrono::Duration::seconds(duration_seconds as i64);
        let mut blocked_ips = self.blocked_ips.write().await;
        blocked_ips.insert(*ip, block_until);
    }

    /// Unblock IP address
    pub async fn unblock_ip(&self, ip: &IpAddr) {
        let mut blocked_ips = self.blocked_ips.write().await;
        blocked_ips.remove(ip);
    }

    /// Get rate limiting statistics
    pub async fn get_statistics(&self) -> RateLimitStatistics {
        let blocked_ips = self.blocked_ips.read().await;
        let user_buckets = self.user_buckets.read().await;
        let ip_buckets = self.ip_buckets.read().await;

        RateLimitStatistics {
            blocked_ips_count: blocked_ips.len(),
            active_user_limiters: user_buckets.len(),
            active_ip_limiters: ip_buckets.len(),
            global_limiter_state: "active".to_string(),
        }
    }

    async fn check_ip_rate_limit(&self, ip: &IpAddr) -> Result<(), DevDocsError> {
        let mut ip_buckets = self.ip_buckets.write().await;

        let bucket = ip_buckets.entry(*ip).or_insert_with(|| {
            TokenBucket::new(
                self.config.per_ip.requests_per_second,
                self.config.per_ip.requests_per_second,
            )
        });

        if !bucket.try_consume(1.0) {
            return Err(DevDocsError::RateLimit(
                "IP rate limit exceeded".to_string(),
            ));
        }

        Ok(())
    }

    async fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        let blocked_ips = self.blocked_ips.read().await;

        if let Some(block_until) = blocked_ips.get(ip) {
            if chrono::Utc::now() < *block_until {
                return true;
            }
        }

        false
    }

    fn is_ip_whitelisted(&self, ip: &str) -> bool {
        self.config.per_ip.whitelist.contains(&ip.to_string())
    }

    fn is_ip_blacklisted(&self, ip: &str) -> bool {
        self.config.per_ip.blacklist.contains(&ip.to_string())
    }

    async fn track_request(&self, ip: &IpAddr) {
        let now = chrono::Utc::now();
        let mut request_counts = self.request_counts.write().await;

        let requests = request_counts.entry(*ip).or_insert_with(Vec::new);
        requests.push(now);

        // Clean up old requests outside the detection window
        let cutoff = now
            - chrono::Duration::seconds(
                self.config.ddos_protection.detection_window_seconds as i64,
            );
        requests.retain(|&timestamp| timestamp > cutoff);
    }

    async fn check_ddos_protection(&self, ip: &IpAddr) -> Result<(), DevDocsError> {
        let request_counts = self.request_counts.read().await;

        if let Some(requests) = request_counts.get(ip) {
            if requests.len() > self.config.ddos_protection.detection_threshold as usize {
                if self.config.ddos_protection.auto_block_suspicious_ips {
                    drop(request_counts);
                    self.block_ip(ip, self.config.ddos_protection.block_duration_seconds)
                        .await;
                }
                return Err(DevDocsError::RateLimit(
                    "DDoS protection triggered".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Cleanup expired blocks and old request tracking data
    pub async fn cleanup(&self) {
        let now = chrono::Utc::now();

        // Clean up expired IP blocks
        {
            let mut blocked_ips = self.blocked_ips.write().await;
            blocked_ips.retain(|_, block_until| now < *block_until);
        }

        // Clean up old request tracking data
        {
            let mut request_counts = self.request_counts.write().await;
            let cutoff = now
                - chrono::Duration::seconds(
                    self.config.ddos_protection.detection_window_seconds as i64,
                );

            for requests in request_counts.values_mut() {
                requests.retain(|&timestamp| timestamp > cutoff);
            }

            // Remove empty entries
            request_counts.retain(|_, requests| !requests.is_empty());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStatistics {
    pub blocked_ips_count: usize,
    pub active_user_limiters: usize,
    pub active_ip_limiters: usize,
    pub global_limiter_state: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_rate_limiting_config_default() {
        let config = RateLimitingConfig::default();
        assert!(config.enabled);
        assert_eq!(config.global.requests_per_second, 1000);
        assert!(config.ddos_protection.enabled);
    }

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let config = RateLimitingConfig::default();
        let limiter = RateLimiter::new(&config);
        assert!(limiter.is_ok());
    }

    #[tokio::test]
    async fn test_ip_rate_limiting() {
        let mut config = RateLimitingConfig::default();
        config.per_ip.requests_per_second = 1; // Very low limit for testing

        let limiter = RateLimiter::new(&config).unwrap();

        // First request should succeed
        let result1 = limiter.check_rate_limit("192.168.1.1").await;
        assert!(result1.is_ok());

        // Second request should be rate limited
        let result2 = limiter.check_rate_limit("192.168.1.1").await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_ip_whitelisting() {
        let mut config = RateLimitingConfig::default();
        config.per_ip.requests_per_second = 1;
        config.per_ip.whitelist.push("192.168.1.100".to_string());

        let limiter = RateLimiter::new(&config).unwrap();

        // Whitelisted IP should not be rate limited
        for _ in 0..10 {
            let result = limiter.check_rate_limit("192.168.1.100").await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_ip_blacklisting() {
        let mut config = RateLimitingConfig::default();
        config.per_ip.blacklist.push("192.168.1.200".to_string());

        let limiter = RateLimiter::new(&config).unwrap();

        // Blacklisted IP should be immediately blocked
        let result = limiter.check_rate_limit("192.168.1.200").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ip_blocking() {
        let config = RateLimitingConfig::default();
        let limiter = RateLimiter::new(&config).unwrap();

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Block IP for 1 second
        limiter.block_ip(&ip, 1).await;

        // Should be blocked
        let result = limiter.check_rate_limit("192.168.1.1").await;
        assert!(result.is_err());

        // Wait for block to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be unblocked now
        let result = limiter.check_rate_limit("192.168.1.1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_user_rate_limiting() {
        let mut config = RateLimitingConfig::default();
        config.per_user.requests_per_second = 1;

        let limiter = RateLimiter::new(&config).unwrap();

        // First request should succeed
        let result1 = limiter.check_user_rate_limit("user123").await;
        assert!(result1.is_ok());

        // Second request should be rate limited
        let result2 = limiter.check_user_rate_limit("user123").await;
        assert!(result2.is_err());

        // Different user should not be affected
        let result3 = limiter.check_user_rate_limit("user456").await;
        assert!(result3.is_ok());
    }

    #[tokio::test]
    async fn test_statistics() {
        let config = RateLimitingConfig::default();
        let limiter = RateLimiter::new(&config).unwrap();

        // Generate some activity
        let _ = limiter.check_rate_limit("192.168.1.1").await;
        let _ = limiter.check_user_rate_limit("user123").await;

        let stats = limiter.get_statistics().await;
        assert_eq!(stats.blocked_ips_count, 0);
        assert!(stats.active_ip_limiters > 0 || stats.active_user_limiters > 0);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let config = RateLimitingConfig::default();
        let limiter = RateLimiter::new(&config).unwrap();

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Block IP for a very short time
        limiter.block_ip(&ip, 1).await;

        // Wait for block to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Run cleanup
        limiter.cleanup().await;

        // Check that expired blocks are cleaned up
        let stats = limiter.get_statistics().await;
        assert_eq!(stats.blocked_ips_count, 0);
    }

    #[tokio::test]
    async fn test_disabled_rate_limiting() {
        let config = RateLimitingConfig {
            enabled: false,
            ..Default::default()
        };

        let limiter = RateLimiter::new(&config).unwrap();

        // Should allow unlimited requests when disabled
        for _ in 0..1000 {
            let result = limiter.check_rate_limit("192.168.1.1").await;
            assert!(result.is_ok());
        }
    }
}
