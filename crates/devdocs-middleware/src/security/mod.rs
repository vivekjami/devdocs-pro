//! Security and PII detection functionality

use regex::Regex;
use std::collections::HashMap;
use tracing::{debug, warn};

/// PII detection and filtering service
pub struct PiiDetector {
    /// Compiled regex patterns for PII detection
    patterns: HashMap<PiiType, Regex>,
    
    /// Whether PII detection is enabled
    enabled: bool,
}

/// Types of PII that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PiiType {
    /// Email addresses
    Email,
    
    /// Phone numbers
    Phone,
    
    /// Social Security Numbers
    Ssn,
    
    /// Credit card numbers
    CreditCard,
    
    /// IP addresses
    IpAddress,
    
    /// Custom pattern
    Custom(String),
}

impl PiiDetector {
    /// Create a new PII detector with default patterns
    #[must_use]
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Email pattern
        if let Ok(email_regex) = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b") {
            patterns.insert(PiiType::Email, email_regex);
        }
        
        // Phone number pattern (US format)
        if let Ok(phone_regex) = Regex::new(r"\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b|\b\d{10}\b") {
            patterns.insert(PiiType::Phone, phone_regex);
        }
        
        // SSN pattern
        if let Ok(ssn_regex) = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b") {
            patterns.insert(PiiType::Ssn, ssn_regex);
        }
        
        // Credit card pattern (basic)
        if let Ok(cc_regex) = Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b") {
            patterns.insert(PiiType::CreditCard, cc_regex);
        }
        
        // IP address pattern
        if let Ok(ip_regex) = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b") {
            patterns.insert(PiiType::IpAddress, ip_regex);
        }
        
        Self {
            patterns,
            enabled: true,
        }
    }
    
    /// Enable or disable PII detection
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
    
    /// Add a custom PII pattern
    pub fn add_pattern(&mut self, name: String, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.patterns.insert(PiiType::Custom(name), regex);
        Ok(())
    }
    
    /// Detect PII in text
    pub fn detect_pii(&self, text: &str) -> Vec<PiiMatch> {
        if !self.enabled {
            return Vec::new();
        }
        
        let mut matches = Vec::new();
        
        for (pii_type, regex) in &self.patterns {
            for match_result in regex.find_iter(text) {
                matches.push(PiiMatch {
                    pii_type: pii_type.clone(),
                    start: match_result.start(),
                    end: match_result.end(),
                    value: match_result.as_str().to_string(),
                });
            }
        }
        
        matches.sort_by_key(|m| m.start);
        matches
    }
    
    /// Filter PII from text, replacing with placeholders
    pub fn filter_pii(&self, text: &str) -> (String, Vec<PiiMatch>) {
        let matches = self.detect_pii(text);
        
        if matches.is_empty() {
            return (text.to_string(), matches);
        }
        
        debug!("Found {} PII matches in text", matches.len());
        
        let mut filtered_text = text.to_string();
        
        // Replace matches in reverse order to maintain indices
        for pii_match in matches.iter().rev() {
            let placeholder = self.get_placeholder(&pii_match.pii_type);
            filtered_text.replace_range(pii_match.start..pii_match.end, &placeholder);
        }
        
        (filtered_text, matches)
    }
    
    /// Get placeholder text for a PII type
    fn get_placeholder(&self, pii_type: &PiiType) -> String {
        match pii_type {
            PiiType::Email => "[EMAIL_REDACTED]".to_string(),
            PiiType::Phone => "[PHONE_REDACTED]".to_string(),
            PiiType::Ssn => "[SSN_REDACTED]".to_string(),
            PiiType::CreditCard => "[CC_REDACTED]".to_string(),
            PiiType::IpAddress => "[IP_REDACTED]".to_string(),
            PiiType::Custom(name) => format!("[{}_REDACTED]", name.to_uppercase()),
        }
    }
}

impl Default for PiiDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a detected PII match
#[derive(Debug, Clone)]
pub struct PiiMatch {
    /// Type of PII detected
    pub pii_type: PiiType,
    
    /// Start position in the text
    pub start: usize,
    
    /// End position in the text
    pub end: usize,
    
    /// The matched value
    pub value: String,
}

/// Security filter for request/response data
pub struct SecurityFilter {
    /// PII detector
    pii_detector: PiiDetector,
    
    /// Headers to always redact
    sensitive_headers: Vec<String>,
    
    /// Query parameters to always redact
    sensitive_params: Vec<String>,
}

impl SecurityFilter {
    /// Create a new security filter
    #[must_use]
    pub fn new() -> Self {
        let sensitive_headers = vec![
            "authorization".to_string(),
            "cookie".to_string(),
            "set-cookie".to_string(),
            "x-api-key".to_string(),
            "x-auth-token".to_string(),
        ];
        
        let sensitive_params = vec![
            "password".to_string(),
            "token".to_string(),
            "api_key".to_string(),
            "secret".to_string(),
        ];
        
        Self {
            pii_detector: PiiDetector::new(),
            sensitive_headers,
            sensitive_params,
        }
    }
    
    /// Filter headers, redacting sensitive ones
    pub fn filter_headers(&self, headers: &HashMap<String, String>) -> HashMap<String, String> {
        let mut filtered = HashMap::new();
        
        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            
            if self.sensitive_headers.contains(&key_lower) {
                filtered.insert(key.clone(), "[REDACTED]".to_string());
            } else {
                let (filtered_value, matches) = self.pii_detector.filter_pii(value);
                if !matches.is_empty() {
                    warn!("PII detected in header '{}', filtered", key);
                }
                filtered.insert(key.clone(), filtered_value);
            }
        }
        
        filtered
    }
    
    /// Filter query parameters, redacting sensitive ones
    pub fn filter_query_params(&self, params: &HashMap<String, String>) -> HashMap<String, String> {
        let mut filtered = HashMap::new();
        
        for (key, value) in params {
            let key_lower = key.to_lowercase();
            
            if self.sensitive_params.contains(&key_lower) {
                filtered.insert(key.clone(), "[REDACTED]".to_string());
            } else {
                let (filtered_value, matches) = self.pii_detector.filter_pii(value);
                if !matches.is_empty() {
                    warn!("PII detected in query parameter '{}', filtered", key);
                }
                filtered.insert(key.clone(), filtered_value);
            }
        }
        
        filtered
    }
    
    /// Filter body content, removing PII
    pub fn filter_body(&self, body: &str) -> (String, bool) {
        let (filtered_body, matches) = self.pii_detector.filter_pii(body);
        let pii_found = !matches.is_empty();
        
        if pii_found {
            warn!("PII detected in body content, filtered {} matches", matches.len());
        }
        
        (filtered_body, pii_found)
    }
    
    /// Get reference to PII detector
    #[must_use]
    pub fn pii_detector(&self) -> &PiiDetector {
        &self.pii_detector
    }
    
    /// Get mutable reference to PII detector
    pub fn pii_detector_mut(&mut self) -> &mut PiiDetector {
        &mut self.pii_detector
    }
}

impl Default for SecurityFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        let detector = PiiDetector::new();
        let text = "Contact us at support@example.com for help";
        
        let matches = detector.detect_pii(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::Email);
        assert_eq!(matches[0].value, "support@example.com");
    }

    #[test]
    fn test_phone_detection() {
        let detector = PiiDetector::new();
        let text = "Call us at 555-123-4567 or (555) 987-6543";
        
        let matches = detector.detect_pii(text);
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.pii_type == PiiType::Phone));
    }

    #[test]
    fn test_pii_filtering() {
        let detector = PiiDetector::new();
        let text = "Email: john.doe@example.com, Phone: 555-123-4567";
        
        let (filtered, matches) = detector.filter_pii(text);
        assert_eq!(matches.len(), 2);
        assert!(filtered.contains("[EMAIL_REDACTED]"));
        assert!(filtered.contains("[PHONE_REDACTED]"));
    }

    #[test]
    fn test_security_filter_headers() {
        let filter = SecurityFilter::new();
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer token123".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        
        let filtered = filter.filter_headers(&headers);
        assert_eq!(filtered.get("Authorization"), Some(&"[REDACTED]".to_string()));
        assert_eq!(filtered.get("Content-Type"), Some(&"application/json".to_string()));
    }

    #[test]
    fn test_custom_pattern() {
        let mut detector = PiiDetector::new();
        detector.add_pattern("custom_id".to_string(), r"ID-\d{6}").unwrap();
        
        let text = "Your ID is ID-123456";
        let matches = detector.detect_pii(text);
        
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::Custom("custom_id".to_string()));
        assert_eq!(matches[0].value, "ID-123456");
    }
}
