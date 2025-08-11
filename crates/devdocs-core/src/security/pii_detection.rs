//! Advanced PII detection and redaction system
//!
//! Uses machine learning models and regex patterns to detect and redact
//! personally identifiable information in API traffic.

use crate::errors::DevDocsError;
use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PII protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiProtectionConfig {
    /// Enable PII detection and redaction
    pub enabled: bool,
    /// Confidence threshold for PII detection (0.0 - 1.0)
    pub confidence_threshold: f64,
    /// Redaction strategy
    pub redaction_strategy: RedactionStrategy,
    /// Custom PII patterns
    pub custom_patterns: Vec<PiiPattern>,
    /// Enable machine learning-based detection
    pub enable_ml_detection: bool,
    /// Whitelist of fields that should never be redacted
    pub field_whitelist: Vec<String>,
    /// Enable context-aware detection
    pub enable_context_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedactionStrategy {
    /// Replace with asterisks (e.g., "john@example.com" -> "****@***.***")
    Asterisks,
    /// Replace with placeholder (e.g., "john@example.com" -> "[EMAIL_REDACTED]")
    Placeholder,
    /// Replace with hash (e.g., "john@example.com" -> "hash_abc123")
    Hash,
    /// Remove entirely
    Remove,
    /// Partial redaction (e.g., "john@example.com" -> "j***@example.com")
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiPattern {
    pub name: String,
    pub pattern: String,
    pub pii_type: PiiType,
    pub confidence: f64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PiiType {
    Email,
    Phone,
    Ssn,
    CreditCard,
    IpAddress,
    Name,
    Address,
    DateOfBirth,
    DriversLicense,
    Passport,
    BankAccount,
    Custom(u32),
}

impl Default for PiiProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            confidence_threshold: 0.7,
            redaction_strategy: RedactionStrategy::Placeholder,
            custom_patterns: Vec::new(),
            enable_ml_detection: true,
            field_whitelist: vec![
                "id".to_string(),
                "created_at".to_string(),
                "updated_at".to_string(),
                "version".to_string(),
            ],
            enable_context_detection: true,
        }
    }
}

/// PII detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiDetectionResult {
    pub detections: Vec<PiiDetection>,
    pub total_detections: usize,
    pub confidence_score: f64,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiDetection {
    pub pii_type: PiiType,
    pub field_path: String,
    pub start_pos: usize,
    pub end_pos: usize,
    pub confidence: f64,
    pub original_value: String,
    pub redacted_value: String,
    pub detection_method: DetectionMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMethod {
    Regex,
    MachineLearning,
    Context,
    Heuristic,
}

/// Advanced PII detector with multiple detection strategies
pub struct PiiDetector {
    config: PiiProtectionConfig,
    patterns: HashMap<PiiType, Vec<CompiledPattern>>,
    ml_model: Option<MlPiiModel>,
    context_analyzer: ContextAnalyzer,
}

struct CompiledPattern {
    regex: Regex,
    confidence: f64,
    name: String,
}

struct MlPiiModel {
    // Placeholder for ML model - in production would use actual ML framework
    model_version: String,
    confidence_threshold: f64,
}

struct ContextAnalyzer {
    field_name_patterns: HashMap<PiiType, Vec<String>>,
    value_patterns: HashMap<PiiType, Vec<String>>,
}

impl PiiDetector {
    pub fn new(config: &PiiProtectionConfig) -> Result<Self, DevDocsError> {
        let mut detector = Self {
            config: config.clone(),
            patterns: HashMap::new(),
            ml_model: None,
            context_analyzer: ContextAnalyzer::new(),
        };

        detector.initialize_patterns()?;

        if config.enable_ml_detection {
            detector.initialize_ml_model()?;
        }

        Ok(detector)
    }

    /// Scan data for PII and return detection results
    pub fn scan_data(&self, data: &[u8]) -> Result<PiiDetectionResult, DevDocsError> {
        if !self.config.enabled {
            return Ok(PiiDetectionResult {
                detections: Vec::new(),
                total_detections: 0,
                confidence_score: 0.0,
                processing_time_ms: 0,
            });
        }

        let start_time = std::time::Instant::now();
        let text = String::from_utf8_lossy(data);
        let mut detections = Vec::new();

        // Try to parse as JSON for structured analysis
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&text) {
            detections.extend(self.scan_json_value(&json_value, "")?);
        } else {
            // Fallback to plain text scanning
            detections.extend(self.scan_plain_text(&text)?);
        }

        // Apply ML detection if enabled
        if self.config.enable_ml_detection && self.ml_model.is_some() {
            detections.extend(self.ml_detect_pii(&text)?);
        }

        // Filter by confidence threshold
        detections.retain(|d| d.confidence >= self.config.confidence_threshold);

        // Calculate overall confidence score
        let confidence_score = if detections.is_empty() {
            0.0
        } else {
            detections.iter().map(|d| d.confidence).sum::<f64>() / detections.len() as f64
        };

        let processing_time = start_time.elapsed().as_millis() as u64;

        Ok(PiiDetectionResult {
            total_detections: detections.len(),
            detections,
            confidence_score,
            processing_time_ms: processing_time,
        })
    }

    /// Redact PII from data
    pub fn redact_pii(&self, data: &[u8]) -> Result<Vec<u8>, DevDocsError> {
        if !self.config.enabled {
            return Ok(data.to_vec());
        }

        let detection_result = self.scan_data(data)?;
        let text = String::from_utf8_lossy(data);

        // Try to parse as JSON for structured redaction
        if let Ok(mut json_value) = serde_json::from_str::<serde_json::Value>(&text) {
            for detection in &detection_result.detections {
                self.redact_json_field(
                    &mut json_value,
                    &detection.field_path,
                    &detection.redacted_value,
                )?;
            }
            Ok(serde_json::to_vec(&json_value)?)
        } else {
            // Fallback to plain text redaction
            let mut redacted_text = text.to_string();

            // Sort detections by position (descending) to avoid offset issues
            let mut sorted_detections = detection_result.detections;
            sorted_detections.sort_by(|a, b| b.start_pos.cmp(&a.start_pos));

            for detection in sorted_detections {
                redacted_text.replace_range(
                    detection.start_pos..detection.end_pos,
                    &detection.redacted_value,
                );
            }

            Ok(redacted_text.into_bytes())
        }
    }

    fn initialize_patterns(&mut self) -> Result<(), DevDocsError> {
        // Email patterns
        self.add_pattern(
            PiiType::Email,
            vec![
                (
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                    0.9,
                    "standard_email",
                ),
                (
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                    0.85,
                    "word_boundary_email",
                ),
            ],
        )?;

        // Phone number patterns
        self.add_pattern(
            PiiType::Phone,
            vec![
                (
                    r"\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
                    0.8,
                    "us_phone",
                ),
                (r"\+[1-9]\d{1,14}", 0.75, "international_phone"),
                (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", 0.7, "simple_phone"),
            ],
        )?;

        // SSN patterns
        self.add_pattern(
            PiiType::Ssn,
            vec![
                (r"\b\d{3}-\d{2}-\d{4}\b", 0.95, "ssn_dashes"),
                (r"\b\d{9}\b", 0.6, "ssn_no_dashes"), // Lower confidence due to false positives
            ],
        )?;

        // Credit card patterns
        self.add_pattern(PiiType::CreditCard, vec![
            (r"\b4[0-9]{12}(?:[0-9]{3})?\b", 0.9, "visa"),
            (r"\b5[1-5][0-9]{14}\b", 0.9, "mastercard"),
            (r"\b3[47][0-9]{13}\b", 0.9, "amex"),
            (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", 0.85, "general_cc"),
        ])?;

        // IP Address patterns
        self.add_pattern(
            PiiType::IpAddress,
            vec![
                (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", 0.8, "ipv4"),
                (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", 0.8, "ipv6"),
            ],
        )?;

        // Add custom patterns from config
        let custom_patterns = self.config.custom_patterns.clone();
        for custom_pattern in custom_patterns {
            if custom_pattern.enabled {
                self.add_pattern(
                    custom_pattern.pii_type,
                    vec![(
                        custom_pattern.pattern.as_str(),
                        custom_pattern.confidence,
                        custom_pattern.name.as_str(),
                    )],
                )?;
            }
        }

        Ok(())
    }

    fn add_pattern(
        &mut self,
        pii_type: PiiType,
        patterns: Vec<(&str, f64, &str)>,
    ) -> Result<(), DevDocsError> {
        let compiled_patterns: Result<Vec<CompiledPattern>, DevDocsError> = patterns
            .into_iter()
            .map(|(pattern, confidence, name)| {
                Ok(CompiledPattern {
                    regex: Regex::new(pattern).map_err(|e| {
                        DevDocsError::PiiDetection(format!(
                            "Invalid regex pattern '{}': {}",
                            pattern, e
                        ))
                    })?,
                    confidence,
                    name: name.to_string(),
                })
            })
            .collect();

        self.patterns.insert(pii_type, compiled_patterns?);
        Ok(())
    }

    fn scan_json_value(
        &self,
        value: &serde_json::Value,
        path: &str,
    ) -> Result<Vec<PiiDetection>, DevDocsError> {
        let mut detections = Vec::new();

        match value {
            serde_json::Value::String(s) => {
                // Check if field is whitelisted
                if self.is_field_whitelisted(path) {
                    return Ok(detections);
                }

                // Context-aware detection
                if self.config.enable_context_detection {
                    if let Some(context_pii_type) = self.context_analyzer.analyze_field_name(path) {
                        let redacted = self.apply_redaction_strategy(s, context_pii_type);
                        detections.push(PiiDetection {
                            pii_type: context_pii_type,
                            field_path: path.to_string(),
                            start_pos: 0,
                            end_pos: s.len(),
                            confidence: 0.8,
                            original_value: s.clone(),
                            redacted_value: redacted,
                            detection_method: DetectionMethod::Context,
                        });
                    }
                }

                // Pattern-based detection
                detections.extend(self.scan_string_value(s, path)?);
            }
            serde_json::Value::Object(obj) => {
                for (key, val) in obj {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    detections.extend(self.scan_json_value(val, &new_path)?);
                }
            }
            serde_json::Value::Array(arr) => {
                for (index, val) in arr.iter().enumerate() {
                    let new_path = format!("{}[{}]", path, index);
                    detections.extend(self.scan_json_value(val, &new_path)?);
                }
            }
            _ => {} // Numbers, booleans, null don't contain PII
        }

        Ok(detections)
    }

    fn scan_string_value(
        &self,
        text: &str,
        field_path: &str,
    ) -> Result<Vec<PiiDetection>, DevDocsError> {
        let mut detections = Vec::new();

        for (pii_type, patterns) in &self.patterns {
            for pattern in patterns {
                for mat in pattern.regex.find_iter(text) {
                    let mat = mat.map_err(|e| {
                        DevDocsError::PiiDetection(format!("Regex match error: {}", e))
                    })?;
                    let matched_text = mat.as_str();

                    // Additional validation for certain PII types
                    if self.validate_detection(*pii_type, matched_text) {
                        let redacted = self.apply_redaction_strategy(matched_text, *pii_type);

                        detections.push(PiiDetection {
                            pii_type: *pii_type,
                            field_path: field_path.to_string(),
                            start_pos: mat.start(),
                            end_pos: mat.end(),
                            confidence: pattern.confidence,
                            original_value: matched_text.to_string(),
                            redacted_value: redacted,
                            detection_method: DetectionMethod::Regex,
                        });
                    }
                }
            }
        }

        Ok(detections)
    }

    fn scan_plain_text(&self, text: &str) -> Result<Vec<PiiDetection>, DevDocsError> {
        self.scan_string_value(text, "")
    }

    fn validate_detection(&self, pii_type: PiiType, text: &str) -> bool {
        match pii_type {
            PiiType::CreditCard => self.validate_credit_card(text),
            PiiType::Ssn => self.validate_ssn(text),
            PiiType::Email => self.validate_email(text),
            PiiType::Phone => self.validate_phone(text),
            _ => true, // No additional validation for other types
        }
    }

    fn validate_credit_card(&self, text: &str) -> bool {
        // Luhn algorithm validation
        let digits: Vec<u32> = text
            .chars()
            .filter(|c| c.is_ascii_digit())
            .map(|c| c.to_digit(10).unwrap())
            .collect();

        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }

        let mut sum = 0;
        let mut alternate = false;

        for &digit in digits.iter().rev() {
            let mut n = digit;
            if alternate {
                n *= 2;
                if n > 9 {
                    n = (n % 10) + 1;
                }
            }
            sum += n;
            alternate = !alternate;
        }

        sum % 10 == 0
    }

    fn validate_ssn(&self, text: &str) -> bool {
        let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();

        // Basic SSN validation rules
        if digits.len() != 9 {
            return false;
        }

        // Check for invalid patterns
        let area = &digits[0..3];
        let group = &digits[3..5];
        let serial = &digits[5..9];

        // Area number cannot be 000, 666, or 900-999
        if area == "000" || area == "666" || area.starts_with('9') {
            return false;
        }

        // Group number cannot be 00
        if group == "00" {
            return false;
        }

        // Serial number cannot be 0000
        if serial == "0000" {
            return false;
        }

        true
    }

    fn validate_email(&self, text: &str) -> bool {
        // Basic email validation beyond regex
        text.contains('@')
            && text.contains('.')
            && !text.starts_with('@')
            && !text.ends_with('@')
            && text.len() >= 5
            && text.len() <= 254
    }

    fn validate_phone(&self, text: &str) -> bool {
        let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();

        // Phone numbers should have 7-15 digits (international standard)
        digits.len() >= 7 && digits.len() <= 15
    }

    fn apply_redaction_strategy(&self, text: &str, pii_type: PiiType) -> String {
        match self.config.redaction_strategy {
            RedactionStrategy::Asterisks => text
                .chars()
                .map(|c| if c.is_alphanumeric() { '*' } else { c })
                .collect(),
            RedactionStrategy::Placeholder => {
                format!("[{}_REDACTED]", self.pii_type_name(pii_type))
            }
            RedactionStrategy::Hash => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(text.as_bytes());
                format!("hash_{:x}", hasher.finalize())[..16].to_string()
            }
            RedactionStrategy::Remove => String::new(),
            RedactionStrategy::Partial => match pii_type {
                PiiType::Email => {
                    if let Some(at_pos) = text.find('@') {
                        let (local, domain) = text.split_at(at_pos);
                        if local.len() > 2 {
                            format!("{}***{}", &local[..1], domain)
                        } else {
                            format!("***{}", domain)
                        }
                    } else {
                        "***".to_string()
                    }
                }
                PiiType::Phone => {
                    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
                    if digits.len() >= 4 {
                        format!("***-***-{}", &digits[digits.len() - 4..])
                    } else {
                        "***".to_string()
                    }
                }
                _ => {
                    if text.len() > 4 {
                        format!("{}***", &text[..2])
                    } else {
                        "***".to_string()
                    }
                }
            },
        }
    }

    fn pii_type_name(&self, pii_type: PiiType) -> &'static str {
        match pii_type {
            PiiType::Email => "EMAIL",
            PiiType::Phone => "PHONE",
            PiiType::Ssn => "SSN",
            PiiType::CreditCard => "CREDIT_CARD",
            PiiType::IpAddress => "IP_ADDRESS",
            PiiType::Name => "NAME",
            PiiType::Address => "ADDRESS",
            PiiType::DateOfBirth => "DATE_OF_BIRTH",
            PiiType::DriversLicense => "DRIVERS_LICENSE",
            PiiType::Passport => "PASSPORT",
            PiiType::BankAccount => "BANK_ACCOUNT",
            PiiType::Custom(_) => "CUSTOM",
        }
    }

    fn is_field_whitelisted(&self, field_path: &str) -> bool {
        self.config
            .field_whitelist
            .iter()
            .any(|pattern| field_path.contains(pattern) || field_path.ends_with(pattern))
    }

    fn ml_detect_pii(&self, _text: &str) -> Result<Vec<PiiDetection>, DevDocsError> {
        // Placeholder for ML-based PII detection
        // In production, this would use a trained model
        Ok(Vec::new())
    }

    fn initialize_ml_model(&mut self) -> Result<(), DevDocsError> {
        // Placeholder for ML model initialization
        self.ml_model = Some(MlPiiModel {
            model_version: "1.0.0".to_string(),
            confidence_threshold: self.config.confidence_threshold,
        });
        Ok(())
    }

    fn redact_json_field(
        &self,
        value: &mut serde_json::Value,
        path: &str,
        redacted_value: &str,
    ) -> Result<(), DevDocsError> {
        let parts: Vec<&str> = path.split('.').collect();
        self.redact_json_field_recursive(value, &parts, redacted_value, 0)
    }

    fn redact_json_field_recursive(
        &self,
        value: &mut serde_json::Value,
        path_parts: &[&str],
        redacted_value: &str,
        depth: usize,
    ) -> Result<(), DevDocsError> {
        if depth >= path_parts.len() {
            return Ok(());
        }

        let current_part = path_parts[depth];

        match value {
            serde_json::Value::Object(obj) => {
                if depth == path_parts.len() - 1 {
                    // Last part, do the redaction
                    if let Some(field_value) = obj.get_mut(current_part) {
                        *field_value = serde_json::Value::String(redacted_value.to_string());
                    }
                } else {
                    // Recurse deeper
                    if let Some(field_value) = obj.get_mut(current_part) {
                        self.redact_json_field_recursive(
                            field_value,
                            path_parts,
                            redacted_value,
                            depth + 1,
                        )?;
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                // Handle array indices like [0], [1], etc.
                if current_part.starts_with('[') && current_part.ends_with(']') {
                    let index_str = &current_part[1..current_part.len() - 1];
                    if let Ok(index) = index_str.parse::<usize>() {
                        if let Some(array_value) = arr.get_mut(index) {
                            if depth == path_parts.len() - 1 {
                                *array_value =
                                    serde_json::Value::String(redacted_value.to_string());
                            } else {
                                self.redact_json_field_recursive(
                                    array_value,
                                    path_parts,
                                    redacted_value,
                                    depth + 1,
                                )?;
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }
}

impl ContextAnalyzer {
    fn new() -> Self {
        let mut field_name_patterns = HashMap::new();

        // Email field patterns
        field_name_patterns.insert(
            PiiType::Email,
            vec![
                "email".to_string(),
                "email_address".to_string(),
                "e_mail".to_string(),
                "mail".to_string(),
                "user_email".to_string(),
            ],
        );

        // Phone field patterns
        field_name_patterns.insert(
            PiiType::Phone,
            vec![
                "phone".to_string(),
                "phone_number".to_string(),
                "mobile".to_string(),
                "cell".to_string(),
                "telephone".to_string(),
            ],
        );

        // Name field patterns
        field_name_patterns.insert(
            PiiType::Name,
            vec![
                "name".to_string(),
                "full_name".to_string(),
                "first_name".to_string(),
                "last_name".to_string(),
                "username".to_string(),
            ],
        );

        Self {
            field_name_patterns,
            value_patterns: HashMap::new(),
        }
    }

    fn analyze_field_name(&self, field_path: &str) -> Option<PiiType> {
        let field_name = field_path.to_lowercase();

        for (pii_type, patterns) in &self.field_name_patterns {
            for pattern in patterns {
                if field_name.contains(pattern) {
                    return Some(*pii_type);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_protection_config_default() {
        let config = PiiProtectionConfig::default();
        assert!(config.enabled);
        assert_eq!(config.confidence_threshold, 0.7);
        assert!(matches!(
            config.redaction_strategy,
            RedactionStrategy::Placeholder
        ));
    }

    #[test]
    fn test_pii_detector_creation() {
        let config = PiiProtectionConfig::default();
        let detector = PiiDetector::new(&config);
        assert!(detector.is_ok());
    }

    #[test]
    fn test_email_detection() {
        let config = PiiProtectionConfig::default();
        let detector = PiiDetector::new(&config).unwrap();

        let test_data = r#"{"user_email": "john.doe@example.com"}"#;
        let result = detector.scan_data(test_data.as_bytes()).unwrap();

        assert!(!result.detections.is_empty());
        assert_eq!(result.detections[0].pii_type, PiiType::Email);
        assert_eq!(result.detections[0].original_value, "john.doe@example.com");
    }

    #[test]
    fn test_phone_detection() {
        let config = PiiProtectionConfig::default();
        let detector = PiiDetector::new(&config).unwrap();

        let test_data = r#"{"phone": "555-123-4567"}"#;
        let result = detector.scan_data(test_data.as_bytes()).unwrap();

        assert!(!result.detections.is_empty());
        assert_eq!(result.detections[0].pii_type, PiiType::Phone);
    }

    #[test]
    fn test_credit_card_validation() {
        let config = PiiProtectionConfig::default();
        let detector = PiiDetector::new(&config).unwrap();

        // Valid Visa test number
        assert!(detector.validate_credit_card("4111111111111111"));

        // Invalid number
        assert!(!detector.validate_credit_card("1234567890123456"));
    }

    #[test]
    fn test_ssn_validation() {
        let config = PiiProtectionConfig::default();
        let detector = PiiDetector::new(&config).unwrap();

        // Valid SSN format
        assert!(detector.validate_ssn("123-45-6789"));

        // Invalid SSN (area 000)
        assert!(!detector.validate_ssn("000-45-6789"));

        // Invalid SSN (area 666)
        assert!(!detector.validate_ssn("666-45-6789"));
    }

    #[test]
    fn test_redaction_strategies() {
        let config = PiiProtectionConfig::default();
        let detector = PiiDetector::new(&config).unwrap();

        let email = "john@example.com";

        // Test placeholder redaction
        let redacted = detector.apply_redaction_strategy(email, PiiType::Email);
        assert_eq!(redacted, "[EMAIL_REDACTED]");

        // Test partial redaction
        let mut config_partial = config.clone();
        config_partial.redaction_strategy = RedactionStrategy::Partial;
        let detector_partial = PiiDetector::new(&config_partial).unwrap();
        let redacted_partial = detector_partial.apply_redaction_strategy(email, PiiType::Email);
        assert!(redacted_partial.contains("j***@example.com"));
    }

    #[test]
    fn test_field_whitelist() {
        let mut config = PiiProtectionConfig::default();
        config.field_whitelist.push("user_id".to_string());

        let detector = PiiDetector::new(&config).unwrap();
        assert!(detector.is_field_whitelisted("user_id"));
        assert!(detector.is_field_whitelisted("profile.user_id"));
        assert!(!detector.is_field_whitelisted("email"));
    }

    #[test]
    fn test_context_analyzer() {
        let analyzer = ContextAnalyzer::new();

        assert_eq!(
            analyzer.analyze_field_name("user_email"),
            Some(PiiType::Email)
        );
        assert_eq!(
            analyzer.analyze_field_name("phone_number"),
            Some(PiiType::Phone)
        );
        assert_eq!(
            analyzer.analyze_field_name("full_name"),
            Some(PiiType::Name)
        );
        assert_eq!(analyzer.analyze_field_name("random_field"), None);
    }

    #[test]
    fn test_pii_redaction() {
        let config = PiiProtectionConfig::default();
        let detector = PiiDetector::new(&config).unwrap();

        let test_data = r#"{"email": "test@example.com", "phone": "555-1234"}"#;
        let redacted = detector.redact_pii(test_data.as_bytes()).unwrap();
        let redacted_str = String::from_utf8(redacted).unwrap();

        assert!(redacted_str.contains("[EMAIL_REDACTED]"));
        assert!(redacted_str.contains("[PHONE_REDACTED]"));
        assert!(!redacted_str.contains("test@example.com"));
        assert!(!redacted_str.contains("555-1234"));
    }

    #[test]
    fn test_disabled_pii_detection() {
        let mut config = PiiProtectionConfig::default();
        config.enabled = false;

        let detector = PiiDetector::new(&config).unwrap();
        let test_data = r#"{"email": "test@example.com"}"#;
        let result = detector.scan_data(test_data.as_bytes()).unwrap();

        assert_eq!(result.total_detections, 0);
        assert!(result.detections.is_empty());
    }
}
