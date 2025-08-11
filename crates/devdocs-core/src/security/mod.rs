//! Enterprise-grade security module for DevDocs Pro
//! 
//! This module provides comprehensive security features including:
//! - Data encryption and key management
//! - PII detection and redaction
//! - Authentication and authorization
//! - Audit logging and compliance
//! - Rate limiting and DDoS protection

pub mod encryption;
pub mod pii_detection;
pub mod auth;
pub mod audit;
pub mod rate_limiting;
pub mod compliance;
pub mod secrets;
pub mod monitoring;
pub mod data_protection;
pub mod config;

// Re-export main types to avoid conflicts
pub use encryption::{DataEncryptor, EncryptionConfig, EncryptionAlgorithm, SecureKey, EncryptedData};
pub use pii_detection::{PiiDetector, PiiProtectionConfig, PiiDetectionResult, PiiType, RedactionStrategy};
pub use auth::{Authenticator, AuthConfig, AuthResult, User, Organization, ApiKey, TokenType};
pub use audit::{AuditLogger, AuditConfig, AuditEvent, AuditEventType, AuditQuery, AuditStatistics};
pub use rate_limiting::{RateLimiter, RateLimitingConfig, RateLimitStatistics};
pub use compliance::{ComplianceChecker, ComplianceConfig, ComplianceResult, ComplianceStandard as ComplianceStandardType};
pub use secrets::{SecretsManager, SecretsConfig, SecureSecret, SecretType, SecretMetadata};
pub use monitoring::{SecurityMonitor, SecurityMonitoringConfig, SecurityEvent, SecurityEventType, SecurityDashboard};
pub use data_protection::{DataProtectionProcessor, DataProtectionConfig, ProtectedData, ProtectionMethod};
pub use config::{SecurityConfigManager, MasterSecurityConfig, GlobalSecuritySettings, SecurityMode};

use crate::errors::DevDocsError;
use serde::{Deserialize, Serialize};

use uuid::Uuid;

/// Security configuration for the entire system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Encryption settings
    pub encryption: EncryptionConfig,
    /// PII detection and redaction settings
    pub pii_protection: PiiProtectionConfig,
    /// Authentication configuration
    pub auth: AuthConfig,
    /// Audit logging configuration
    pub audit: AuditConfig,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,
    /// Compliance settings
    pub compliance: ComplianceConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            encryption: EncryptionConfig::default(),
            pii_protection: PiiProtectionConfig::default(),
            auth: AuthConfig::default(),
            audit: AuditConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            compliance: ComplianceConfig::default(),
        }
    }
}

/// Security context for request processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub request_id: Uuid,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub permissions: Vec<String>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub security_level: SecurityLevel,
}

/// Security levels for different types of data and operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Public data, minimal security requirements
    Public,
    /// Internal data, standard security requirements
    Internal,
    /// Confidential data, enhanced security requirements
    Confidential,
    /// Restricted data, maximum security requirements
    Restricted,
}

impl SecurityContext {
    pub fn new(request_id: Uuid, ip_address: String) -> Self {
        Self {
            request_id,
            user_id: None,
            organization_id: None,
            permissions: Vec::new(),
            ip_address,
            user_agent: None,
            timestamp: chrono::Utc::now(),
            security_level: SecurityLevel::Public,
        }
    }

    pub fn with_user(mut self, user_id: String, organization_id: Option<String>) -> Self {
        self.user_id = Some(user_id);
        self.organization_id = organization_id;
        self
    }

    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions = permissions;
        self
    }

    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    pub fn requires_encryption(&self) -> bool {
        matches!(self.security_level, SecurityLevel::Confidential | SecurityLevel::Restricted)
    }

    pub fn requires_audit(&self) -> bool {
        matches!(self.security_level, SecurityLevel::Internal | SecurityLevel::Confidential | SecurityLevel::Restricted)
    }
}

/// Security validation result
#[derive(Debug, Clone)]
pub struct SecurityValidationResult {
    pub is_valid: bool,
    pub violations: Vec<SecurityViolation>,
    pub risk_score: f64,
    pub recommendations: Vec<String>,
}

/// Security violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityViolation {
    pub violation_type: ViolationType,
    pub severity: Severity,
    pub description: String,
    pub field_path: Option<String>,
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationType {
    PiiDetected,
    UnauthorizedAccess,
    RateLimitExceeded,
    DataIntegrityViolation,
    ComplianceViolation,
    EncryptionRequired,
    AuditRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl SecurityValidationResult {
    pub fn new() -> Self {
        Self {
            is_valid: true,
            violations: Vec::new(),
            risk_score: 0.0,
            recommendations: Vec::new(),
        }
    }

    pub fn add_violation(&mut self, violation: SecurityViolation) {
        self.is_valid = false;
        self.risk_score += match violation.severity {
            Severity::Low => 0.1,
            Severity::Medium => 0.3,
            Severity::High => 0.6,
            Severity::Critical => 1.0,
        };
        self.violations.push(violation);
    }

    pub fn add_recommendation(&mut self, recommendation: String) {
        self.recommendations.push(recommendation);
    }

    pub fn is_critical(&self) -> bool {
        self.violations.iter().any(|v| v.severity == Severity::Critical)
    }

    pub fn should_block(&self) -> bool {
        self.risk_score >= 0.8 || self.is_critical()
    }
}

/// Main security manager that coordinates all security operations
pub struct SecurityManager {
    config: SecurityConfig,
    encryptor: DataEncryptor,
    pii_detector: PiiDetector,
    authenticator: Authenticator,
    auditor: AuditLogger,
    rate_limiter: RateLimiter,
    compliance_checker: ComplianceChecker,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            encryptor: DataEncryptor::new(&config.encryption)?,
            pii_detector: PiiDetector::new(&config.pii_protection)?,
            authenticator: Authenticator::new(&config.auth)?,
            auditor: AuditLogger::new(&config.audit)?,
            rate_limiter: RateLimiter::new(&config.rate_limiting)?,
            compliance_checker: ComplianceChecker::new(&config.compliance)?,
            config,
        })
    }

    /// Validate security requirements for incoming data
    pub async fn validate_security(&self, 
        data: &[u8], 
        context: &SecurityContext
    ) -> Result<SecurityValidationResult, DevDocsError> {
        let mut result = SecurityValidationResult::new();

        // Check rate limiting
        if let Err(e) = self.rate_limiter.check_rate_limit(&context.ip_address).await {
            result.add_violation(SecurityViolation {
                violation_type: ViolationType::RateLimitExceeded,
                severity: Severity::High,
                description: format!("Rate limit exceeded: {}", e),
                field_path: None,
                detected_at: chrono::Utc::now(),
            });
        }

        // Check for PII
        let pii_results = self.pii_detector.scan_data(data)?;
        for detection in pii_results.detections {
            result.add_violation(SecurityViolation {
                violation_type: ViolationType::PiiDetected,
                severity: match detection.confidence {
                    c if c >= 0.9 => Severity::Critical,
                    c if c >= 0.7 => Severity::High,
                    c if c >= 0.5 => Severity::Medium,
                    _ => Severity::Low,
                },
                description: format!("PII detected: {:?}", detection.pii_type),
                field_path: Some(detection.field_path),
                detected_at: chrono::Utc::now(),
            });
        }

        // Check compliance requirements
        let compliance_result = self.compliance_checker.check_compliance(data, context).await?;
        for violation in compliance_result.violations {
            result.add_violation(violation);
        }

        // Add security recommendations
        if context.requires_encryption() && !self.is_data_encrypted(data) {
            result.add_recommendation("Data should be encrypted for this security level".to_string());
        }

        if context.requires_audit() {
            result.add_recommendation("This operation should be audited".to_string());
        }

        Ok(result)
    }

    /// Process and secure data according to security requirements
    pub async fn secure_data(&mut self, 
        data: &[u8], 
        context: &SecurityContext
    ) -> Result<Vec<u8>, DevDocsError> {
        let mut processed_data = data.to_vec();

        // Redact PII if required
        if self.config.pii_protection.enabled {
            processed_data = self.pii_detector.redact_pii(&processed_data)?;
        }

        // Encrypt if required
        if context.requires_encryption() {
            processed_data = self.encryptor.encrypt(&processed_data, &context.request_id.to_string())?;
        }

        // Log audit trail if required
        if context.requires_audit() {
            self.auditor.log_data_access(context, data.len()).await?;
        }

        Ok(processed_data)
    }

    /// Authenticate and authorize a request
    pub async fn authenticate_request(&self, 
        token: &str, 
        required_permissions: &[String]
    ) -> Result<SecurityContext, DevDocsError> {
        let auth_result = self.authenticator.validate_token(token).await?;
        
        let context = SecurityContext::new(
            Uuid::new_v4(),
            "unknown".to_string(), // IP should be set by caller
        ).with_user(auth_result.user_id, auth_result.organization_id)
         .with_permissions(auth_result.permissions);

        // Check if user has required permissions
        for permission in required_permissions {
            if !context.has_permission(permission) {
                return Err(DevDocsError::Unauthorized(
                    format!("Missing required permission: {}", permission)
                ));
            }
        }

        Ok(context)
    }

    fn is_data_encrypted(&self, data: &[u8]) -> bool {
        // Simple heuristic: encrypted data typically has high entropy
        // In production, you'd have proper metadata or headers
        if data.len() < 16 {
            return false;
        }
        
        let mut byte_counts = [0u32; 256];
        for &byte in data {
            byte_counts[byte as usize] += 1;
        }
        
        let entropy = byte_counts.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / data.len() as f64;
                -p * p.log2()
            })
            .sum::<f64>();
            
        entropy > 7.0 // High entropy suggests encryption
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_context_creation() {
        let request_id = Uuid::new_v4();
        let context = SecurityContext::new(request_id, "192.168.1.1".to_string());
        
        assert_eq!(context.request_id, request_id);
        assert_eq!(context.ip_address, "192.168.1.1");
        assert_eq!(context.security_level, SecurityLevel::Public);
        assert!(context.user_id.is_none());
    }

    #[test]
    fn test_security_context_permissions() {
        let context = SecurityContext::new(Uuid::new_v4(), "192.168.1.1".to_string())
            .with_permissions(vec!["read".to_string(), "write".to_string()]);
        
        assert!(context.has_permission("read"));
        assert!(context.has_permission("write"));
        assert!(!context.has_permission("admin"));
    }

    #[test]
    fn test_security_validation_result() {
        let mut result = SecurityValidationResult::new();
        assert!(result.is_valid);
        assert_eq!(result.risk_score, 0.0);

        result.add_violation(SecurityViolation {
            violation_type: ViolationType::PiiDetected,
            severity: Severity::High,
            description: "Email detected".to_string(),
            field_path: Some("user.email".to_string()),
            detected_at: chrono::Utc::now(),
        });

        assert!(!result.is_valid);
        assert_eq!(result.risk_score, 0.6);
    }

    #[test]
    fn test_security_levels() {
        let public_context = SecurityContext::new(Uuid::new_v4(), "192.168.1.1".to_string())
            .with_security_level(SecurityLevel::Public);
        assert!(!public_context.requires_encryption());
        assert!(!public_context.requires_audit());

        let confidential_context = SecurityContext::new(Uuid::new_v4(), "192.168.1.1".to_string())
            .with_security_level(SecurityLevel::Confidential);
        assert!(confidential_context.requires_encryption());
        assert!(confidential_context.requires_audit());
    }
}