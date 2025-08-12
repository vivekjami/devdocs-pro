//! Comprehensive security configuration management
//!
//! Provides centralized configuration for all security components
//! with validation, environment variable support, and hot reloading.

use crate::errors::DevDocsError;
use crate::security::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Master security configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MasterSecurityConfig {
    /// Global security settings
    pub global: GlobalSecuritySettings,
    /// Encryption configuration
    pub encryption: EncryptionConfig,
    /// PII protection configuration
    pub pii_protection: PiiProtectionConfig,
    /// Authentication configuration
    pub authentication: AuthConfig,
    /// Audit configuration
    pub audit: AuditConfig,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,
    /// Compliance configuration
    pub compliance: ComplianceConfig,
    /// Secrets management configuration
    pub secrets: SecretsConfig,
    /// Security monitoring configuration
    pub monitoring: SecurityMonitoringConfig,
    /// Data protection configuration
    pub data_protection: DataProtectionConfig,
    /// Environment-specific overrides
    pub environment_overrides: HashMap<String, EnvironmentOverride>,
}

/// Global security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSecuritySettings {
    /// Security mode (development, staging, production)
    pub security_mode: SecurityMode,
    /// Default security level for new data
    pub default_security_level: SecurityLevel,
    /// Enable security headers
    pub enable_security_headers: bool,
    /// Security headers configuration
    pub security_headers: SecurityHeadersConfig,
    /// Enable CORS protection
    pub enable_cors: bool,
    /// CORS configuration
    pub cors: CorsConfig,
    /// Enable CSRF protection
    pub enable_csrf: bool,
    /// CSRF configuration
    pub csrf: CsrfConfig,
    /// Security policy enforcement
    pub policy_enforcement: PolicyEnforcementConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityMode {
    Development,
    Staging,
    Production,
    HighSecurity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    /// Enable Strict-Transport-Security
    pub hsts: bool,
    /// HSTS max age in seconds
    pub hsts_max_age: u32,
    /// Enable X-Content-Type-Options
    pub content_type_options: bool,
    /// Enable X-Frame-Options
    pub frame_options: bool,
    /// X-Frame-Options value
    pub frame_options_value: String,
    /// Enable X-XSS-Protection
    pub xss_protection: bool,
    /// Enable Content-Security-Policy
    pub csp: bool,
    /// CSP directives
    pub csp_directives: HashMap<String, String>,
    /// Enable Referrer-Policy
    pub referrer_policy: bool,
    /// Referrer policy value
    pub referrer_policy_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Exposed headers
    pub exposed_headers: Vec<String>,
    /// Allow credentials
    pub allow_credentials: bool,
    /// Max age for preflight requests
    pub max_age: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfConfig {
    /// CSRF token header name
    pub token_header: String,
    /// CSRF token cookie name
    pub token_cookie: String,
    /// Token expiration time in seconds
    pub token_expiry: u32,
    /// Secure cookie flag
    pub secure_cookie: bool,
    /// SameSite cookie attribute
    pub same_site: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnforcementConfig {
    /// Enable strict policy enforcement
    pub strict_enforcement: bool,
    /// Policy violation actions
    pub violation_actions: Vec<PolicyViolationAction>,
    /// Grace period for policy violations in seconds
    pub grace_period_seconds: u32,
    /// Enable policy learning mode
    pub learning_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolationAction {
    pub violation_type: String,
    pub action: ViolationActionType,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationActionType {
    Log,
    Alert,
    Block,
    Quarantine,
    Custom(String),
}

/// Environment-specific configuration overrides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentOverride {
    /// Environment name
    pub environment: String,
    /// Security mode override
    pub security_mode: Option<SecurityMode>,
    /// Encryption overrides
    pub encryption: Option<EncryptionOverride>,
    /// Authentication overrides
    pub authentication: Option<AuthOverride>,
    /// Monitoring overrides
    pub monitoring: Option<MonitoringOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionOverride {
    pub enabled: Option<bool>,
    pub algorithm: Option<String>,
    pub key_rotation_hours: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthOverride {
    pub enabled: Option<bool>,
    pub token_expiry_seconds: Option<u64>,
    pub enable_mfa: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringOverride {
    pub enabled: Option<bool>,
    pub real_time_enabled: Option<bool>,
    pub anomaly_detection_enabled: Option<bool>,
}

impl Default for GlobalSecuritySettings {
    fn default() -> Self {
        Self {
            security_mode: SecurityMode::Production,
            default_security_level: SecurityLevel::Internal,
            enable_security_headers: true,
            security_headers: SecurityHeadersConfig::default(),
            enable_cors: true,
            cors: CorsConfig::default(),
            enable_csrf: true,
            csrf: CsrfConfig::default(),
            policy_enforcement: PolicyEnforcementConfig::default(),
        }
    }
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            hsts: true,
            hsts_max_age: 31536000, // 1 year
            content_type_options: true,
            frame_options: true,
            frame_options_value: "DENY".to_string(),
            xss_protection: true,
            csp: true,
            csp_directives: {
                let mut directives = HashMap::new();
                directives.insert("default-src".to_string(), "'self'".to_string());
                directives.insert(
                    "script-src".to_string(),
                    "'self' 'unsafe-inline'".to_string(),
                );
                directives.insert(
                    "style-src".to_string(),
                    "'self' 'unsafe-inline'".to_string(),
                );
                directives.insert("img-src".to_string(), "'self' data: https:".to_string());
                directives
            },
            referrer_policy: true,
            referrer_policy_value: "strict-origin-when-cross-origin".to_string(),
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["https://localhost:3000".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
            ],
            exposed_headers: vec!["X-Total-Count".to_string()],
            allow_credentials: true,
            max_age: 86400, // 24 hours
        }
    }
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            token_header: "X-CSRF-Token".to_string(),
            token_cookie: "csrf_token".to_string(),
            token_expiry: 3600, // 1 hour
            secure_cookie: true,
            same_site: "Strict".to_string(),
        }
    }
}

impl Default for PolicyEnforcementConfig {
    fn default() -> Self {
        Self {
            strict_enforcement: true,
            violation_actions: vec![
                PolicyViolationAction {
                    violation_type: "pii_detected".to_string(),
                    action: ViolationActionType::Block,
                    parameters: HashMap::new(),
                },
                PolicyViolationAction {
                    violation_type: "unauthorized_access".to_string(),
                    action: ViolationActionType::Block,
                    parameters: HashMap::new(),
                },
            ],
            grace_period_seconds: 300, // 5 minutes
            learning_mode: false,
        }
    }
}

/// Security configuration manager
pub struct SecurityConfigManager {
    config: MasterSecurityConfig,
    config_path: Option<PathBuf>,
    environment: String,
}

impl Default for SecurityConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityConfigManager {
    /// Create a new configuration manager
    pub fn new() -> Self {
        Self {
            config: MasterSecurityConfig::default(),
            config_path: None,
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_string()),
        }
    }

    /// Load configuration from file
    pub fn load_from_file<P: Into<PathBuf>>(path: P) -> Result<Self, DevDocsError> {
        let path = path.into();
        let content = std::fs::read_to_string(&path)
            .map_err(|e| DevDocsError::Configuration(format!("Failed to read config file: {e}")))?;

        let config: MasterSecurityConfig = if path.extension().and_then(|s| s.to_str())
            == Some("yaml")
            || path.extension().and_then(|s| s.to_str()) == Some("yml")
        {
            serde_yaml::from_str(&content).map_err(|e| {
                DevDocsError::Configuration(format!("Failed to parse YAML config: {e}"))
            })?
        } else {
            serde_json::from_str(&content).map_err(|e| {
                DevDocsError::Configuration(format!("Failed to parse JSON config: {e}"))
            })?
        };

        let mut manager = Self {
            config,
            config_path: Some(path),
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_string()),
        };

        manager.apply_environment_overrides()?;
        manager.apply_environment_variables()?;
        manager.validate_configuration()?;

        Ok(manager)
    }

    /// Load configuration from environment variables
    pub fn load_from_env() -> Result<Self, DevDocsError> {
        let mut manager = Self::new();
        manager.apply_environment_variables()?;
        manager.validate_configuration()?;
        Ok(manager)
    }

    /// Get the current configuration
    pub fn get_config(&self) -> &MasterSecurityConfig {
        &self.config
    }

    /// Get configuration for a specific component
    pub fn get_encryption_config(&self) -> &EncryptionConfig {
        &self.config.encryption
    }

    pub fn get_auth_config(&self) -> &AuthConfig {
        &self.config.authentication
    }

    pub fn get_audit_config(&self) -> &AuditConfig {
        &self.config.audit
    }

    pub fn get_compliance_config(&self) -> &ComplianceConfig {
        &self.config.compliance
    }

    pub fn get_monitoring_config(&self) -> &SecurityMonitoringConfig {
        &self.config.monitoring
    }

    /// Update configuration and validate
    pub fn update_config(&mut self, new_config: MasterSecurityConfig) -> Result<(), DevDocsError> {
        // Validate new configuration
        self.validate_config(&new_config)?;

        self.config = new_config;
        self.apply_environment_overrides()?;
        self.apply_environment_variables()?;

        Ok(())
    }

    /// Save configuration to file
    pub fn save_to_file<P: Into<PathBuf>>(&self, path: P) -> Result<(), DevDocsError> {
        let path = path.into();
        let content = if path.extension().and_then(|s| s.to_str()) == Some("yaml")
            || path.extension().and_then(|s| s.to_str()) == Some("yml")
        {
            serde_yaml::to_string(&self.config).map_err(|e| {
                DevDocsError::Configuration(format!("Failed to serialize YAML config: {e}"))
            })?
        } else {
            serde_json::to_string_pretty(&self.config).map_err(|e| {
                DevDocsError::Configuration(format!("Failed to serialize JSON config: {e}"))
            })?
        };

        std::fs::write(&path, content).map_err(|e| {
            DevDocsError::Configuration(format!("Failed to write config file: {e}"))
        })?;

        Ok(())
    }

    /// Reload configuration from file
    pub fn reload(&mut self) -> Result<(), DevDocsError> {
        if let Some(path) = &self.config_path.clone() {
            let new_manager = Self::load_from_file(path)?;
            self.config = new_manager.config;
            Ok(())
        } else {
            Err(DevDocsError::Configuration(
                "No config file path available for reload".to_string(),
            ))
        }
    }

    /// Apply environment-specific overrides
    fn apply_environment_overrides(&mut self) -> Result<(), DevDocsError> {
        if let Some(override_config) = self
            .config
            .environment_overrides
            .get(&self.environment)
            .cloned()
        {
            // Apply security mode override
            if let Some(security_mode) = override_config.security_mode {
                self.config.global.security_mode = security_mode;
            }

            // Apply encryption overrides
            if let Some(enc_override) = override_config.encryption {
                if let Some(enabled) = enc_override.enabled {
                    self.config.encryption.enabled = enabled;
                }
                if let Some(algorithm) = enc_override.algorithm {
                    self.config.encryption.algorithm = match algorithm.as_str() {
                        "aes256gcm" => EncryptionAlgorithm::Aes256Gcm,
                        "chacha20poly1305" => EncryptionAlgorithm::ChaCha20Poly1305,
                        _ => {
                            return Err(DevDocsError::Configuration(format!(
                                "Unknown encryption algorithm: {algorithm}"
                            )))
                        }
                    };
                }
                if let Some(rotation_hours) = enc_override.key_rotation_hours {
                    self.config.encryption.key_rotation_hours = rotation_hours;
                }
            }

            // Apply authentication overrides
            if let Some(auth_override) = override_config.authentication {
                if let Some(enabled) = auth_override.enabled {
                    self.config.authentication.enabled = enabled;
                }
                if let Some(token_expiry) = auth_override.token_expiry_seconds {
                    self.config.authentication.token_expiry_seconds = token_expiry;
                }
            }

            // Apply monitoring overrides
            if let Some(mon_override) = override_config.monitoring {
                if let Some(enabled) = mon_override.enabled {
                    self.config.monitoring.enabled = enabled;
                }
                if let Some(real_time) = mon_override.real_time_enabled {
                    self.config.monitoring.real_time.enabled = real_time;
                }
                if let Some(anomaly) = mon_override.anomaly_detection_enabled {
                    self.config.monitoring.anomaly_detection.enabled = anomaly;
                }
            }
        }

        Ok(())
    }

    /// Apply environment variable overrides
    fn apply_environment_variables(&mut self) -> Result<(), DevDocsError> {
        // Security mode
        if let Ok(mode) = std::env::var("SECURITY_MODE") {
            self.config.global.security_mode = match mode.to_lowercase().as_str() {
                "development" => SecurityMode::Development,
                "staging" => SecurityMode::Staging,
                "production" => SecurityMode::Production,
                "high_security" => SecurityMode::HighSecurity,
                _ => {
                    return Err(DevDocsError::Configuration(format!(
                        "Invalid security mode: {mode}"
                    )))
                }
            };
        }

        // Encryption settings
        if let Ok(enabled) = std::env::var("ENCRYPTION_ENABLED") {
            self.config.encryption.enabled = enabled.parse().map_err(|_| {
                DevDocsError::Configuration("Invalid ENCRYPTION_ENABLED value".to_string())
            })?;
        }

        if let Ok(key_rotation) = std::env::var("ENCRYPTION_KEY_ROTATION_HOURS") {
            self.config.encryption.key_rotation_hours = key_rotation.parse().map_err(|_| {
                DevDocsError::Configuration(
                    "Invalid ENCRYPTION_KEY_ROTATION_HOURS value".to_string(),
                )
            })?;
        }

        // Authentication settings
        if let Ok(enabled) = std::env::var("AUTH_ENABLED") {
            self.config.authentication.enabled = enabled.parse().map_err(|_| {
                DevDocsError::Configuration("Invalid AUTH_ENABLED value".to_string())
            })?;
        }

        if let Ok(token_expiry) = std::env::var("AUTH_TOKEN_EXPIRY_SECONDS") {
            self.config.authentication.token_expiry_seconds =
                token_expiry.parse().map_err(|_| {
                    DevDocsError::Configuration(
                        "Invalid AUTH_TOKEN_EXPIRY_SECONDS value".to_string(),
                    )
                })?;
        }

        // Rate limiting settings
        if let Ok(enabled) = std::env::var("RATE_LIMITING_ENABLED") {
            self.config.rate_limiting.enabled = enabled.parse().map_err(|_| {
                DevDocsError::Configuration("Invalid RATE_LIMITING_ENABLED value".to_string())
            })?;
        }

        // Monitoring settings
        if let Ok(enabled) = std::env::var("MONITORING_ENABLED") {
            self.config.monitoring.enabled = enabled.parse().map_err(|_| {
                DevDocsError::Configuration("Invalid MONITORING_ENABLED value".to_string())
            })?;
        }

        Ok(())
    }

    /// Validate the entire configuration
    fn validate_configuration(&self) -> Result<(), DevDocsError> {
        self.validate_config(&self.config)
    }

    /// Validate a configuration object
    fn validate_config(&self, config: &MasterSecurityConfig) -> Result<(), DevDocsError> {
        // Validate encryption configuration
        if config.encryption.enabled && config.encryption.key_rotation_hours == 0 {
            return Err(DevDocsError::Configuration(
                "Key rotation hours must be greater than 0".to_string(),
            ));
        }

        // Validate authentication configuration
        if config.authentication.enabled {
            if config.authentication.token_expiry_seconds == 0 {
                return Err(DevDocsError::Configuration(
                    "Token expiry must be greater than 0".to_string(),
                ));
            }
            if config.authentication.jwt_secret.is_empty() {
                return Err(DevDocsError::Configuration(
                    "JWT secret cannot be empty".to_string(),
                ));
            }
        }

        // Validate rate limiting configuration
        if config.rate_limiting.enabled && config.rate_limiting.global.requests_per_second == 0 {
            return Err(DevDocsError::Configuration(
                "Global requests per second must be greater than 0".to_string(),
            ));
        }

        // Validate audit configuration
        if config.audit.enabled && config.audit.retention.retention_days == 0 {
            return Err(DevDocsError::Configuration(
                "Audit retention days must be greater than 0".to_string(),
            ));
        }

        // Validate compliance configuration
        if config.compliance.enabled && config.compliance.standards.is_empty() {
            return Err(DevDocsError::Configuration(
                "At least one compliance standard must be specified".to_string(),
            ));
        }

        // Validate monitoring configuration
        if config.monitoring.enabled && config.monitoring.real_time.buffer_size == 0 {
            return Err(DevDocsError::Configuration(
                "Monitoring buffer size must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Get security configuration for the current environment
    pub fn get_security_config(&self) -> SecurityConfig {
        SecurityConfig {
            encryption: self.config.encryption.clone(),
            pii_protection: self.config.pii_protection.clone(),
            auth: self.config.authentication.clone(),
            audit: self.config.audit.clone(),
            rate_limiting: self.config.rate_limiting.clone(),
            compliance: self.config.compliance.clone(),
        }
    }

    /// Check if a feature is enabled based on security mode
    pub fn is_feature_enabled(&self, feature: SecurityFeature) -> bool {
        match (&self.config.global.security_mode, feature) {
            (SecurityMode::Development, SecurityFeature::StrictValidation) => false,
            (SecurityMode::Development, SecurityFeature::EncryptionAtRest) => false,
            (SecurityMode::Development, _) => false,
            (SecurityMode::Staging, SecurityFeature::StrictValidation) => true,
            (SecurityMode::Staging, SecurityFeature::EncryptionAtRest) => true,
            (SecurityMode::Staging, _) => true,
            (SecurityMode::Production, _) => true,
            (SecurityMode::HighSecurity, _) => true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SecurityFeature {
    StrictValidation,
    EncryptionAtRest,
    AuditLogging,
    RealTimeMonitoring,
    ThreatDetection,
    ComplianceChecking,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_master_security_config_default() {
        let config = MasterSecurityConfig::default();
        assert!(matches!(
            config.global.security_mode,
            SecurityMode::Production
        ));
        assert!(config.encryption.enabled);
        assert!(config.authentication.enabled);
    }

    #[test]
    fn test_security_config_manager_new() {
        let manager = SecurityConfigManager::new();
        assert!(matches!(
            manager.config.global.security_mode,
            SecurityMode::Production
        ));
    }

    #[test]
    fn test_config_validation() {
        let manager = SecurityConfigManager::new();
        let result = manager.validate_configuration();
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_config_validation() {
        let mut config = MasterSecurityConfig::default();
        config.encryption.key_rotation_hours = 0; // Invalid

        let manager = SecurityConfigManager::new();
        let result = manager.validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_file_operations() {
        let _config = MasterSecurityConfig::default();
        let temp_file = NamedTempFile::new().unwrap();

        let manager = SecurityConfigManager::new();
        let result = manager.save_to_file(temp_file.path());
        assert!(result.is_ok());

        let loaded_manager = SecurityConfigManager::load_from_file(temp_file.path());
        assert!(loaded_manager.is_ok());
    }

    #[test]
    fn test_environment_variable_override() {
        std::env::set_var("SECURITY_MODE", "development");
        std::env::set_var("ENCRYPTION_ENABLED", "false");

        let manager = SecurityConfigManager::load_from_env().unwrap();
        assert!(matches!(
            manager.config.global.security_mode,
            SecurityMode::Development
        ));
        assert!(!manager.config.encryption.enabled);

        // Cleanup
        std::env::remove_var("SECURITY_MODE");
        std::env::remove_var("ENCRYPTION_ENABLED");
    }

    #[test]
    fn test_feature_enablement() {
        let mut manager = SecurityConfigManager::new();

        // Production mode - all features enabled
        manager.config.global.security_mode = SecurityMode::Production;
        assert!(manager.is_feature_enabled(SecurityFeature::StrictValidation));
        assert!(manager.is_feature_enabled(SecurityFeature::EncryptionAtRest));

        // Development mode - some features disabled
        manager.config.global.security_mode = SecurityMode::Development;
        assert!(!manager.is_feature_enabled(SecurityFeature::StrictValidation));
        assert!(!manager.is_feature_enabled(SecurityFeature::EncryptionAtRest));
    }

    #[test]
    fn test_component_config_getters() {
        let manager = SecurityConfigManager::new();

        let encryption_config = manager.get_encryption_config();
        assert!(encryption_config.enabled);

        let auth_config = manager.get_auth_config();
        assert!(auth_config.enabled);

        let audit_config = manager.get_audit_config();
        assert!(audit_config.enabled);
    }
}
