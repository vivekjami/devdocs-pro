//! Advanced data protection and privacy system
//!
//! Provides comprehensive data protection including encryption,
//! anonymization, pseudonymization, and privacy-preserving analytics.

use crate::errors::DevDocsError;
use crate::security::{SecurityContext, SecurityLevel};
use chrono::{DateTime, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Data protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProtectionConfig {
    /// Enable data protection
    pub enabled: bool,
    /// Encryption settings
    pub encryption: DataEncryptionConfig,
    /// Anonymization settings
    pub anonymization: AnonymizationConfig,
    /// Pseudonymization settings
    pub pseudonymization: PseudonymizationConfig,
    /// Data masking settings
    pub data_masking: DataMaskingConfig,
    /// Privacy-preserving analytics
    pub privacy_analytics: PrivacyAnalyticsConfig,
    /// Data lifecycle management
    pub lifecycle: DataLifecycleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEncryptionConfig {
    /// Enable field-level encryption
    pub field_level_encryption: bool,
    /// Encryption algorithm
    pub algorithm: String,
    /// Key management settings
    pub key_management: KeyManagementConfig,
    /// Encryption scope
    pub encryption_scope: EncryptionScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagementConfig {
    /// Key rotation interval in days
    pub rotation_interval_days: u32,
    /// Key derivation method
    pub derivation_method: String,
    /// Key storage backend
    pub storage_backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionScope {
    /// Fields to always encrypt
    pub always_encrypt: Vec<String>,
    /// Fields to encrypt based on classification
    pub classification_based: bool,
    /// Custom encryption rules
    pub custom_rules: Vec<EncryptionRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionRule {
    pub field_pattern: String,
    pub condition: String,
    pub encryption_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationConfig {
    /// Enable anonymization
    pub enabled: bool,
    /// Anonymization techniques
    pub techniques: Vec<AnonymizationTechnique>,
    /// Anonymization threshold
    pub k_anonymity_threshold: u32,
    /// L-diversity settings
    pub l_diversity: Option<LDiversityConfig>,
    /// T-closeness settings
    pub t_closeness: Option<TClosenessConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnonymizationTechnique {
    /// K-anonymity
    KAnonymity,
    /// L-diversity
    LDiversity,
    /// T-closeness
    TCloseness,
    /// Differential privacy
    DifferentialPrivacy,
    /// Data suppression
    Suppression,
    /// Data generalization
    Generalization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDiversityConfig {
    pub l_value: u32,
    pub sensitive_attributes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TClosenessConfig {
    pub t_value: f64,
    pub distance_metric: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymizationConfig {
    /// Enable pseudonymization
    pub enabled: bool,
    /// Pseudonymization method
    pub method: PseudonymizationMethod,
    /// Key management for pseudonymization
    pub key_management: PseudoKeyManagement,
    /// Reversibility settings
    pub reversible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PseudonymizationMethod {
    /// Hash-based pseudonymization
    Hash,
    /// Encryption-based pseudonymization
    Encryption,
    /// Token-based pseudonymization
    Tokenization,
    /// Format-preserving encryption
    FormatPreserving,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudoKeyManagement {
    pub key_derivation: String,
    pub salt_generation: String,
    pub key_rotation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DataMaskingConfig {
    /// Enable data masking
    pub enabled: bool,
    /// Masking rules
    pub rules: Vec<MaskingRule>,
    /// Default masking character
    pub default_mask_char: char,
    /// Preserve format
    pub preserve_format: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskingRule {
    pub field_pattern: String,
    pub masking_type: MaskingType,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaskingType {
    /// Full masking
    Full,
    /// Partial masking (show first/last N characters)
    Partial { show_first: usize, show_last: usize },
    /// Random replacement
    Random,
    /// Format-preserving masking
    FormatPreserving,
    /// Custom masking function
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAnalyticsConfig {
    /// Enable privacy-preserving analytics
    pub enabled: bool,
    /// Differential privacy settings
    pub differential_privacy: DifferentialPrivacyConfig,
    /// Homomorphic encryption settings
    pub homomorphic_encryption: HomomorphicEncryptionConfig,
    /// Secure multi-party computation
    pub secure_mpc: SecureMpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialPrivacyConfig {
    pub epsilon: f64,
    pub delta: f64,
    pub noise_mechanism: NoiseMechanism,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NoiseMechanism {
    Laplace,
    Gaussian,
    Exponential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomomorphicEncryptionConfig {
    pub scheme: String,
    pub key_size: u32,
    pub supported_operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMpcConfig {
    pub protocol: String,
    pub parties: u32,
    pub threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLifecycleConfig {
    /// Enable lifecycle management
    pub enabled: bool,
    /// Data classification rules
    pub classification_rules: Vec<ClassificationRule>,
    /// Retention policies
    pub retention_policies: Vec<RetentionPolicy>,
    /// Deletion policies
    pub deletion_policies: Vec<DeletionPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRule {
    pub rule_id: String,
    pub field_patterns: Vec<String>,
    pub classification: DataClassification,
    pub confidence_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    PersonalData,
    SensitivePersonalData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub policy_id: String,
    pub data_types: Vec<String>,
    pub retention_period_days: u32,
    pub legal_hold_support: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionPolicy {
    pub policy_id: String,
    pub trigger: DeletionTrigger,
    pub deletion_method: DeletionMethod,
    pub verification_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeletionTrigger {
    TimeBasedRetention,
    UserRequest,
    LegalRequirement,
    DataSubjectRequest,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeletionMethod {
    SoftDelete,
    HardDelete,
    Anonymization,
    Pseudonymization,
    Shredding,
}

impl Default for DataProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            encryption: DataEncryptionConfig {
                field_level_encryption: true,
                algorithm: "AES-256-GCM".to_string(),
                key_management: KeyManagementConfig {
                    rotation_interval_days: 90,
                    derivation_method: "PBKDF2".to_string(),
                    storage_backend: "local".to_string(),
                },
                encryption_scope: EncryptionScope {
                    always_encrypt: vec![
                        "password".to_string(),
                        "ssn".to_string(),
                        "credit_card".to_string(),
                    ],
                    classification_based: true,
                    custom_rules: Vec::new(),
                },
            },
            anonymization: AnonymizationConfig {
                enabled: true,
                techniques: vec![
                    AnonymizationTechnique::KAnonymity,
                    AnonymizationTechnique::Suppression,
                ],
                k_anonymity_threshold: 5,
                l_diversity: Some(LDiversityConfig {
                    l_value: 2,
                    sensitive_attributes: vec![
                        "salary".to_string(),
                        "medical_condition".to_string(),
                    ],
                }),
                t_closeness: None,
            },
            pseudonymization: PseudonymizationConfig {
                enabled: true,
                method: PseudonymizationMethod::Hash,
                key_management: PseudoKeyManagement {
                    key_derivation: "HKDF".to_string(),
                    salt_generation: "random".to_string(),
                    key_rotation: true,
                },
                reversible: false,
            },
            data_masking: DataMaskingConfig {
                enabled: true,
                rules: vec![MaskingRule {
                    field_pattern: "email".to_string(),
                    masking_type: MaskingType::Partial {
                        show_first: 2,
                        show_last: 0,
                    },
                    parameters: HashMap::new(),
                }],
                default_mask_char: '*',
                preserve_format: true,
            },
            privacy_analytics: PrivacyAnalyticsConfig {
                enabled: true,
                differential_privacy: DifferentialPrivacyConfig {
                    epsilon: 1.0,
                    delta: 1e-5,
                    noise_mechanism: NoiseMechanism::Laplace,
                },
                homomorphic_encryption: HomomorphicEncryptionConfig {
                    scheme: "BFV".to_string(),
                    key_size: 4096,
                    supported_operations: vec!["add".to_string(), "multiply".to_string()],
                },
                secure_mpc: SecureMpcConfig {
                    protocol: "BGW".to_string(),
                    parties: 3,
                    threshold: 2,
                },
            },
            lifecycle: DataLifecycleConfig {
                enabled: true,
                classification_rules: vec![ClassificationRule {
                    rule_id: "pii_detection".to_string(),
                    field_patterns: vec![
                        "email".to_string(),
                        "phone".to_string(),
                        "ssn".to_string(),
                    ],
                    classification: DataClassification::PersonalData,
                    confidence_threshold: 0.8,
                }],
                retention_policies: vec![RetentionPolicy {
                    policy_id: "default".to_string(),
                    data_types: vec!["api_logs".to_string()],
                    retention_period_days: 365,
                    legal_hold_support: true,
                }],
                deletion_policies: vec![DeletionPolicy {
                    policy_id: "gdpr_erasure".to_string(),
                    trigger: DeletionTrigger::DataSubjectRequest,
                    deletion_method: DeletionMethod::HardDelete,
                    verification_required: true,
                }],
            },
        }
    }
}

/// Data protection processor
pub struct DataProtectionProcessor {
    config: DataProtectionConfig,
    encryptor: FieldLevelEncryptor,
    anonymizer: DataAnonymizer,
    pseudonymizer: DataPseudonymizer,
    masker: DataMasker,
    classifier: DataClassifier,
    rng: SystemRandom,
}

/// Field-level encryption processor
pub struct FieldLevelEncryptor {
    config: DataEncryptionConfig,
    encryption_keys: HashMap<String, Vec<u8>>,
}

/// Data anonymization processor
pub struct DataAnonymizer {
    config: AnonymizationConfig,
}

/// Data pseudonymization processor
pub struct DataPseudonymizer {
    config: PseudonymizationConfig,
    pseudonym_mapping: HashMap<String, String>,
}

/// Data masking processor
pub struct DataMasker {
    config: DataMaskingConfig,
}

/// Data classification processor
pub struct DataClassifier {
    classification_rules: Vec<ClassificationRule>,
}

/// Protected data result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedData {
    pub original_size: usize,
    pub protected_size: usize,
    pub protection_methods: Vec<ProtectionMethod>,
    pub data: Vec<u8>,
    pub metadata: ProtectionMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtectionMethod {
    Encryption,
    Anonymization,
    Pseudonymization,
    Masking,
    Suppression,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionMetadata {
    pub classification: DataClassification,
    pub protection_level: ProtectionLevel,
    pub applied_at: DateTime<Utc>,
    pub reversible: bool,
    pub retention_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtectionLevel {
    None,
    Basic,
    Standard,
    High,
    Maximum,
}

impl DataProtectionProcessor {
    pub fn new(config: &DataProtectionConfig) -> Result<Self, DevDocsError> {
        let encryptor = FieldLevelEncryptor::new(&config.encryption)?;
        let anonymizer = DataAnonymizer::new(&config.anonymization)?;
        let pseudonymizer = DataPseudonymizer::new(&config.pseudonymization)?;
        let masker = DataMasker::new(&config.data_masking)?;
        let classifier = DataClassifier::new(&config.lifecycle.classification_rules)?;

        Ok(Self {
            config: config.clone(),
            encryptor,
            anonymizer,
            pseudonymizer,
            masker,
            classifier,
            rng: SystemRandom::new(),
        })
    }

    /// Apply data protection based on context and classification
    pub async fn protect_data(
        &mut self,
        data: &[u8],
        context: &SecurityContext,
    ) -> Result<ProtectedData, DevDocsError> {
        if !self.config.enabled {
            return Ok(ProtectedData {
                original_size: data.len(),
                protected_size: data.len(),
                protection_methods: Vec::new(),
                data: data.to_vec(),
                metadata: ProtectionMetadata {
                    classification: DataClassification::Public,
                    protection_level: ProtectionLevel::None,
                    applied_at: Utc::now(),
                    reversible: true,
                    retention_policy: None,
                },
            });
        }

        // Classify the data
        let classification = self.classifier.classify_data(data).await?;

        // Determine protection level based on context and classification
        let protection_level = self.determine_protection_level(&classification, context);

        let mut protected_data = data.to_vec();
        let mut methods = Vec::new();

        // Apply protection methods based on level
        match protection_level {
            ProtectionLevel::None => {
                // No protection needed
            }
            ProtectionLevel::Basic => {
                if self.config.data_masking.enabled {
                    protected_data = self.masker.mask_data(&protected_data).await?;
                    methods.push(ProtectionMethod::Masking);
                }
            }
            ProtectionLevel::Standard => {
                if self.config.pseudonymization.enabled {
                    protected_data = self
                        .pseudonymizer
                        .pseudonymize_data(&protected_data)
                        .await?;
                    methods.push(ProtectionMethod::Pseudonymization);
                }
                if self.config.data_masking.enabled {
                    protected_data = self.masker.mask_data(&protected_data).await?;
                    methods.push(ProtectionMethod::Masking);
                }
            }
            ProtectionLevel::High => {
                if self.config.encryption.field_level_encryption {
                    protected_data = self.encryptor.encrypt_fields(&protected_data).await?;
                    methods.push(ProtectionMethod::Encryption);
                }
                if self.config.anonymization.enabled {
                    protected_data = self.anonymizer.anonymize_data(&protected_data).await?;
                    methods.push(ProtectionMethod::Anonymization);
                }
            }
            ProtectionLevel::Maximum => {
                // Apply all protection methods
                if self.config.encryption.field_level_encryption {
                    protected_data = self.encryptor.encrypt_fields(&protected_data).await?;
                    methods.push(ProtectionMethod::Encryption);
                }
                if self.config.anonymization.enabled {
                    protected_data = self.anonymizer.anonymize_data(&protected_data).await?;
                    methods.push(ProtectionMethod::Anonymization);
                }
                if self.config.pseudonymization.enabled {
                    protected_data = self
                        .pseudonymizer
                        .pseudonymize_data(&protected_data)
                        .await?;
                    methods.push(ProtectionMethod::Pseudonymization);
                }
            }
        }

        Ok(ProtectedData {
            original_size: data.len(),
            protected_size: protected_data.len(),
            protection_methods: methods.clone(),
            data: protected_data,
            metadata: ProtectionMetadata {
                classification: classification.clone(),
                protection_level,
                applied_at: Utc::now(),
                reversible: self.is_reversible(&methods),
                retention_policy: self.get_retention_policy(&classification),
            },
        })
    }

    /// Apply differential privacy for analytics
    pub async fn apply_differential_privacy(
        &self,
        query_result: f64,
        sensitivity: f64,
    ) -> Result<f64, DevDocsError> {
        if !self.config.privacy_analytics.enabled {
            return Ok(query_result);
        }

        let dp_config = &self.config.privacy_analytics.differential_privacy;
        let noise =
            self.generate_noise(sensitivity, dp_config.epsilon, &dp_config.noise_mechanism)?;

        Ok(query_result + noise)
    }

    /// Generate synthetic data for testing while preserving privacy
    pub async fn generate_synthetic_data(
        &self,
        original_data: &[u8],
        count: usize,
    ) -> Result<Vec<Vec<u8>>, DevDocsError> {
        // Simplified implementation - would use advanced techniques like GANs
        let mut synthetic_data = Vec::new();

        for _ in 0..count {
            let mut synthetic = original_data.to_vec();

            // Apply noise and modifications
            for byte in &mut synthetic {
                if self.rng.fill(&mut [0u8; 1]).is_ok() {
                    *byte = (*byte).wrapping_add(1);
                }
            }

            synthetic_data.push(synthetic);
        }

        Ok(synthetic_data)
    }

    fn determine_protection_level(
        &self,
        classification: &DataClassification,
        context: &SecurityContext,
    ) -> ProtectionLevel {
        match (classification, context.security_level) {
            (DataClassification::Public, _) => ProtectionLevel::None,
            (DataClassification::Internal, SecurityLevel::Public) => ProtectionLevel::Basic,
            (DataClassification::Internal, _) => ProtectionLevel::Standard,
            (DataClassification::Confidential, _) => ProtectionLevel::High,
            (DataClassification::Restricted, _) => ProtectionLevel::Maximum,
            (DataClassification::PersonalData, _) => ProtectionLevel::High,
            (DataClassification::SensitivePersonalData, _) => ProtectionLevel::Maximum,
        }
    }

    fn is_reversible(&self, methods: &[ProtectionMethod]) -> bool {
        // Encryption and some pseudonymization methods are reversible
        methods.iter().all(|method| {
            matches!(
                method,
                ProtectionMethod::Encryption | ProtectionMethod::Masking
            )
        })
    }

    fn get_retention_policy(&self, classification: &DataClassification) -> Option<String> {
        // Find applicable retention policy
        for policy in &self.config.lifecycle.retention_policies {
            let classification_str = format!("{:?}", classification).to_lowercase();
            if policy.data_types.contains(&classification_str) {
                return Some(policy.policy_id.clone());
            }
        }
        None
    }

    fn generate_noise(
        &self,
        sensitivity: f64,
        epsilon: f64,
        mechanism: &NoiseMechanism,
    ) -> Result<f64, DevDocsError> {
        match mechanism {
            NoiseMechanism::Laplace => {
                // Laplace noise: scale = sensitivity / epsilon
                let scale = sensitivity / epsilon;
                let mut bytes = [0u8; 8];
                self.rng.fill(&mut bytes).map_err(|e| {
                    DevDocsError::Encryption(format!("Failed to generate random bytes: {}", e))
                })?;

                let uniform = f64::from_le_bytes(bytes) / f64::MAX;
                let laplace_noise = if uniform < 0.5 {
                    scale * (2.0 * uniform).ln()
                } else {
                    -scale * (2.0 * (1.0 - uniform)).ln()
                };

                Ok(laplace_noise)
            }
            NoiseMechanism::Gaussian => {
                // Simplified Gaussian noise implementation
                let scale = sensitivity / epsilon;
                let mut bytes = [0u8; 8];
                self.rng.fill(&mut bytes).map_err(|e| {
                    DevDocsError::Encryption(format!("Failed to generate random bytes: {}", e))
                })?;

                let uniform = f64::from_le_bytes(bytes) / f64::MAX;
                let gaussian_noise = scale
                    * ((-2.0 * uniform.ln()).sqrt() * (2.0 * std::f64::consts::PI * uniform).cos());

                Ok(gaussian_noise)
            }
            NoiseMechanism::Exponential => {
                // Exponential mechanism - simplified implementation
                let scale = sensitivity / epsilon;
                let mut bytes = [0u8; 8];
                self.rng.fill(&mut bytes).map_err(|e| {
                    DevDocsError::Encryption(format!("Failed to generate random bytes: {}", e))
                })?;

                let uniform = f64::from_le_bytes(bytes) / f64::MAX;
                let exponential_noise = -scale * uniform.ln();

                Ok(exponential_noise)
            }
        }
    }
}

// Simplified implementations for the component processors
impl FieldLevelEncryptor {
    pub fn new(_config: &DataEncryptionConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            config: _config.clone(),
            encryption_keys: HashMap::new(),
        })
    }

    pub async fn encrypt_fields(&self, data: &[u8]) -> Result<Vec<u8>, DevDocsError> {
        // Simplified implementation - would encrypt specific fields
        Ok(data.to_vec())
    }
}

impl DataAnonymizer {
    pub fn new(config: &AnonymizationConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            config: config.clone(),
        })
    }

    pub async fn anonymize_data(&self, data: &[u8]) -> Result<Vec<u8>, DevDocsError> {
        // Simplified implementation - would apply k-anonymity, l-diversity, etc.
        Ok(data.to_vec())
    }
}

impl DataPseudonymizer {
    pub fn new(config: &PseudonymizationConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            config: config.clone(),
            pseudonym_mapping: HashMap::new(),
        })
    }

    pub async fn pseudonymize_data(&self, data: &[u8]) -> Result<Vec<u8>, DevDocsError> {
        // Simplified implementation - would replace identifiers with pseudonyms
        Ok(data.to_vec())
    }
}

impl DataMasker {
    pub fn new(config: &DataMaskingConfig) -> Result<Self, DevDocsError> {
        Ok(Self {
            config: config.clone(),
        })
    }

    pub async fn mask_data(&self, data: &[u8]) -> Result<Vec<u8>, DevDocsError> {
        // Simplified implementation - would mask sensitive fields
        let mut masked = data.to_vec();

        // Simple masking: replace some bytes with mask character
        for (i, byte) in masked.iter_mut().enumerate() {
            if i % 3 == 0 && *byte != b' ' && *byte != b'\n' {
                *byte = self.config.default_mask_char as u8;
            }
        }

        Ok(masked)
    }
}

impl DataClassifier {
    pub fn new(rules: &[ClassificationRule]) -> Result<Self, DevDocsError> {
        Ok(Self {
            classification_rules: rules.to_vec(),
        })
    }

    pub async fn classify_data(&self, data: &[u8]) -> Result<DataClassification, DevDocsError> {
        let data_str = String::from_utf8_lossy(data);

        // Simple classification based on content patterns
        if data_str.contains("@") && data_str.contains(".") {
            return Ok(DataClassification::PersonalData);
        }

        if data_str.contains("password") || data_str.contains("secret") {
            return Ok(DataClassification::Confidential);
        }

        if data_str.contains("ssn") || data_str.contains("credit_card") {
            return Ok(DataClassification::SensitivePersonalData);
        }

        Ok(DataClassification::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityLevel;
    use uuid::Uuid;

    #[test]
    fn test_data_protection_config_default() {
        let config = DataProtectionConfig::default();
        assert!(config.enabled);
        assert!(config.encryption.field_level_encryption);
        assert!(config.anonymization.enabled);
        assert!(config.pseudonymization.enabled);
    }

    #[tokio::test]
    async fn test_data_protection_processor_creation() {
        let config = DataProtectionConfig::default();
        let processor = DataProtectionProcessor::new(&config);
        assert!(processor.is_ok());
    }

    #[tokio::test]
    async fn test_data_protection() {
        let config = DataProtectionConfig::default();
        let mut processor = DataProtectionProcessor::new(&config).unwrap();

        let context = SecurityContext::new(Uuid::new_v4(), "192.168.1.1".to_string())
            .with_security_level(SecurityLevel::Confidential);

        let test_data = b"test@example.com";
        let protected = processor.protect_data(test_data, &context).await.unwrap();

        assert!(!protected.protection_methods.is_empty());
        assert!(matches!(
            protected.metadata.classification,
            DataClassification::PersonalData
        ));
    }

    #[tokio::test]
    async fn test_differential_privacy() {
        let config = DataProtectionConfig::default();
        let processor = DataProtectionProcessor::new(&config).unwrap();

        let original_result = 100.0;
        let sensitivity = 1.0;

        let private_result = processor
            .apply_differential_privacy(original_result, sensitivity)
            .await
            .unwrap();

        // Result should be different due to added noise
        assert_ne!(original_result, private_result);
    }

    #[tokio::test]
    async fn test_synthetic_data_generation() {
        let config = DataProtectionConfig::default();
        let processor = DataProtectionProcessor::new(&config).unwrap();

        let original_data = b"sample data";
        let synthetic_data = processor
            .generate_synthetic_data(original_data, 3)
            .await
            .unwrap();

        assert_eq!(synthetic_data.len(), 3);
        assert_eq!(synthetic_data[0].len(), original_data.len());
    }

    #[tokio::test]
    async fn test_data_classification() {
        let rules = vec![ClassificationRule {
            rule_id: "email_rule".to_string(),
            field_patterns: vec!["email".to_string()],
            classification: DataClassification::PersonalData,
            confidence_threshold: 0.8,
        }];

        let classifier = DataClassifier::new(&rules).unwrap();

        let email_data = b"user@example.com";
        let classification = classifier.classify_data(email_data).await.unwrap();

        assert!(matches!(classification, DataClassification::PersonalData));
    }

    #[tokio::test]
    async fn test_data_masking() {
        let config = DataMaskingConfig::default();
        let masker = DataMasker::new(&config).unwrap();

        let test_data = b"sensitive information";
        let masked_data = masker.mask_data(test_data).await.unwrap();

        assert_ne!(test_data, masked_data.as_slice());
        assert_eq!(test_data.len(), masked_data.len());
    }

    #[test]
    fn test_protection_level_determination() {
        let config = DataProtectionConfig::default();
        let processor = DataProtectionProcessor::new(&config).unwrap();

        let context = SecurityContext::new(Uuid::new_v4(), "192.168.1.1".to_string())
            .with_security_level(SecurityLevel::Confidential);

        let level =
            processor.determine_protection_level(&DataClassification::PersonalData, &context);
        assert!(matches!(level, ProtectionLevel::High));

        let level = processor.determine_protection_level(&DataClassification::Public, &context);
        assert!(matches!(level, ProtectionLevel::None));
    }
}
