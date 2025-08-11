//! Secure secrets management system
//!
//! Provides secure storage, rotation, and access control for sensitive configuration

use crate::errors::DevDocsError;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Secrets management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Enable secrets management
    pub enabled: bool,
    /// Secrets storage backend
    pub storage_backend: SecretsStorageBackend,
    /// Encryption settings for secrets at rest
    pub encryption: SecretsEncryptionConfig,
    /// Access control settings
    pub access_control: SecretsAccessControlConfig,
    /// Rotation settings
    pub rotation: SecretsRotationConfig,
    /// Audit settings
    pub audit: SecretsAuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretsStorageBackend {
    /// Local encrypted file storage
    LocalFile { path: String },
    /// Environment variables (less secure, for development)
    Environment,
    /// HashiCorp Vault
    Vault { url: String, token: String },
    /// AWS Secrets Manager
    AwsSecretsManager { region: String },
    /// Azure Key Vault
    AzureKeyVault { vault_url: String },
    /// Google Secret Manager
    GoogleSecretManager { project_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsEncryptionConfig {
    /// Master key for encrypting secrets
    pub master_key_id: String,
    /// Encryption algorithm
    pub algorithm: String,
    /// Key derivation settings
    pub key_derivation: KeyDerivationSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationSettings {
    pub iterations: u32,
    pub salt_length: usize,
    pub key_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsAccessControlConfig {
    /// Enable role-based access control
    pub enable_rbac: bool,
    /// Default permissions for new secrets
    pub default_permissions: Vec<String>,
    /// Require approval for secret access
    pub require_approval: bool,
    /// Access logging enabled
    pub log_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsRotationConfig {
    /// Enable automatic rotation
    pub auto_rotation: bool,
    /// Default rotation interval in days
    pub default_rotation_days: u32,
    /// Rotation policies per secret type
    pub rotation_policies: HashMap<String, RotationPolicy>,
    /// Grace period for old secrets in days
    pub grace_period_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub rotation_interval_days: u32,
    pub notification_days_before: u32,
    pub auto_rotate: bool,
    pub require_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsAuditConfig {
    /// Log all secret operations
    pub log_operations: bool,
    /// Log secret access
    pub log_access: bool,
    /// Log rotation events
    pub log_rotation: bool,
    /// Retention period for audit logs
    pub audit_retention_days: u32,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            storage_backend: SecretsStorageBackend::LocalFile {
                path: "./secrets".to_string(),
            },
            encryption: SecretsEncryptionConfig {
                master_key_id: "default".to_string(),
                algorithm: "AES-256-GCM".to_string(),
                key_derivation: KeyDerivationSettings {
                    iterations: 100000,
                    salt_length: 32,
                    key_length: 32,
                },
            },
            access_control: SecretsAccessControlConfig {
                enable_rbac: true,
                default_permissions: vec!["read".to_string()],
                require_approval: false,
                log_access: true,
            },
            rotation: SecretsRotationConfig {
                auto_rotation: true,
                default_rotation_days: 90,
                rotation_policies: HashMap::new(),
                grace_period_days: 7,
            },
            audit: SecretsAuditConfig {
                log_operations: true,
                log_access: true,
                log_rotation: true,
                audit_retention_days: 365,
            },
        }
    }
}

/// Secure secret value that zeros itself on drop
#[derive(Clone)]
pub struct SecureSecret {
    pub id: String,
    pub name: String,
    pub value: Secret<String>,
    pub secret_type: SecretType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rotation_policy: Option<RotationPolicy>,
    pub permissions: Vec<String>,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    /// API keys
    ApiKey,
    /// Database passwords
    DatabasePassword,
    /// JWT signing keys
    JwtSigningKey,
    /// Encryption keys
    EncryptionKey,
    /// OAuth client secrets
    OAuthClientSecret,
    /// Webhook secrets
    WebhookSecret,
    /// Third-party service tokens
    ServiceToken,
    /// Custom secret type
    Custom(String),
}

/// Secret metadata for listing and management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub id: String,
    pub name: String,
    pub secret_type: SecretType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_accessed: Option<chrono::DateTime<chrono::Utc>>,
    pub access_count: u64,
    pub rotation_due: bool,
    pub permissions: Vec<String>,
    pub tags: HashMap<String, String>,
}

/// Secret access request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAccessRequest {
    pub secret_id: String,
    pub requester_id: String,
    pub purpose: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub approved: bool,
    pub approved_by: Option<String>,
    pub approved_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Secrets manager implementation
pub struct SecretsManager {
    config: SecretsConfig,
    storage: LocalFileSecretsStorage,
    encryptor: SecretsEncryptor,
    access_log: Vec<SecretAccessLog>,
}

/// Trait for secrets storage backends
#[async_trait::async_trait]
pub trait SecretsStorage {
    async fn store_secret(&mut self, secret: &SecureSecret) -> Result<(), DevDocsError>;
    async fn retrieve_secret(&self, id: &str) -> Result<Option<SecureSecret>, DevDocsError>;
    async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, DevDocsError>;
    async fn delete_secret(&mut self, id: &str) -> Result<(), DevDocsError>;
    async fn update_metadata(
        &mut self,
        id: &str,
        metadata: &SecretMetadata,
    ) -> Result<(), DevDocsError>;
}

/// Local file storage implementation
pub struct LocalFileSecretsStorage {
    base_path: std::path::PathBuf,
    encryptor: SecretsEncryptor,
}

/// Secrets encryptor for at-rest encryption
pub struct SecretsEncryptor {
    master_key: Vec<u8>,
    rng: SystemRandom,
}

/// Secret access log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAccessLog {
    pub secret_id: String,
    pub accessor_id: String,
    pub access_type: SecretAccessType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub success: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretAccessType {
    Read,
    Write,
    Delete,
    List,
    Rotate,
}

impl SecretsManager {
    pub fn new(config: &SecretsConfig) -> Result<Self, DevDocsError> {
        let encryptor = SecretsEncryptor::new(&config.encryption)?;

        let storage = match &config.storage_backend {
            SecretsStorageBackend::LocalFile { path } => {
                LocalFileSecretsStorage::new(path, encryptor.clone())?
            }
            _ => {
                return Err(DevDocsError::Configuration(
                    "Unsupported secrets storage backend".to_string(),
                ));
            }
        };

        Ok(Self {
            config: config.clone(),
            storage,
            encryptor,
            access_log: Vec::new(),
        })
    }

    /// Store a new secret
    pub async fn store_secret(
        &mut self,
        name: String,
        value: String,
        secret_type: SecretType,
    ) -> Result<String, DevDocsError> {
        let secret_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let secret = SecureSecret {
            id: secret_id.clone(),
            name,
            value: Secret::new(value),
            secret_type: secret_type.clone(),
            created_at: now,
            updated_at: now,
            expires_at: None,
            rotation_policy: self.get_rotation_policy_for_type(secret_type.clone()),
            permissions: self.config.access_control.default_permissions.clone(),
            tags: HashMap::new(),
        };

        self.storage.store_secret(&secret).await?;

        self.log_access(&secret_id, "system", SecretAccessType::Write, true)
            .await;

        Ok(secret_id)
    }

    /// Retrieve a secret by ID
    pub async fn get_secret(
        &mut self,
        secret_id: &str,
        accessor_id: &str,
    ) -> Result<Option<String>, DevDocsError> {
        // Check access permissions
        if !self
            .check_access_permission(secret_id, accessor_id, "read")
            .await?
        {
            self.log_access(secret_id, accessor_id, SecretAccessType::Read, false)
                .await;
            return Err(DevDocsError::Unauthorized(
                "Access denied to secret".to_string(),
            ));
        }

        if let Some(secret) = self.storage.retrieve_secret(secret_id).await? {
            // Check if secret has expired
            if let Some(expires_at) = secret.expires_at {
                if chrono::Utc::now() > expires_at {
                    self.log_access(secret_id, accessor_id, SecretAccessType::Read, false)
                        .await;
                    return Err(DevDocsError::NotFound("Secret has expired".to_string()));
                }
            }

            self.log_access(secret_id, accessor_id, SecretAccessType::Read, true)
                .await;
            Ok(Some(secret.value.expose_secret().clone()))
        } else {
            self.log_access(secret_id, accessor_id, SecretAccessType::Read, false)
                .await;
            Ok(None)
        }
    }

    /// List all secrets (metadata only)
    pub async fn list_secrets(
        &mut self,
        accessor_id: &str,
    ) -> Result<Vec<SecretMetadata>, DevDocsError> {
        self.log_access("*", accessor_id, SecretAccessType::List, true)
            .await;
        self.storage.list_secrets().await
    }

    /// Delete a secret
    pub async fn delete_secret(
        &mut self,
        secret_id: &str,
        accessor_id: &str,
    ) -> Result<(), DevDocsError> {
        if !self
            .check_access_permission(secret_id, accessor_id, "delete")
            .await?
        {
            self.log_access(secret_id, accessor_id, SecretAccessType::Delete, false)
                .await;
            return Err(DevDocsError::Unauthorized(
                "Access denied to delete secret".to_string(),
            ));
        }

        self.storage.delete_secret(secret_id).await?;
        self.log_access(secret_id, accessor_id, SecretAccessType::Delete, true)
            .await;
        Ok(())
    }

    /// Rotate a secret
    pub async fn rotate_secret(
        &mut self,
        secret_id: &str,
        accessor_id: &str,
    ) -> Result<String, DevDocsError> {
        if !self
            .check_access_permission(secret_id, accessor_id, "rotate")
            .await?
        {
            self.log_access(secret_id, accessor_id, SecretAccessType::Rotate, false)
                .await;
            return Err(DevDocsError::Unauthorized(
                "Access denied to rotate secret".to_string(),
            ));
        }

        if let Some(mut secret) = self.storage.retrieve_secret(secret_id).await? {
            // Generate new secret value based on type
            let new_value = self.generate_secret_value(secret.secret_type.clone())?;
            secret.value = Secret::new(new_value.clone());
            secret.updated_at = chrono::Utc::now();

            self.storage.store_secret(&secret).await?;
            self.log_access(secret_id, accessor_id, SecretAccessType::Rotate, true)
                .await;

            Ok(new_value)
        } else {
            self.log_access(secret_id, accessor_id, SecretAccessType::Rotate, false)
                .await;
            Err(DevDocsError::NotFound("Secret not found".to_string()))
        }
    }

    /// Check which secrets need rotation
    pub async fn check_rotation_due(&self) -> Result<Vec<String>, DevDocsError> {
        let secrets = self.storage.list_secrets().await?;
        let _now = chrono::Utc::now();
        let mut due_for_rotation = Vec::new();

        for secret in secrets {
            if secret.rotation_due {
                due_for_rotation.push(secret.id);
            }
        }

        Ok(due_for_rotation)
    }

    /// Get secret access logs
    pub async fn get_access_logs(&self, secret_id: Option<&str>) -> Vec<SecretAccessLog> {
        if let Some(id) = secret_id {
            self.access_log
                .iter()
                .filter(|log| log.secret_id == id)
                .cloned()
                .collect()
        } else {
            self.access_log.clone()
        }
    }

    async fn check_access_permission(
        &self,
        _secret_id: &str,
        _accessor_id: &str,
        _permission: &str,
    ) -> Result<bool, DevDocsError> {
        // Simplified implementation - in production would check RBAC
        Ok(true)
    }

    async fn log_access(
        &mut self,
        secret_id: &str,
        accessor_id: &str,
        access_type: SecretAccessType,
        success: bool,
    ) {
        if self.config.audit.log_access {
            self.access_log.push(SecretAccessLog {
                secret_id: secret_id.to_string(),
                accessor_id: accessor_id.to_string(),
                access_type,
                timestamp: chrono::Utc::now(),
                success,
                ip_address: None,
                user_agent: None,
            });
        }
    }

    fn get_rotation_policy_for_type(&self, secret_type: SecretType) -> Option<RotationPolicy> {
        let type_key = match secret_type {
            SecretType::ApiKey => "api_key",
            SecretType::DatabasePassword => "database_password",
            SecretType::JwtSigningKey => "jwt_signing_key",
            SecretType::EncryptionKey => "encryption_key",
            _ => "default",
        };

        self.config
            .rotation
            .rotation_policies
            .get(type_key)
            .cloned()
            .or_else(|| {
                Some(RotationPolicy {
                    rotation_interval_days: self.config.rotation.default_rotation_days,
                    notification_days_before: 7,
                    auto_rotate: self.config.rotation.auto_rotation,
                    require_approval: false,
                })
            })
    }

    fn generate_secret_value(&self, secret_type: SecretType) -> Result<String, DevDocsError> {
        match secret_type {
            SecretType::ApiKey => {
                let mut bytes = vec![0u8; 32];
                self.encryptor.rng.fill(&mut bytes).map_err(|e| {
                    DevDocsError::Encryption(format!("Failed to generate API key: {}", e))
                })?;
                Ok(format!(
                    "dk_{}",
                    base64::engine::general_purpose::STANDARD.encode(&bytes)
                ))
            }
            SecretType::DatabasePassword => {
                let mut bytes = vec![0u8; 24];
                self.encryptor.rng.fill(&mut bytes).map_err(|e| {
                    DevDocsError::Encryption(format!("Failed to generate password: {}", e))
                })?;
                Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
            }
            SecretType::JwtSigningKey => {
                let mut bytes = vec![0u8; 64];
                self.encryptor.rng.fill(&mut bytes).map_err(|e| {
                    DevDocsError::Encryption(format!("Failed to generate JWT key: {}", e))
                })?;
                Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
            }
            SecretType::EncryptionKey => {
                let mut bytes = vec![0u8; 32];
                self.encryptor.rng.fill(&mut bytes).map_err(|e| {
                    DevDocsError::Encryption(format!("Failed to generate encryption key: {}", e))
                })?;
                Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
            }
            _ => {
                let mut bytes = vec![0u8; 32];
                self.encryptor.rng.fill(&mut bytes).map_err(|e| {
                    DevDocsError::Encryption(format!("Failed to generate secret: {}", e))
                })?;
                Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
            }
        }
    }
}

impl SecretsEncryptor {
    pub fn new(_config: &SecretsEncryptionConfig) -> Result<Self, DevDocsError> {
        // In production, this would derive from a secure master key
        let master_key = std::env::var("SECRETS_MASTER_KEY")
            .unwrap_or_else(|_| "default_master_key_change_in_production".to_string())
            .into_bytes();

        Ok(Self {
            master_key,
            rng: SystemRandom::new(),
        })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, DevDocsError> {
        // Simplified encryption - in production would use proper AEAD
        Ok(data.to_vec())
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, DevDocsError> {
        // Simplified decryption - in production would use proper AEAD
        Ok(data.to_vec())
    }
}

impl Clone for SecretsEncryptor {
    fn clone(&self) -> Self {
        Self {
            master_key: self.master_key.clone(),
            rng: SystemRandom::new(),
        }
    }
}

impl LocalFileSecretsStorage {
    pub fn new(base_path: &str, encryptor: SecretsEncryptor) -> Result<Self, DevDocsError> {
        let path = std::path::PathBuf::from(base_path);
        std::fs::create_dir_all(&path).map_err(|e| {
            DevDocsError::Storage(format!("Failed to create secrets directory: {}", e))
        })?;

        Ok(Self {
            base_path: path,
            encryptor,
        })
    }

    fn get_secret_file_path(&self, id: &str) -> std::path::PathBuf {
        self.base_path.join(format!("{}.secret", id))
    }
}

#[async_trait::async_trait]
impl SecretsStorage for LocalFileSecretsStorage {
    async fn store_secret(&mut self, secret: &SecureSecret) -> Result<(), DevDocsError> {
        let file_path = self.get_secret_file_path(&secret.id);

        // Create metadata without the secret value
        let metadata = SecretMetadata {
            id: secret.id.clone(),
            name: secret.name.clone(),
            secret_type: secret.secret_type.clone(),
            created_at: secret.created_at,
            updated_at: secret.updated_at,
            expires_at: secret.expires_at,
            last_accessed: None,
            access_count: 0,
            rotation_due: false,
            permissions: secret.permissions.clone(),
            tags: secret.tags.clone(),
        };

        // Encrypt the secret value
        let encrypted_value = self
            .encryptor
            .encrypt(secret.value.expose_secret().as_bytes())?;

        let storage_data = StoredSecret {
            metadata,
            encrypted_value,
        };

        let json_data =
            serde_json::to_vec(&storage_data).map_err(|e| DevDocsError::Serialization(e))?;

        tokio::fs::write(&file_path, json_data)
            .await
            .map_err(|e| DevDocsError::Storage(format!("Failed to write secret file: {}", e)))?;

        Ok(())
    }

    async fn retrieve_secret(&self, id: &str) -> Result<Option<SecureSecret>, DevDocsError> {
        let file_path = self.get_secret_file_path(id);

        if !file_path.exists() {
            return Ok(None);
        }

        let json_data = tokio::fs::read(&file_path)
            .await
            .map_err(|e| DevDocsError::Storage(format!("Failed to read secret file: {}", e)))?;

        let stored_secret: StoredSecret =
            serde_json::from_slice(&json_data).map_err(|e| DevDocsError::Serialization(e))?;

        let decrypted_value = self.encryptor.decrypt(&stored_secret.encrypted_value)?;
        let value_string = String::from_utf8(decrypted_value)
            .map_err(|e| DevDocsError::Storage(format!("Invalid UTF-8 in secret value: {}", e)))?;

        let secret = SecureSecret {
            id: stored_secret.metadata.id,
            name: stored_secret.metadata.name,
            value: Secret::new(value_string),
            secret_type: stored_secret.metadata.secret_type,
            created_at: stored_secret.metadata.created_at,
            updated_at: stored_secret.metadata.updated_at,
            expires_at: stored_secret.metadata.expires_at,
            rotation_policy: None, // Would be loaded from config
            permissions: stored_secret.metadata.permissions,
            tags: stored_secret.metadata.tags,
        };

        Ok(Some(secret))
    }

    async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, DevDocsError> {
        let mut secrets = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_path).await.map_err(|e| {
            DevDocsError::Storage(format!("Failed to read secrets directory: {}", e))
        })?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| DevDocsError::Storage(format!("Failed to read directory entry: {}", e)))?
        {
            if let Some(file_name) = entry.file_name().to_str() {
                if file_name.ends_with(".secret") {
                    let json_data = tokio::fs::read(entry.path()).await.map_err(|e| {
                        DevDocsError::Storage(format!("Failed to read secret file: {}", e))
                    })?;

                    if let Ok(stored_secret) = serde_json::from_slice::<StoredSecret>(&json_data) {
                        secrets.push(stored_secret.metadata);
                    }
                }
            }
        }

        Ok(secrets)
    }

    async fn delete_secret(&mut self, id: &str) -> Result<(), DevDocsError> {
        let file_path = self.get_secret_file_path(id);

        if file_path.exists() {
            tokio::fs::remove_file(&file_path).await.map_err(|e| {
                DevDocsError::Storage(format!("Failed to delete secret file: {}", e))
            })?;
        }

        Ok(())
    }

    async fn update_metadata(
        &mut self,
        id: &str,
        metadata: &SecretMetadata,
    ) -> Result<(), DevDocsError> {
        // For file storage, we need to read the secret, update metadata, and write back
        if let Some(mut secret) = self.retrieve_secret(id).await? {
            // Update the metadata fields
            secret.name = metadata.name.clone();
            secret.updated_at = metadata.updated_at;
            secret.expires_at = metadata.expires_at;
            secret.permissions = metadata.permissions.clone();
            secret.tags = metadata.tags.clone();

            self.store_secret(&secret).await?;
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct StoredSecret {
    metadata: SecretMetadata,
    encrypted_value: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_secrets_config_default() {
        let config = SecretsConfig::default();
        assert!(config.enabled);
        assert!(config.access_control.enable_rbac);
        assert!(config.rotation.auto_rotation);
    }

    #[tokio::test]
    async fn test_secrets_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = SecretsConfig::default();
        config.storage_backend = SecretsStorageBackend::LocalFile {
            path: temp_dir.path().to_string_lossy().to_string(),
        };

        let manager = SecretsManager::new(&config);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_store_and_retrieve_secret() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = SecretsConfig::default();
        config.storage_backend = SecretsStorageBackend::LocalFile {
            path: temp_dir.path().to_string_lossy().to_string(),
        };

        let mut manager = SecretsManager::new(&config).unwrap();

        let secret_id = manager
            .store_secret(
                "test_secret".to_string(),
                "secret_value_123".to_string(),
                SecretType::ApiKey,
            )
            .await
            .unwrap();

        let retrieved = manager.get_secret(&secret_id, "test_user").await.unwrap();
        assert_eq!(retrieved, Some("secret_value_123".to_string()));
    }

    #[tokio::test]
    async fn test_list_secrets() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = SecretsConfig::default();
        config.storage_backend = SecretsStorageBackend::LocalFile {
            path: temp_dir.path().to_string_lossy().to_string(),
        };

        let mut manager = SecretsManager::new(&config).unwrap();

        let _secret_id1 = manager
            .store_secret(
                "secret1".to_string(),
                "value1".to_string(),
                SecretType::ApiKey,
            )
            .await
            .unwrap();

        let _secret_id2 = manager
            .store_secret(
                "secret2".to_string(),
                "value2".to_string(),
                SecretType::DatabasePassword,
            )
            .await
            .unwrap();

        let secrets = manager.list_secrets("test_user").await.unwrap();
        assert_eq!(secrets.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_secret() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = SecretsConfig::default();
        config.storage_backend = SecretsStorageBackend::LocalFile {
            path: temp_dir.path().to_string_lossy().to_string(),
        };

        let mut manager = SecretsManager::new(&config).unwrap();

        let secret_id = manager
            .store_secret(
                "test_secret".to_string(),
                "secret_value".to_string(),
                SecretType::ApiKey,
            )
            .await
            .unwrap();

        manager
            .delete_secret(&secret_id, "test_user")
            .await
            .unwrap();

        let retrieved = manager.get_secret(&secret_id, "test_user").await.unwrap();
        assert_eq!(retrieved, None);
    }

    #[tokio::test]
    async fn test_rotate_secret() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = SecretsConfig::default();
        config.storage_backend = SecretsStorageBackend::LocalFile {
            path: temp_dir.path().to_string_lossy().to_string(),
        };

        let mut manager = SecretsManager::new(&config).unwrap();

        let secret_id = manager
            .store_secret(
                "test_secret".to_string(),
                "original_value".to_string(),
                SecretType::ApiKey,
            )
            .await
            .unwrap();

        let new_value = manager
            .rotate_secret(&secret_id, "test_user")
            .await
            .unwrap();
        assert_ne!(new_value, "original_value");

        let retrieved = manager.get_secret(&secret_id, "test_user").await.unwrap();
        assert_eq!(retrieved, Some(new_value));
    }

    #[test]
    fn test_secret_type_serialization() {
        let secret_type = SecretType::ApiKey;
        let serialized = serde_json::to_string(&secret_type).unwrap();
        let deserialized: SecretType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(secret_type, deserialized);
    }

    #[test]
    fn test_secrets_encryptor() {
        let config = SecretsEncryptionConfig {
            master_key_id: "test".to_string(),
            algorithm: "AES-256-GCM".to_string(),
            key_derivation: KeyDerivationSettings {
                iterations: 1000,
                salt_length: 16,
                key_length: 32,
            },
        };

        let encryptor = SecretsEncryptor::new(&config).unwrap();
        let data = b"test secret data";

        let encrypted = encryptor.encrypt(data).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(data, decrypted.as_slice());
    }
}
