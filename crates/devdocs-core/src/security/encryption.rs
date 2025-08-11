//! Enterprise-grade encryption module
//! 
//! Provides AES-256-GCM encryption with proper key management,
//! key rotation, and secure key derivation.

use crate::errors::DevDocsError;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;


/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Enable encryption for sensitive data
    pub enabled: bool,
    /// Key rotation interval in hours
    pub key_rotation_hours: u64,
    /// Master key for key derivation (should be from secure storage)
    pub master_key_id: String,
    /// Encryption algorithm settings
    pub algorithm: EncryptionAlgorithm,
    /// Key derivation settings
    pub key_derivation: KeyDerivationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationConfig {
    /// Argon2 memory cost (in KB)
    pub memory_cost: u32,
    /// Argon2 time cost (iterations)
    pub time_cost: u32,
    /// Argon2 parallelism
    pub parallelism: u32,
    /// Salt length in bytes
    pub salt_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            key_rotation_hours: 24, // Rotate keys daily
            master_key_id: "default".to_string(),
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            key_derivation: KeyDerivationConfig::default(),
        }
    }
}

impl Default for KeyDerivationConfig {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,       // 3 iterations
            parallelism: 4,     // 4 threads
            salt_length: 32,    // 32 bytes
        }
    }
}

/// Secure key material that zeros itself on drop
#[derive(Clone)]
pub struct SecureKey {
    pub key_id: String,
    pub key_data: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // Zero out the key data when dropped
        self.key_data.fill(0);
    }
}

impl SecureKey {
    pub fn new(key_id: String, key_data: Vec<u8>) -> Self {
        Self {
            key_id,
            key_data,
            created_at: chrono::Utc::now(),
            expires_at: None,
        }
    }

    pub fn with_expiry(mut self, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            chrono::Utc::now() > expires_at
        } else {
            false
        }
    }
}

/// Encrypted data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub key_id: String,
    pub algorithm: EncryptionAlgorithm,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
    pub encrypted_at: chrono::DateTime<chrono::Utc>,
}

/// Key management and encryption operations
pub struct DataEncryptor {
    config: EncryptionConfig,
    keys: HashMap<String, SecureKey>,
    current_key_id: String,
    rng: SystemRandom,
}

impl DataEncryptor {
    pub fn new(config: &EncryptionConfig) -> Result<Self, DevDocsError> {
        let mut encryptor = Self {
            config: config.clone(),
            keys: HashMap::new(),
            current_key_id: String::new(),
            rng: SystemRandom::new(),
        };

        // Generate initial key
        encryptor.rotate_key()?;

        Ok(encryptor)
    }

    /// Encrypt data using the current key
    pub fn encrypt(&self, data: &[u8], context: &str) -> Result<Vec<u8>, DevDocsError> {
        if !self.config.enabled {
            return Ok(data.to_vec());
        }

        let key = self.keys.get(&self.current_key_id)
            .ok_or_else(|| DevDocsError::Encryption("Current key not found".to_string()))?;

        if key.is_expired() {
            return Err(DevDocsError::Encryption("Current key has expired".to_string()));
        }

        match self.config.algorithm {
            EncryptionAlgorithm::Aes256Gcm => self.encrypt_aes_gcm(data, key, context),
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                Err(DevDocsError::Encryption("ChaCha20Poly1305 not implemented yet".to_string()))
            }
        }
    }

    /// Decrypt data using the appropriate key
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, DevDocsError> {
        if !self.config.enabled {
            return Ok(encrypted_data.to_vec());
        }

        let encrypted: EncryptedData = serde_json::from_slice(encrypted_data)
            .map_err(|e| DevDocsError::Encryption(format!("Failed to parse encrypted data: {}", e)))?;

        let key = self.keys.get(&encrypted.key_id)
            .ok_or_else(|| DevDocsError::Encryption(format!("Key {} not found", encrypted.key_id)))?;

        match encrypted.algorithm {
            EncryptionAlgorithm::Aes256Gcm => self.decrypt_aes_gcm(&encrypted, key),
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                Err(DevDocsError::Encryption("ChaCha20Poly1305 not implemented yet".to_string()))
            }
        }
    }

    /// Rotate encryption keys
    pub fn rotate_key(&mut self) -> Result<(), DevDocsError> {
        let key_id = format!("key_{}", chrono::Utc::now().timestamp());
        let key_data = self.generate_key()?;
        
        let expires_at = chrono::Utc::now() + 
            chrono::Duration::hours(self.config.key_rotation_hours as i64 * 2); // Keep old keys for 2x rotation period

        let secure_key = SecureKey::new(key_id.clone(), key_data)
            .with_expiry(expires_at);

        self.keys.insert(key_id.clone(), secure_key);
        self.current_key_id = key_id;

        // Clean up expired keys
        self.cleanup_expired_keys();

        Ok(())
    }

    /// Derive key from master key and context
    pub fn derive_key(&self, context: &str, salt: &[u8]) -> Result<Vec<u8>, DevDocsError> {
        let master_key = self.get_master_key()?;
        
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                self.config.key_derivation.memory_cost,
                self.config.key_derivation.time_cost,
                self.config.key_derivation.parallelism,
                Some(32), // 32-byte output
            ).map_err(|e| DevDocsError::Encryption(format!("Invalid Argon2 params: {}", e)))?,
        );

        // Use salt directly for key derivation
        let salt_bytes = salt;

        let mut output = vec![0u8; 32];
        argon2.hash_password_into(
            format!("{}:{}", master_key, context).as_bytes(),
            salt_bytes,
            &mut output,
        ).map_err(|e| DevDocsError::Encryption(format!("Key derivation failed: {}", e)))?;

        Ok(output)
    }

    fn encrypt_aes_gcm(&self, data: &[u8], key: &SecureKey, _context: &str) -> Result<Vec<u8>, DevDocsError> {
        let cipher_key = Key::<Aes256Gcm>::from_slice(&key.key_data[..32]);
        let cipher = Aes256Gcm::new(cipher_key);
        
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|e| DevDocsError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;

        let encrypted_data = EncryptedData {
            key_id: key.key_id.clone(),
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: nonce.to_vec(),
            ciphertext: ciphertext[..ciphertext.len()-16].to_vec(), // Separate tag
            tag: ciphertext[ciphertext.len()-16..].to_vec(),
            encrypted_at: chrono::Utc::now(),
        };

        serde_json::to_vec(&encrypted_data)
            .map_err(|e| DevDocsError::Encryption(format!("Failed to serialize encrypted data: {}", e)))
    }

    fn decrypt_aes_gcm(&self, encrypted: &EncryptedData, key: &SecureKey) -> Result<Vec<u8>, DevDocsError> {
        let cipher_key = Key::<Aes256Gcm>::from_slice(&key.key_data[..32]);
        let cipher = Aes256Gcm::new(cipher_key);
        
        let nonce = Nonce::from_slice(&encrypted.nonce);
        
        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = encrypted.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&encrypted.tag);
        
        cipher.decrypt(nonce, ciphertext_with_tag.as_slice())
            .map_err(|e| DevDocsError::Encryption(format!("AES-GCM decryption failed: {}", e)))
    }

    fn generate_key(&self) -> Result<Vec<u8>, DevDocsError> {
        let mut key = vec![0u8; 32]; // 256-bit key
        self.rng.fill(&mut key)
            .map_err(|e| DevDocsError::Encryption(format!("Key generation failed: {}", e)))?;
        Ok(key)
    }

    fn get_master_key(&self) -> Result<String, DevDocsError> {
        // In production, this should fetch from secure key management service
        // For now, use environment variable or default
        std::env::var("DEVDOCS_MASTER_KEY")
            .or_else(|_: std::env::VarError| Ok("default_master_key_change_in_production".to_string()))
            .map_err(|e: std::env::VarError| DevDocsError::Encryption(format!("Master key not available: {}", e)))
    }

    fn cleanup_expired_keys(&mut self) {
        let _now = chrono::Utc::now();
        self.keys.retain(|_, key| !key.is_expired());
    }

    /// Check if automatic key rotation is needed
    pub fn should_rotate_key(&self) -> bool {
        if let Some(current_key) = self.keys.get(&self.current_key_id) {
            let rotation_interval = chrono::Duration::hours(self.config.key_rotation_hours as i64);
            chrono::Utc::now() - current_key.created_at > rotation_interval
        } else {
            true // No current key, need to rotate
        }
    }

    /// Get encryption metadata for audit purposes
    pub fn get_encryption_metadata(&self) -> EncryptionMetadata {
        EncryptionMetadata {
            enabled: self.config.enabled,
            current_key_id: self.current_key_id.clone(),
            algorithm: self.config.algorithm.clone(),
            key_count: self.keys.len(),
            last_rotation: self.keys.get(&self.current_key_id)
                .map(|k| k.created_at),
        }
    }
}

/// Encryption metadata for monitoring and audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    pub enabled: bool,
    pub current_key_id: String,
    pub algorithm: EncryptionAlgorithm,
    pub key_count: usize,
    pub last_rotation: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_config_default() {
        let config = EncryptionConfig::default();
        assert!(config.enabled);
        assert_eq!(config.key_rotation_hours, 24);
        assert!(matches!(config.algorithm, EncryptionAlgorithm::Aes256Gcm));
    }

    #[test]
    fn test_secure_key_creation() {
        let key_data = vec![1, 2, 3, 4];
        let key = SecureKey::new("test_key".to_string(), key_data.clone());
        
        assert_eq!(key.key_id, "test_key");
        assert_eq!(key.key_data, key_data);
        assert!(!key.is_expired());
    }

    #[test]
    fn test_secure_key_expiry() {
        let key_data = vec![1, 2, 3, 4];
        let past_time = chrono::Utc::now() - chrono::Duration::hours(1);
        let key = SecureKey::new("test_key".to_string(), key_data)
            .with_expiry(past_time);
        
        assert!(key.is_expired());
    }

    #[test]
    fn test_data_encryptor_creation() {
        let config = EncryptionConfig::default();
        let encryptor = DataEncryptor::new(&config);
        assert!(encryptor.is_ok());
    }

    #[test]
    fn test_encryption_disabled() {
        let mut config = EncryptionConfig::default();
        config.enabled = false;
        
        let encryptor = DataEncryptor::new(&config).unwrap();
        let data = b"test data";
        let encrypted = encryptor.encrypt(data, "test_context").unwrap();
        
        assert_eq!(encrypted, data);
    }

    #[test]
    fn test_key_rotation() {
        let config = EncryptionConfig::default();
        let mut encryptor = DataEncryptor::new(&config).unwrap();
        
        let original_key_id = encryptor.current_key_id.clone();
        
        // Force key rotation
        std::thread::sleep(std::time::Duration::from_millis(1));
        encryptor.rotate_key().unwrap();
        
        assert_ne!(encryptor.current_key_id, original_key_id);
        assert_eq!(encryptor.keys.len(), 2); // Original + new key
    }

    #[test]
    fn test_encryption_metadata() {
        let config = EncryptionConfig::default();
        let encryptor = DataEncryptor::new(&config).unwrap();
        
        let metadata = encryptor.get_encryption_metadata();
        assert!(metadata.enabled);
        assert!(!metadata.current_key_id.is_empty());
        assert!(matches!(metadata.algorithm, EncryptionAlgorithm::Aes256Gcm));
        assert_eq!(metadata.key_count, 1);
    }

    #[test]
    fn test_should_rotate_key() {
        let mut config = EncryptionConfig::default();
        config.key_rotation_hours = 0; // Immediate rotation needed
        
        let encryptor = DataEncryptor::new(&config).unwrap();
        
        // Should need rotation immediately due to 0 hour rotation interval
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(encryptor.should_rotate_key());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let encrypted_data = EncryptedData {
            key_id: "test_key".to_string(),
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![1, 2, 3],
            ciphertext: vec![4, 5, 6],
            tag: vec![7, 8, 9],
            encrypted_at: chrono::Utc::now(),
        };

        let serialized = serde_json::to_string(&encrypted_data).unwrap();
        let deserialized: EncryptedData = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized.key_id, encrypted_data.key_id);
        assert_eq!(deserialized.nonce, encrypted_data.nonce);
    }
}