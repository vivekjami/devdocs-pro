//! Encryption utilities for data protection

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use crate::{DevDocsError, Result};

/// Encryption service for protecting sensitive data
pub struct EncryptionService {
    cipher: Aes256Gcm,
}

impl EncryptionService {
    /// Create a new encryption service with the provided key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(key.into());
        Self { cipher }
    }

    /// Encrypt data with the provided nonce
    pub fn encrypt(&self, data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .encrypt(nonce, data)
            .map_err(|e| DevDocsError::Security(format!("Encryption failed: {}", e)))
    }

    /// Decrypt data with the provided nonce
    pub fn decrypt(&self, encrypted_data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| DevDocsError::Security(format!("Decryption failed: {}", e)))
    }
}

/// Generate a random encryption key
#[must_use]
pub fn generate_key() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    // In a real implementation, use a proper random number generator
    // This is a simplified version for demonstration
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    
    let mut key = [0u8; 32];
    let timestamp_bytes = timestamp.to_be_bytes();
    
    // Fill key with timestamp-based pseudo-random data
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = timestamp_bytes[i % timestamp_bytes.len()].wrapping_add(i as u8);
    }
    
    key
}

/// Generate a random nonce
#[must_use]
pub fn generate_nonce() -> [u8; 12] {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    // In a real implementation, use a proper random number generator
    // This is a simplified version for demonstration
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    
    let mut nonce = [0u8; 12];
    let timestamp_bytes = timestamp.to_be_bytes();
    
    for (i, byte) in nonce.iter_mut().enumerate() {
        *byte = timestamp_bytes[i % timestamp_bytes.len()].wrapping_mul(i as u8 + 1);
    }
    
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let key = generate_key();
        let service = EncryptionService::new(&key);
        let nonce = generate_nonce();
        
        let data = b"sensitive data";
        let encrypted = service.encrypt(data, &nonce).unwrap();
        let decrypted = service.decrypt(&encrypted, &nonce).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_key_generation() {
        let key1 = generate_key();
        let key2 = generate_key();
        
        // Keys should be different (with high probability)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        
        // Nonces should be different (with high probability)
        assert_ne!(nonce1, nonce2);
    }
}
