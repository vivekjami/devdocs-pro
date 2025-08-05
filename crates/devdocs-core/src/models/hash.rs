//! Hash utilities for data integrity

use sha2::{Digest, Sha256};
use std::fmt;

/// Represents a cryptographic hash for data integrity
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash {
    /// The hash value as bytes
    bytes: Vec<u8>,
    
    /// Hash algorithm used
    algorithm: HashAlgorithm,
}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 algorithm
    Sha256,
}

impl Hash {
    /// Create a new SHA-256 hash from data
    #[must_use]
    pub fn sha256(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        
        Self {
            bytes: result.to_vec(),
            algorithm: HashAlgorithm::Sha256,
        }
    }
    
    /// Create a hash from multiple data pieces
    #[must_use]
    pub fn sha256_multi(data_pieces: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for piece in data_pieces {
            hasher.update(piece);
        }
        let result = hasher.finalize();
        
        Self {
            bytes: result.to_vec(),
            algorithm: HashAlgorithm::Sha256,
        }
    }
    
    /// Get the hash as a hexadecimal string
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }
    
    /// Get the hash bytes
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Get the hash algorithm
    #[must_use]
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
    
    /// Verify data against this hash
    pub fn verify(&self, data: &[u8]) -> bool {
        let computed_hash = match self.algorithm {
            HashAlgorithm::Sha256 => Self::sha256(data),
        };
        
        computed_hash.bytes == self.bytes
    }
    
    /// Verify multiple data pieces against this hash
    pub fn verify_multi(&self, data_pieces: &[&[u8]]) -> bool {
        let computed_hash = match self.algorithm {
            HashAlgorithm::Sha256 => Self::sha256_multi(data_pieces),
        };
        
        computed_hash.bytes == self.bytes
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "SHA-256"),
        }
    }
}

// Add hex dependency to workspace
// Note: This would normally be added to Cargo.toml, but for now we'll implement hex encoding manually
mod hex {
    /// Encode bytes as hexadecimal string
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = Hash::sha256(data);
        
        // Known SHA-256 hash of "hello world"
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(hash.to_hex(), expected);
    }

    #[test]
    fn test_hash_verification() {
        let data = b"test data";
        let hash = Hash::sha256(data);
        
        assert!(hash.verify(data));
        assert!(!hash.verify(b"different data"));
    }

    #[test]
    fn test_multi_piece_hash() {
        let piece1 = b"hello";
        let piece2 = b" ";
        let piece3 = b"world";
        
        let hash_multi = Hash::sha256_multi(&[piece1, piece2, piece3]);
        let hash_single = Hash::sha256(b"hello world");
        
        assert_eq!(hash_multi.bytes(), hash_single.bytes());
    }
}
