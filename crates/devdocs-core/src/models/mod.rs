//! Core data models with data integrity features

mod hash;
mod request;
mod response;
mod schema_types;

pub use hash::Hash;
pub use request::{Request, RequestMetadata};
pub use response::{Response, ResponseMetadata};
pub use schema_types::{Schema, SchemaField, SchemaType};

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Represents a captured HTTP transaction (request + response)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpTransaction {
    /// Unique transaction ID
    pub id: Uuid,

    /// Request details
    pub request: Request,

    /// Response details
    pub response: Response,

    /// Timestamp when transaction was captured
    pub timestamp: u64,

    /// Content hash for data integrity verification
    pub content_hash: String,
}

impl HttpTransaction {
    /// Create a new HTTP transaction from request and response
    #[must_use]
    pub fn new(request: Request, response: Response) -> Self {
        let id = Uuid::new_v4();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // Create content hash for data integrity
        let mut hasher = Sha256::new();
        hasher.update(request.body.as_bytes());
        hasher.update(response.body.as_bytes());
        let hash = hasher.finalize();
        let content_hash = format!("{:x}", hash);

        Self {
            id,
            request,
            response,
            timestamp,
            content_hash,
        }
    }

    /// Verify data integrity by recomputing and comparing hash
    pub fn verify_integrity(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.request.body.as_bytes());
        hasher.update(self.response.body.as_bytes());
        let hash = hasher.finalize();
        let computed_hash = format!("{:x}", hash);

        self.content_hash == computed_hash
    }
}
