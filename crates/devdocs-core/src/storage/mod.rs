//! Storage implementations with data integrity guarantees

mod database;
mod disk;
mod memory;
mod encryption;

use crate::models::HttpTransaction;
use crate::{DevDocsError, Result, StorageConfig, StorageType};
use async_trait::async_trait;
use std::sync::Arc;

/// Storage interface for HTTP transactions
#[async_trait]
pub trait Storage: Send + Sync {
    /// Store a transaction with data integrity checks
    async fn store(&self, transaction: HttpTransaction) -> Result<()>;

    /// Retrieve a transaction by ID
    async fn get(&self, id: &str) -> Result<Option<HttpTransaction>>;

    /// List transactions matching filters
    async fn list(&self, filter: StorageFilter) -> Result<Vec<HttpTransaction>>;

    /// Verify data integrity of stored transactions
    async fn verify_integrity(&self) -> Result<IntegrityReport>;

    /// Get storage statistics
    async fn stats(&self) -> Result<StorageStats>;
}

/// Filter criteria for transaction queries
#[derive(Debug, Clone, Default)]
pub struct StorageFilter {
    /// Filter by endpoint path
    pub path: Option<String>,

    /// Filter by HTTP method
    pub method: Option<String>,

    /// Filter by status code
    pub status: Option<u16>,

    /// Filter by time range (start timestamp)
    pub time_start: Option<u64>,

    /// Filter by time range (end timestamp)
    pub time_end: Option<u64>,

    /// Maximum results to return
    pub limit: Option<usize>,

    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Report of data integrity verification
#[derive(Debug)]
pub struct IntegrityReport {
    /// Number of transactions verified
    pub transactions_checked: usize,

    /// Number of transactions with integrity failures
    pub integrity_failures: usize,

    /// IDs of transactions with integrity failures
    pub failed_ids: Vec<String>,

    /// Total verification time in milliseconds
    pub verification_time_ms: u64,
}

/// Storage statistics
#[derive(Debug)]
pub struct StorageStats {
    /// Total number of transactions stored
    pub total_transactions: usize,

    /// Total storage size in bytes
    pub total_size_bytes: usize,

    /// Number of unique endpoints
    pub unique_endpoints: usize,

    /// Average transaction size in bytes
    pub avg_transaction_size: usize,

    /// Oldest transaction timestamp
    pub oldest_timestamp: Option<u64>,

    /// Newest transaction timestamp
    pub newest_timestamp: Option<u64>,
}

/// Create a new storage instance based on configuration
pub fn create_storage(config: &StorageConfig) -> Result<Arc<dyn Storage>> {
    match config.storage_type {
        StorageType::Memory => {
            // Initialize in-memory storage
            Ok(Arc::new(memory::MemoryStorage::new(config.clone())))
        }
        StorageType::Disk => {
            if let Some(path) = &config.storage_path {
                // Initialize disk storage
                Ok(Arc::new(disk::DiskStorage::new(
                    path.clone(),
                    config.clone(),
                )?))
            } else {
                Err(DevDocsError::Configuration(
                    "Storage path required for disk storage".into(),
                ))
            }
        }
        StorageType::Database => {
            if let Some(conn) = &config.db_connection {
                // Initialize database storage
                Ok(Arc::new(database::DatabaseStorage::new(
                    conn.clone(),
                    config.clone(),
                )?))
            } else {
                Err(DevDocsError::Configuration(
                    "Database connection string required".into(),
                ))
            }
        }
    }
}

impl StorageFilter {
    /// Create a new empty filter
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add path filter
    pub fn with_path(mut self, path: String) -> Self {
        self.path = Some(path);
        self
    }

    /// Add method filter
    pub fn with_method(mut self, method: String) -> Self {
        self.method = Some(method);
        self
    }

    /// Add status filter
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Add time range filter
    pub fn with_time_range(mut self, start: u64, end: u64) -> Self {
        self.time_start = Some(start);
        self.time_end = Some(end);
        self
    }

    /// Add limit
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Add offset for pagination
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}
