//! Disk-based storage implementation with data integrity

use super::{IntegrityReport, Storage, StorageFilter, StorageStats};
use crate::models::HttpTransaction;
use crate::{DevDocsError, Result, StorageConfig};
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Disk-based storage implementation
pub struct DiskStorage {
    /// Storage directory path
    storage_path: PathBuf,
    
    /// Configuration
    config: StorageConfig,
}

impl DiskStorage {
    /// Create a new disk storage instance
    pub fn new(storage_path: String, config: StorageConfig) -> Result<Self> {
        let path = PathBuf::from(storage_path);
        
        // Create storage directory if it doesn't exist
        if !path.exists() {
            std::fs::create_dir_all(&path)
                .map_err(|e| DevDocsError::Storage(format!("Failed to create storage directory: {}", e)))?;
        }
        
        info!("Initialized disk storage at: {}", path.display());
        
        Ok(Self {
            storage_path: path,
            config,
        })
    }
    
    /// Get the file path for a transaction
    fn transaction_path(&self, id: &str) -> PathBuf {
        self.storage_path.join(format!("{}.json", id))
    }
    
    /// Get current storage size in bytes
    fn get_storage_size(&self) -> Result<usize> {
        let mut total_size = 0;
        
        let entries = std::fs::read_dir(&self.storage_path)
            .map_err(|e| DevDocsError::Storage(format!("Failed to read storage directory: {}", e)))?;
        
        for entry in entries {
            let entry = entry
                .map_err(|e| DevDocsError::Storage(format!("Failed to read directory entry: {}", e)))?;
            
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let metadata = entry.metadata()
                    .map_err(|e| DevDocsError::Storage(format!("Failed to read file metadata: {}", e)))?;
                total_size += metadata.len() as usize;
            }
        }
        
        Ok(total_size)
    }
    
    /// Check if storage is at capacity
    fn is_at_capacity(&self, new_transaction_size: usize) -> Result<bool> {
        if let Some(max_size) = self.config.max_size {
            let current_size = self.get_storage_size()?;
            Ok(current_size + new_transaction_size > max_size)
        } else {
            Ok(false)
        }
    }
    
    /// Apply retention policy
    fn apply_retention(&self) -> Result<()> {
        if let Some(retention_period) = self.config.retention_period {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let entries = std::fs::read_dir(&self.storage_path)
                .map_err(|e| DevDocsError::Storage(format!("Failed to read storage directory: {}", e)))?;
            
            let mut removed_count = 0;
            
            for entry in entries {
                let entry = entry
                    .map_err(|e| DevDocsError::Storage(format!("Failed to read directory entry: {}", e)))?;
                
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    // Try to read the transaction to check its timestamp
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(transaction) = serde_json::from_str::<HttpTransaction>(&content) {
                            if current_time - transaction.timestamp > retention_period {
                                if std::fs::remove_file(&path).is_ok() {
                                    removed_count += 1;
                                }
                            }
                        }
                    }
                }
            }
            
            if removed_count > 0 {
                info!("Removed {} expired transactions from disk storage", removed_count);
            }
        }
        
        Ok(())
    }
}

#[async_trait]
impl Storage for DiskStorage {
    async fn store(&self, transaction: HttpTransaction) -> Result<()> {
        // Verify transaction integrity before storing
        if !transaction.verify_integrity() {
            return Err(DevDocsError::DataIntegrity(
                "Transaction failed integrity check".into(),
            ));
        }
        
        // Serialize transaction
        let content = serde_json::to_string_pretty(&transaction)
            .map_err(|e| DevDocsError::Storage(format!("Failed to serialize transaction: {}", e)))?;
        
        let transaction_size = content.len();
        
        // Check capacity limits
        if self.is_at_capacity(transaction_size)? {
            warn!("Disk storage at capacity, applying retention policy");
            self.apply_retention()?;
            
            if self.is_at_capacity(transaction_size)? {
                return Err(DevDocsError::Storage(
                    "Storage capacity exceeded".into(),
                ));
            }
        }
        
        let file_path = self.transaction_path(&transaction.id.to_string());
        
        // Write to temporary file first, then rename for atomic operation
        let temp_path = file_path.with_extension("tmp");
        
        std::fs::write(&temp_path, content)
            .map_err(|e| DevDocsError::Storage(format!("Failed to write transaction file: {}", e)))?;
        
        std::fs::rename(&temp_path, &file_path)
            .map_err(|e| DevDocsError::Storage(format!("Failed to rename transaction file: {}", e)))?;
        
        debug!("Stored transaction {} to disk", transaction.id);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<HttpTransaction>> {
        let file_path = self.transaction_path(id);
        
        if !file_path.exists() {
            return Ok(None);
        }
        
        let content = std::fs::read_to_string(&file_path)
            .map_err(|e| DevDocsError::Storage(format!("Failed to read transaction file: {}", e)))?;
        
        let transaction: HttpTransaction = serde_json::from_str(&content)
            .map_err(|e| DevDocsError::Storage(format!("Failed to deserialize transaction: {}", e)))?;
        
        // Verify integrity of retrieved transaction
        if !transaction.verify_integrity() {
            warn!("Retrieved transaction {} failed integrity check", id);
            return Err(DevDocsError::DataIntegrity(
                format!("Transaction {} integrity check failed", id),
            ));
        }
        
        Ok(Some(transaction))
    }

    async fn list(&self, filter: StorageFilter) -> Result<Vec<HttpTransaction>> {
        let entries = std::fs::read_dir(&self.storage_path)
            .map_err(|e| DevDocsError::Storage(format!("Failed to read storage directory: {}", e)))?;
        
        let mut transactions = Vec::new();
        
        for entry in entries {
            let entry = entry
                .map_err(|e| DevDocsError::Storage(format!("Failed to read directory entry: {}", e)))?;
            
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| DevDocsError::Storage(format!("Failed to read transaction file: {}", e)))?;
                
                let transaction: HttpTransaction = serde_json::from_str(&content)
                    .map_err(|e| DevDocsError::Storage(format!("Failed to deserialize transaction: {}", e)))?;
                
                // Verify integrity
                if !transaction.verify_integrity() {
                    warn!("Transaction {} failed integrity check, skipping", transaction.id);
                    continue;
                }
                
                // Apply filters
                let mut include = true;
                
                if let Some(ref path_filter) = filter.path {
                    if !transaction.request.path.contains(path_filter) {
                        include = false;
                    }
                }
                
                if let Some(ref method) = filter.method {
                    if transaction.request.method != *method {
                        include = false;
                    }
                }
                
                if let Some(status) = filter.status {
                    if transaction.response.status_code != status {
                        include = false;
                    }
                }
                
                if let Some(start) = filter.time_start {
                    if transaction.timestamp < start {
                        include = false;
                    }
                }
                
                if let Some(end) = filter.time_end {
                    if transaction.timestamp > end {
                        include = false;
                    }
                }
                
                if include {
                    transactions.push(transaction);
                }
            }
        }
        
        // Sort by timestamp (newest first)
        transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // Apply offset
        if let Some(offset) = filter.offset {
            if offset < transactions.len() {
                transactions = transactions.into_iter().skip(offset).collect();
            } else {
                transactions.clear();
            }
        }
        
        // Apply limit
        if let Some(limit) = filter.limit {
            transactions.truncate(limit);
        }
        
        Ok(transactions)
    }

    async fn verify_integrity(&self) -> Result<IntegrityReport> {
        let start_time = std::time::SystemTime::now();
        
        let entries = std::fs::read_dir(&self.storage_path)
            .map_err(|e| DevDocsError::Storage(format!("Failed to read storage directory: {}", e)))?;
        
        let mut failed_ids = Vec::new();
        let mut transactions_checked = 0;
        
        for entry in entries {
            let entry = entry
                .map_err(|e| DevDocsError::Storage(format!("Failed to read directory entry: {}", e)))?;
            
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                transactions_checked += 1;
                
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(transaction) = serde_json::from_str::<HttpTransaction>(&content) {
                        if !transaction.verify_integrity() {
                            failed_ids.push(transaction.id.to_string());
                        }
                    } else {
                        // Malformed JSON file
                        if let Some(file_name) = path.file_stem().and_then(|s| s.to_str()) {
                            failed_ids.push(file_name.to_string());
                        }
                    }
                }
            }
        }
        
        let verification_time_ms = start_time.elapsed()
            .unwrap_or_default()
            .as_millis() as u64;
        
        let integrity_failures = failed_ids.len();
        
        if integrity_failures > 0 {
            warn!("Integrity verification found {} failures out of {} transactions", 
                  integrity_failures, transactions_checked);
        } else {
            info!("Integrity verification passed for all {} transactions", transactions_checked);
        }
        
        Ok(IntegrityReport {
            transactions_checked,
            integrity_failures,
            failed_ids,
            verification_time_ms,
        })
    }

    async fn stats(&self) -> Result<StorageStats> {
        let entries = std::fs::read_dir(&self.storage_path)
            .map_err(|e| DevDocsError::Storage(format!("Failed to read storage directory: {}", e)))?;
        
        let mut total_transactions = 0;
        let mut total_size_bytes = 0;
        let mut unique_endpoints = std::collections::HashSet::new();
        let mut total_transaction_size = 0;
        let mut oldest_timestamp = None;
        let mut newest_timestamp = None;
        
        for entry in entries {
            let entry = entry
                .map_err(|e| DevDocsError::Storage(format!("Failed to read directory entry: {}", e)))?;
            
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                total_transactions += 1;
                
                let metadata = entry.metadata()
                    .map_err(|e| DevDocsError::Storage(format!("Failed to read file metadata: {}", e)))?;
                total_size_bytes += metadata.len() as usize;
                
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(transaction) = serde_json::from_str::<HttpTransaction>(&content) {
                        unique_endpoints.insert(format!("{} {}", 
                                                      transaction.request.method, 
                                                      transaction.request.path));
                        
                        total_transaction_size += transaction.request.body.len() + transaction.response.body.len();
                        
                        if oldest_timestamp.is_none() || Some(transaction.timestamp) < oldest_timestamp {
                            oldest_timestamp = Some(transaction.timestamp);
                        }
                        
                        if newest_timestamp.is_none() || Some(transaction.timestamp) > newest_timestamp {
                            newest_timestamp = Some(transaction.timestamp);
                        }
                    }
                }
            }
        }
        
        let avg_transaction_size = if total_transactions > 0 {
            total_transaction_size / total_transactions
        } else {
            0
        };
        
        Ok(StorageStats {
            total_transactions,
            total_size_bytes,
            unique_endpoints: unique_endpoints.len(),
            avg_transaction_size,
            oldest_timestamp,
            newest_timestamp,
        })
    }
}
