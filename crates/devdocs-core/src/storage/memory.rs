//! In-memory storage implementation with data integrity

use super::{IntegrityReport, Storage, StorageFilter, StorageStats};
use crate::models::HttpTransaction;
use crate::{DevDocsError, Result, StorageConfig};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// In-memory storage implementation
pub struct MemoryStorage {
    /// Storage for transactions
    transactions: RwLock<HashMap<String, HttpTransaction>>,
    
    /// Configuration
    config: StorageConfig,
}

impl MemoryStorage {
    /// Create a new in-memory storage instance
    #[must_use]
    pub fn new(config: StorageConfig) -> Self {
        info!("Initializing in-memory storage");
        
        Self {
            transactions: RwLock::new(HashMap::new()),
            config,
        }
    }
    
    /// Get current storage size in bytes (approximate)
    fn estimate_size(&self) -> usize {
        let transactions = self.transactions.read().unwrap();
        transactions.values()
            .map(|t| {
                // Rough estimation of transaction size
                t.request.body.len() + 
                t.response.body.len() + 
                500 // metadata overhead
            })
            .sum()
    }
    
    /// Check if storage is at capacity
    fn is_at_capacity(&self, new_transaction_size: usize) -> bool {
        if let Some(max_size) = self.config.max_size {
            self.estimate_size() + new_transaction_size > max_size
        } else {
            false
        }
    }
    
    /// Apply retention policy
    fn apply_retention(&self) {
        if let Some(retention_period) = self.config.retention_period {
            let mut transactions = self.transactions.write().unwrap();
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let initial_count = transactions.len();
            transactions.retain(|_, transaction| {
                current_time - transaction.timestamp < retention_period
            });
            
            let removed_count = initial_count - transactions.len();
            if removed_count > 0 {
                info!("Removed {} expired transactions from memory storage", removed_count);
            }
        }
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn store(&self, transaction: HttpTransaction) -> Result<()> {
        // Verify transaction integrity before storing
        if !transaction.verify_integrity() {
            return Err(DevDocsError::DataIntegrity(
                "Transaction failed integrity check".into(),
            ));
        }
        
        let transaction_size = transaction.request.body.len() + transaction.response.body.len();
        
        // Check capacity limits
        if self.is_at_capacity(transaction_size) {
            warn!("Memory storage at capacity, applying retention policy");
            self.apply_retention();
            
            if self.is_at_capacity(transaction_size) {
                return Err(DevDocsError::Storage(
                    "Storage capacity exceeded".into(),
                ));
            }
        }
        
        let transaction_id = transaction.id.to_string();
        
        {
            let mut transactions = self.transactions.write()
                .map_err(|e| DevDocsError::Storage(format!("Lock error: {}", e)))?;
            
            transactions.insert(transaction_id.clone(), transaction);
        }
        
        debug!("Stored transaction {} in memory", transaction_id);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<HttpTransaction>> {
        let transactions = self.transactions.read()
            .map_err(|e| DevDocsError::Storage(format!("Lock error: {}", e)))?;
        
        let transaction = transactions.get(id).cloned();
        
        // Verify integrity of retrieved transaction
        if let Some(ref t) = transaction {
            if !t.verify_integrity() {
                warn!("Retrieved transaction {} failed integrity check", id);
                return Err(DevDocsError::DataIntegrity(
                    format!("Transaction {} integrity check failed", id),
                ));
            }
        }
        
        Ok(transaction)
    }

    async fn list(&self, filter: StorageFilter) -> Result<Vec<HttpTransaction>> {
        let transactions = self.transactions.read()
            .map_err(|e| DevDocsError::Storage(format!("Lock error: {}", e)))?;
        
        let mut results: Vec<HttpTransaction> = transactions
            .values()
            .filter(|transaction| {
                // Apply path filter
                if let Some(ref path) = filter.path {
                    if !transaction.request.path.contains(path) {
                        return false;
                    }
                }
                
                // Apply method filter
                if let Some(ref method) = filter.method {
                    if transaction.request.method != *method {
                        return false;
                    }
                }
                
                // Apply status filter
                if let Some(status) = filter.status {
                    if transaction.response.status_code != status {
                        return false;
                    }
                }
                
                // Apply time range filter
                if let Some(start) = filter.time_start {
                    if transaction.timestamp < start {
                        return false;
                    }
                }
                
                if let Some(end) = filter.time_end {
                    if transaction.timestamp > end {
                        return false;
                    }
                }
                
                true
            })
            .cloned()
            .collect();
        
        // Sort by timestamp (newest first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // Apply offset
        if let Some(offset) = filter.offset {
            if offset < results.len() {
                results = results.into_iter().skip(offset).collect();
            } else {
                results.clear();
            }
        }
        
        // Apply limit
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }
        
        // Verify integrity of all returned transactions
        for transaction in &results {
            if !transaction.verify_integrity() {
                return Err(DevDocsError::DataIntegrity(
                    format!("Transaction {} integrity check failed", transaction.id),
                ));
            }
        }
        
        Ok(results)
    }

    async fn verify_integrity(&self) -> Result<IntegrityReport> {
        let start_time = SystemTime::now();
        
        let transactions = self.transactions.read()
            .map_err(|e| DevDocsError::Storage(format!("Lock error: {}", e)))?;
        
        let mut failed_ids = Vec::new();
        let transactions_checked = transactions.len();
        
        for (id, transaction) in transactions.iter() {
            if !transaction.verify_integrity() {
                failed_ids.push(id.clone());
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
        let transactions = self.transactions.read()
            .map_err(|e| DevDocsError::Storage(format!("Lock error: {}", e)))?;
        
        let total_transactions = transactions.len();
        let total_size_bytes = self.estimate_size();
        
        let mut unique_endpoints = std::collections::HashSet::new();
        let mut total_transaction_size = 0;
        let mut oldest_timestamp = None;
        let mut newest_timestamp = None;
        
        for transaction in transactions.values() {
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
