//! Comprehensive audit logging and compliance system
//!
//! Provides tamper-evident audit trails, compliance reporting,
//! and security event monitoring.

use crate::errors::DevDocsError;
use crate::security::SecurityContext;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    /// Log level for audit events
    pub log_level: AuditLogLevel,
    /// Storage configuration
    pub storage: AuditStorageConfig,
    /// Retention policy
    pub retention: AuditRetentionConfig,
    /// Enable real-time alerting
    pub enable_alerting: bool,
    /// Compliance standards to track
    pub compliance_standards: Vec<ComplianceStandard>,
    /// Enable log integrity verification
    pub enable_integrity_verification: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditLogLevel {
    /// Log only critical security events
    Critical,
    /// Log important security and access events
    Important,
    /// Log all security-related events
    Detailed,
    /// Log everything including debug information
    Verbose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStorageConfig {
    /// Storage backend type
    pub backend: AuditStorageBackend,
    /// Connection string or configuration
    pub connection_string: String,
    /// Enable encryption at rest
    pub encrypt_at_rest: bool,
    /// Enable compression
    pub enable_compression: bool,
    /// Batch size for bulk operations
    pub batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditStorageBackend {
    /// Local file system
    FileSystem,
    /// PostgreSQL database
    PostgreSQL,
    /// Elasticsearch
    Elasticsearch,
    /// AWS CloudTrail
    CloudTrail,
    /// Azure Monitor
    AzureMonitor,
    /// Google Cloud Logging
    GoogleCloudLogging,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRetentionConfig {
    /// Retention period in days
    pub retention_days: u32,
    /// Archive old logs instead of deleting
    pub enable_archiving: bool,
    /// Archive storage configuration
    pub archive_storage: Option<String>,
    /// Automatic cleanup enabled
    pub auto_cleanup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStandard {
    /// SOC 2 Type II
    Soc2,
    /// GDPR compliance
    Gdpr,
    /// HIPAA compliance
    Hipaa,
    /// PCI DSS compliance
    PciDss,
    /// ISO 27001
    Iso27001,
    /// Custom compliance standard
    Custom(String),
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: AuditLogLevel::Important,
            storage: AuditStorageConfig {
                backend: AuditStorageBackend::FileSystem,
                connection_string: "./audit_logs".to_string(),
                encrypt_at_rest: true,
                enable_compression: true,
                batch_size: 100,
            },
            retention: AuditRetentionConfig {
                retention_days: 365, // 1 year default
                enable_archiving: true,
                archive_storage: None,
                auto_cleanup: true,
            },
            enable_alerting: true,
            compliance_standards: vec![ComplianceStandard::Soc2],
            enable_integrity_verification: true,
        }
    }
}

/// Audit event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditEventType {
    // Authentication events
    LoginSuccess,
    LoginFailure,
    Logout,
    TokenGenerated,
    TokenRevoked,
    PasswordChanged,

    // Authorization events
    AccessGranted,
    AccessDenied,
    PermissionChanged,
    RoleAssigned,
    RoleRevoked,

    // Data access events
    DataRead,
    DataWrite,
    DataDelete,
    DataExport,
    DataImport,

    // Configuration events
    ConfigurationChanged,
    UserCreated,
    UserDeleted,
    UserModified,
    OrganizationCreated,
    OrganizationModified,

    // Security events
    SecurityViolation,
    PiiDetected,
    EncryptionKeyRotated,
    SuspiciousActivity,
    RateLimitExceeded,

    // System events
    SystemStartup,
    SystemShutdown,
    BackupCreated,
    BackupRestored,

    // Compliance events
    ComplianceViolation,
    AuditLogAccessed,
    DataRetentionPolicyApplied,
}

/// Audit event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Comprehensive audit event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier
    pub id: Uuid,
    /// Event type
    pub event_type: AuditEventType,
    /// Event severity
    pub severity: AuditSeverity,
    /// Timestamp when event occurred
    pub timestamp: DateTime<Utc>,
    /// User who triggered the event
    pub user_id: Option<String>,
    /// Organization context
    pub organization_id: Option<String>,
    /// IP address of the request
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Request ID for correlation
    pub request_id: Option<Uuid>,
    /// Session ID
    pub session_id: Option<String>,
    /// Resource that was accessed
    pub resource: Option<String>,
    /// Action that was performed
    pub action: String,
    /// Result of the action
    pub result: AuditResult,
    /// Additional event details
    pub details: HashMap<String, serde_json::Value>,
    /// Compliance tags
    pub compliance_tags: Vec<ComplianceStandard>,
    /// Event hash for integrity verification
    pub integrity_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    Partial,
    Blocked,
}

/// Audit query parameters for searching logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Start time for query range
    pub start_time: Option<DateTime<Utc>>,
    /// End time for query range
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by event types
    pub event_types: Option<Vec<AuditEventType>>,
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by organization ID
    pub organization_id: Option<String>,
    /// Filter by IP address
    pub ip_address: Option<String>,
    /// Filter by severity level
    pub min_severity: Option<AuditSeverity>,
    /// Filter by resource
    pub resource: Option<String>,
    /// Filter by result
    pub result: Option<AuditResult>,
    /// Maximum number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Audit statistics and metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatistics {
    pub total_events: u64,
    pub events_by_type: HashMap<AuditEventType, u64>,
    pub events_by_severity: HashMap<AuditSeverity, u64>,
    pub events_by_result: HashMap<AuditResult, u64>,
    pub unique_users: u64,
    pub unique_ips: u64,
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
    pub compliance_violations: u64,
    pub security_incidents: u64,
}

/// Main audit logger
pub struct AuditLogger {
    config: AuditConfig,
    storage: FileSystemAuditStorage,
    integrity_verifier: Option<IntegrityVerifier>,
}

/// Trait for audit storage backends
#[async_trait::async_trait]
pub trait AuditStorage {
    async fn store_event(&mut self, event: &AuditEvent) -> Result<(), DevDocsError>;
    async fn store_events(&mut self, events: &[AuditEvent]) -> Result<(), DevDocsError>;
    async fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, DevDocsError>;
    async fn get_statistics(&self, query: &AuditQuery) -> Result<AuditStatistics, DevDocsError>;
    async fn cleanup_old_events(&mut self, retention_days: u32) -> Result<u64, DevDocsError>;
}

/// File system audit storage implementation
pub struct FileSystemAuditStorage {
    base_path: std::path::PathBuf,
    encrypt_at_rest: bool,
    enable_compression: bool,
}

/// Integrity verification for audit logs
pub struct IntegrityVerifier {
    secret_key: Vec<u8>,
}

impl AuditLogger {
    pub fn new(config: &AuditConfig) -> Result<Self, DevDocsError> {
        let storage = match config.storage.backend {
            AuditStorageBackend::FileSystem => FileSystemAuditStorage::new(
                &config.storage.connection_string,
                config.storage.encrypt_at_rest,
                config.storage.enable_compression,
            )?,
            _ => {
                return Err(DevDocsError::Configuration(
                    "Unsupported audit storage backend".to_string(),
                ));
            }
        };

        let integrity_verifier = if config.enable_integrity_verification {
            Some(IntegrityVerifier::new()?)
        } else {
            None
        };

        Ok(Self {
            config: config.clone(),
            storage,
            integrity_verifier,
        })
    }

    /// Log an audit event
    pub async fn log_event(&mut self, event: AuditEvent) -> Result<(), DevDocsError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check if event meets minimum log level
        if !self.should_log_event(&event) {
            return Ok(());
        }

        let mut event = event;

        // Add integrity hash if enabled
        if let Some(verifier) = &self.integrity_verifier {
            event.integrity_hash = Some(verifier.calculate_hash(&event)?);
        }

        // Add compliance tags based on event type
        event.compliance_tags = self.determine_compliance_tags(&event);

        self.storage.store_event(&event).await
    }

    /// Log data access event
    pub async fn log_data_access(
        &mut self,
        context: &SecurityContext,
        data_size: usize,
    ) -> Result<(), DevDocsError> {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            event_type: AuditEventType::DataRead,
            severity: AuditSeverity::Info,
            timestamp: Utc::now(),
            user_id: context.user_id.clone(),
            organization_id: context.organization_id.clone(),
            ip_address: Some(context.ip_address.clone()),
            user_agent: context.user_agent.clone(),
            request_id: Some(context.request_id),
            session_id: None,
            resource: None,
            action: "data_access".to_string(),
            result: AuditResult::Success,
            details: {
                let mut details = HashMap::new();
                details.insert(
                    "data_size".to_string(),
                    serde_json::Value::Number(data_size.into()),
                );
                details.insert(
                    "security_level".to_string(),
                    serde_json::Value::String(format!("{:?}", context.security_level)),
                );
                details
            },
            compliance_tags: Vec::new(),
            integrity_hash: None,
        };

        self.log_event(event).await
    }

    /// Log authentication event
    pub async fn log_authentication(
        &mut self,
        user_id: &str,
        ip_address: &str,
        success: bool,
        details: HashMap<String, serde_json::Value>,
    ) -> Result<(), DevDocsError> {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            event_type: if success {
                AuditEventType::LoginSuccess
            } else {
                AuditEventType::LoginFailure
            },
            severity: if success {
                AuditSeverity::Info
            } else {
                AuditSeverity::Warning
            },
            timestamp: Utc::now(),
            user_id: Some(user_id.to_string()),
            organization_id: None,
            ip_address: Some(ip_address.to_string()),
            user_agent: None,
            request_id: None,
            session_id: None,
            resource: None,
            action: "authentication".to_string(),
            result: if success {
                AuditResult::Success
            } else {
                AuditResult::Failure
            },
            details,
            compliance_tags: Vec::new(),
            integrity_hash: None,
        };

        self.log_event(event).await
    }

    /// Log security violation
    pub async fn log_security_violation(
        &mut self,
        context: &SecurityContext,
        violation_type: &str,
        description: &str,
    ) -> Result<(), DevDocsError> {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            event_type: AuditEventType::SecurityViolation,
            severity: AuditSeverity::Critical,
            timestamp: Utc::now(),
            user_id: context.user_id.clone(),
            organization_id: context.organization_id.clone(),
            ip_address: Some(context.ip_address.clone()),
            user_agent: context.user_agent.clone(),
            request_id: Some(context.request_id),
            session_id: None,
            resource: None,
            action: "security_violation".to_string(),
            result: AuditResult::Blocked,
            details: {
                let mut details = HashMap::new();
                details.insert(
                    "violation_type".to_string(),
                    serde_json::Value::String(violation_type.to_string()),
                );
                details.insert(
                    "description".to_string(),
                    serde_json::Value::String(description.to_string()),
                );
                details
            },
            compliance_tags: Vec::new(),
            integrity_hash: None,
        };

        self.log_event(event).await
    }

    /// Query audit events
    pub async fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, DevDocsError> {
        self.storage.query_events(query).await
    }

    /// Get audit statistics
    pub async fn get_statistics(
        &self,
        query: &AuditQuery,
    ) -> Result<AuditStatistics, DevDocsError> {
        self.storage.get_statistics(query).await
    }

    /// Cleanup old audit events
    pub async fn cleanup_old_events(&mut self) -> Result<u64, DevDocsError> {
        if self.config.retention.auto_cleanup {
            self.storage
                .cleanup_old_events(self.config.retention.retention_days)
                .await
        } else {
            Ok(0)
        }
    }

    /// Verify integrity of audit logs
    pub async fn verify_integrity(&self, events: &[AuditEvent]) -> Result<Vec<Uuid>, DevDocsError> {
        if let Some(verifier) = &self.integrity_verifier {
            let mut corrupted_events = Vec::new();

            for event in events {
                if let Some(stored_hash) = &event.integrity_hash {
                    let calculated_hash = verifier.calculate_hash(event)?;
                    if &calculated_hash != stored_hash {
                        corrupted_events.push(event.id);
                    }
                }
            }

            Ok(corrupted_events)
        } else {
            Ok(Vec::new())
        }
    }

    fn should_log_event(&self, event: &AuditEvent) -> bool {
        match self.config.log_level {
            AuditLogLevel::Critical => event.severity >= AuditSeverity::Critical,
            AuditLogLevel::Important => event.severity >= AuditSeverity::Error,
            AuditLogLevel::Detailed => event.severity >= AuditSeverity::Warning,
            AuditLogLevel::Verbose => true,
        }
    }

    fn determine_compliance_tags(&self, event: &AuditEvent) -> Vec<ComplianceStandard> {
        let mut tags = Vec::new();

        for standard in &self.config.compliance_standards {
            match standard {
                ComplianceStandard::Soc2 => {
                    // SOC 2 requires logging of all access and changes
                    if matches!(
                        event.event_type,
                        AuditEventType::DataRead
                            | AuditEventType::DataWrite
                            | AuditEventType::DataDelete
                            | AuditEventType::ConfigurationChanged
                            | AuditEventType::LoginSuccess
                            | AuditEventType::LoginFailure
                    ) {
                        tags.push(standard.clone());
                    }
                }
                ComplianceStandard::Gdpr => {
                    // GDPR requires logging of personal data access
                    if matches!(
                        event.event_type,
                        AuditEventType::DataRead
                            | AuditEventType::DataWrite
                            | AuditEventType::DataDelete
                            | AuditEventType::DataExport
                            | AuditEventType::PiiDetected
                    ) {
                        tags.push(standard.clone());
                    }
                }
                ComplianceStandard::Hipaa => {
                    // HIPAA requires comprehensive audit trails
                    tags.push(standard.clone());
                }
                _ => {}
            }
        }

        tags
    }
}

impl FileSystemAuditStorage {
    pub fn new(
        base_path: &str,
        encrypt_at_rest: bool,
        enable_compression: bool,
    ) -> Result<Self, DevDocsError> {
        let path = std::path::PathBuf::from(base_path);
        std::fs::create_dir_all(&path).map_err(|e| {
            DevDocsError::Storage(format!("Failed to create audit log directory: {}", e))
        })?;

        Ok(Self {
            base_path: path,
            encrypt_at_rest,
            enable_compression,
        })
    }

    fn get_log_file_path(&self, date: &DateTime<Utc>) -> std::path::PathBuf {
        self.base_path
            .join(format!("audit_{}.jsonl", date.format("%Y-%m-%d")))
    }
}

#[async_trait::async_trait]
impl AuditStorage for FileSystemAuditStorage {
    async fn store_event(&mut self, event: &AuditEvent) -> Result<(), DevDocsError> {
        let log_file = self.get_log_file_path(&event.timestamp);
        let event_json =
            serde_json::to_string(event).map_err(|e| DevDocsError::Serialization(e))?;

        let mut content = event_json + "\n";

        let data_to_write = if self.enable_compression {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(content.as_bytes())
                .map_err(|e| DevDocsError::Storage(format!("Compression failed: {}", e)))?;
            encoder
                .finish()
                .map_err(|e| DevDocsError::Storage(format!("Compression failed: {}", e)))?
        } else {
            content.as_bytes().to_vec()
        };

        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .await
            .map_err(|e| DevDocsError::Storage(format!("Failed to open audit log file: {}", e)))?
            .write_all(&data_to_write)
            .await
            .map_err(|e| DevDocsError::Storage(format!("Failed to write audit event: {}", e)))?;

        Ok(())
    }

    async fn store_events(&mut self, events: &[AuditEvent]) -> Result<(), DevDocsError> {
        for event in events {
            self.store_event(event).await?;
        }
        Ok(())
    }

    async fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, DevDocsError> {
        // Simple implementation - in production would use proper indexing
        let mut events = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_path)
            .await
            .map_err(|e| DevDocsError::Storage(format!("Failed to read audit directory: {}", e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| DevDocsError::Storage(format!("Failed to read directory entry: {}", e)))?
        {
            if let Some(file_name) = entry.file_name().to_str() {
                if file_name.starts_with("audit_") && file_name.ends_with(".jsonl") {
                    let file_data = tokio::fs::read(entry.path()).await.map_err(|e| {
                        DevDocsError::Storage(format!("Failed to read audit file: {}", e))
                    })?;

                    let content = if self.enable_compression {
                        use flate2::read::GzDecoder;
                        use std::io::Read;

                        let mut decoder = GzDecoder::new(&file_data[..]);
                        let mut decompressed = String::new();
                        decoder.read_to_string(&mut decompressed).map_err(|e| {
                            DevDocsError::Storage(format!("Failed to decompress audit file: {}", e))
                        })?;
                        decompressed
                    } else {
                        String::from_utf8(file_data).map_err(|e| {
                            DevDocsError::Storage(format!("Failed to read audit file: {}", e))
                        })?
                    };

                    for line in content.lines() {
                        if let Ok(event) = serde_json::from_str::<AuditEvent>(line) {
                            if self.matches_query(&event, query) {
                                events.push(event);
                            }
                        }
                    }
                }
            }
        }

        // Sort by timestamp
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Apply limit and offset
        if let Some(offset) = query.offset {
            if offset < events.len() {
                events = events[offset..].to_vec();
            } else {
                events.clear();
            }
        }

        if let Some(limit) = query.limit {
            events.truncate(limit);
        }

        Ok(events)
    }

    async fn get_statistics(&self, query: &AuditQuery) -> Result<AuditStatistics, DevDocsError> {
        let events = self.query_events(query).await?;

        let mut stats = AuditStatistics {
            total_events: events.len() as u64,
            events_by_type: HashMap::new(),
            events_by_severity: HashMap::new(),
            events_by_result: HashMap::new(),
            unique_users: 0,
            unique_ips: 0,
            time_range: (Utc::now(), Utc::now()),
            compliance_violations: 0,
            security_incidents: 0,
        };

        if !events.is_empty() {
            stats.time_range.0 = events.first().unwrap().timestamp;
            stats.time_range.1 = events.last().unwrap().timestamp;

            let mut unique_users = std::collections::HashSet::new();
            let mut unique_ips = std::collections::HashSet::new();

            for event in &events {
                *stats.events_by_type.entry(event.event_type).or_insert(0) += 1;
                *stats.events_by_severity.entry(event.severity).or_insert(0) += 1;
                *stats
                    .events_by_result
                    .entry(event.result.clone())
                    .or_insert(0) += 1;

                if let Some(user_id) = &event.user_id {
                    unique_users.insert(user_id.clone());
                }

                if let Some(ip) = &event.ip_address {
                    unique_ips.insert(ip.clone());
                }

                if event.event_type == AuditEventType::ComplianceViolation {
                    stats.compliance_violations += 1;
                }

                if event.event_type == AuditEventType::SecurityViolation {
                    stats.security_incidents += 1;
                }
            }

            stats.unique_users = unique_users.len() as u64;
            stats.unique_ips = unique_ips.len() as u64;
        }

        Ok(stats)
    }

    async fn cleanup_old_events(&mut self, retention_days: u32) -> Result<u64, DevDocsError> {
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);
        let mut deleted_count = 0u64;

        let mut entries = tokio::fs::read_dir(&self.base_path)
            .await
            .map_err(|e| DevDocsError::Storage(format!("Failed to read audit directory: {}", e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| DevDocsError::Storage(format!("Failed to read directory entry: {}", e)))?
        {
            if let Some(file_name) = entry.file_name().to_str() {
                if file_name.starts_with("audit_") && file_name.ends_with(".jsonl") {
                    // Extract date from filename
                    if let Some(date_str) = file_name
                        .strip_prefix("audit_")
                        .and_then(|s| s.strip_suffix(".jsonl"))
                    {
                        if let Ok(file_date) =
                            chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
                        {
                            let file_datetime = file_date.and_hms_opt(0, 0, 0).unwrap().and_utc();
                            if file_datetime < cutoff_date {
                                tokio::fs::remove_file(entry.path()).await.map_err(|e| {
                                    DevDocsError::Storage(format!(
                                        "Failed to delete old audit file: {}",
                                        e
                                    ))
                                })?;
                                deleted_count += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(deleted_count)
    }
}

impl FileSystemAuditStorage {
    fn matches_query(&self, event: &AuditEvent, query: &AuditQuery) -> bool {
        if let Some(start_time) = query.start_time {
            if event.timestamp < start_time {
                return false;
            }
        }

        if let Some(end_time) = query.end_time {
            if event.timestamp > end_time {
                return false;
            }
        }

        if let Some(event_types) = &query.event_types {
            if !event_types.contains(&event.event_type) {
                return false;
            }
        }

        if let Some(user_id) = &query.user_id {
            if event.user_id.as_ref() != Some(user_id) {
                return false;
            }
        }

        if let Some(org_id) = &query.organization_id {
            if event.organization_id.as_ref() != Some(org_id) {
                return false;
            }
        }

        if let Some(ip) = &query.ip_address {
            if event.ip_address.as_ref() != Some(ip) {
                return false;
            }
        }

        if let Some(min_severity) = query.min_severity {
            if event.severity < min_severity {
                return false;
            }
        }

        true
    }
}

impl IntegrityVerifier {
    pub fn new() -> Result<Self, DevDocsError> {
        let mut secret_key = vec![0u8; 32];
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        rng.fill(&mut secret_key).map_err(|e| {
            DevDocsError::Encryption(format!("Failed to generate integrity key: {}", e))
        })?;

        Ok(Self { secret_key })
    }

    pub fn calculate_hash(&self, event: &AuditEvent) -> Result<String, DevDocsError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Create a copy without the integrity hash for calculation
        let mut event_for_hash = event.clone();
        event_for_hash.integrity_hash = None;

        let event_json =
            serde_json::to_string(&event_for_hash).map_err(|e| DevDocsError::Serialization(e))?;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret_key)
            .map_err(|e| DevDocsError::Encryption(format!("Failed to create HMAC: {}", e)))?;

        mac.update(event_json.as_bytes());
        let result = mac.finalize();

        Ok(hex::encode(result.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert!(config.enabled);
        assert!(matches!(config.log_level, AuditLogLevel::Important));
        assert!(config.enable_integrity_verification);
    }

    #[tokio::test]
    async fn test_audit_logger_creation() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = AuditConfig::default();
        config.storage.connection_string = temp_dir.path().to_string_lossy().to_string();

        let logger = AuditLogger::new(&config);
        assert!(logger.is_ok());
    }

    #[tokio::test]
    async fn test_audit_event_logging() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = AuditConfig::default();
        config.storage.connection_string = temp_dir.path().to_string_lossy().to_string();

        let mut logger = AuditLogger::new(&config).unwrap();

        let event = AuditEvent {
            id: Uuid::new_v4(),
            event_type: AuditEventType::LoginSuccess,
            severity: AuditSeverity::Info,
            timestamp: Utc::now(),
            user_id: Some("test_user".to_string()),
            organization_id: None,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: None,
            request_id: None,
            session_id: None,
            resource: None,
            action: "login".to_string(),
            result: AuditResult::Success,
            details: HashMap::new(),
            compliance_tags: Vec::new(),
            integrity_hash: None,
        };

        let result = logger.log_event(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_audit_query() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = AuditConfig::default();
        config.storage.connection_string = temp_dir.path().to_string_lossy().to_string();

        let mut logger = AuditLogger::new(&config).unwrap();

        // Log a test event
        let event = AuditEvent {
            id: Uuid::new_v4(),
            event_type: AuditEventType::DataRead,
            severity: AuditSeverity::Info,
            timestamp: Utc::now(),
            user_id: Some("test_user".to_string()),
            organization_id: None,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: None,
            request_id: None,
            session_id: None,
            resource: Some("test_resource".to_string()),
            action: "read".to_string(),
            result: AuditResult::Success,
            details: HashMap::new(),
            compliance_tags: Vec::new(),
            integrity_hash: None,
        };

        logger.log_event(event).await.unwrap();

        // Query events
        let query = AuditQuery {
            start_time: None,
            end_time: None,
            event_types: Some(vec![AuditEventType::DataRead]),
            user_id: Some("test_user".to_string()),
            organization_id: None,
            ip_address: None,
            min_severity: None,
            resource: None,
            result: None,
            limit: None,
            offset: None,
        };

        let events = logger.query_events(&query).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::DataRead);
    }

    #[test]
    fn test_integrity_verifier() {
        let verifier = IntegrityVerifier::new().unwrap();

        let event = AuditEvent {
            id: Uuid::new_v4(),
            event_type: AuditEventType::LoginSuccess,
            severity: AuditSeverity::Info,
            timestamp: Utc::now(),
            user_id: Some("test_user".to_string()),
            organization_id: None,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: None,
            request_id: None,
            session_id: None,
            resource: None,
            action: "login".to_string(),
            result: AuditResult::Success,
            details: HashMap::new(),
            compliance_tags: Vec::new(),
            integrity_hash: None,
        };

        let hash1 = verifier.calculate_hash(&event).unwrap();
        let hash2 = verifier.calculate_hash(&event).unwrap();

        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
    }
}
