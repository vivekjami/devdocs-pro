//! Comprehensive security system example
//! 
//! This example demonstrates how to use all the security features
//! of DevDocs Pro in a production environment.

use devdocs_core::security::*;
use devdocs_core::security::monitoring::*;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🔒 DevDocs Pro - Enterprise Security System Demo");
    println!("================================================");

    // 1. Load comprehensive security configuration
    println!("\n1. Loading Security Configuration...");
    let security_config = load_security_configuration().await?;
    println!("✅ Security configuration loaded successfully");

    // 2. Initialize security manager
    println!("\n2. Initializing Security Manager...");
    let mut security_manager = SecurityManager::new(security_config.get_security_config())?;
    println!("✅ Security manager initialized");

    // 3. Demonstrate authentication and authorization
    println!("\n3. Testing Authentication & Authorization...");
    demo_authentication(&mut security_manager).await?;

    // 4. Demonstrate data protection and PII detection
    println!("\n4. Testing Data Protection & PII Detection...");
    demo_data_protection(&mut security_manager).await?;

    // 5. Demonstrate encryption and key management
    println!("\n5. Testing Encryption & Key Management...");
    demo_encryption().await?;

    // 6. Demonstrate audit logging
    println!("\n6. Testing Audit Logging...");
    demo_audit_logging().await?;

    // 7. Demonstrate rate limiting and DDoS protection
    println!("\n7. Testing Rate Limiting & DDoS Protection...");
    demo_rate_limiting().await?;

    // 8. Demonstrate compliance checking
    println!("\n8. Testing Compliance Checking...");
    demo_compliance_checking().await?;

    // 9. Demonstrate security monitoring
    println!("\n9. Testing Security Monitoring...");
    demo_security_monitoring().await?;

    // 10. Demonstrate secrets management
    println!("\n10. Testing Secrets Management...");
    demo_secrets_management().await?;

    println!("\n🎉 All security features demonstrated successfully!");
    println!("Your API documentation system is now enterprise-ready with:");
    println!("  ✅ End-to-end encryption");
    println!("  ✅ Advanced PII detection and redaction");
    println!("  ✅ Multi-factor authentication");
    println!("  ✅ Comprehensive audit logging");
    println!("  ✅ Real-time threat detection");
    println!("  ✅ GDPR, HIPAA, SOC 2 compliance");
    println!("  ✅ Advanced rate limiting and DDoS protection");
    println!("  ✅ Secure secrets management");
    println!("  ✅ Data protection and privacy controls");

    Ok(())
}

async fn load_security_configuration() -> Result<SecurityConfigManager, Box<dyn std::error::Error>> {
    // Try to load from file first, fallback to environment variables
    let config_manager = if std::path::Path::new("security_config.yaml").exists() {
        println!("  📄 Loading from security_config.yaml");
        SecurityConfigManager::load_from_file("security_config.yaml")?
    } else {
        println!("  🌍 Loading from environment variables");
        SecurityConfigManager::load_from_env()?
    };

    // Display current security mode
    let config = config_manager.get_config();
    println!("  🔧 Security Mode: {:?}", config.global.security_mode);
    println!("  🔐 Encryption: {}", if config.encryption.enabled { "Enabled" } else { "Disabled" });
    println!("  👤 Authentication: {}", if config.authentication.enabled { "Enabled" } else { "Disabled" });
    println!("  📊 Monitoring: {}", if config.monitoring.enabled { "Enabled" } else { "Disabled" });

    Ok(config_manager)
}

async fn demo_authentication(security_manager: &mut SecurityManager) -> Result<(), Box<dyn std::error::Error>> {
    println!("  🔑 Creating test user...");
    
    // Create a security context for testing
    let context = SecurityContext::new(Uuid::new_v4(), "192.168.1.100".to_string())
        .with_user("demo_user".to_string(), Some("demo_org".to_string()))
        .with_permissions(vec!["read".to_string(), "write".to_string()])
        .with_security_level(SecurityLevel::Confidential);

    println!("  ✅ User context created: {}", context.user_id.as_ref().unwrap());
    println!("  🏢 Organization: {}", context.organization_id.as_ref().unwrap());
    println!("  🔒 Security Level: {:?}", context.security_level);
    println!("  📋 Permissions: {:?}", context.permissions);

    // Test authentication with a mock token
    let mock_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_payload.signature";
    match security_manager.authenticate_request(mock_token, &["read".to_string()]).await {
        Ok(auth_context) => {
            println!("  ✅ Authentication successful");
            println!("  👤 User ID: {}", auth_context.user_id.as_ref().unwrap_or(&"unknown".to_string()));
        }
        Err(e) => {
            println!("  ⚠️  Authentication failed (expected in demo): {}", e);
        }
    }

    Ok(())
}

async fn demo_data_protection(security_manager: &mut SecurityManager) -> Result<(), Box<dyn std::error::Error>> {
    // Test data with PII
    let test_data = r#"{
        "user": {
            "name": "John Doe",
            "email": "john.doe@example.com",
            "phone": "555-123-4567",
            "ssn": "123-45-6789",
            "address": "123 Main St, Anytown, USA"
        },
        "api_key": "sk_test_1234567890abcdef",
        "credit_card": "4111-1111-1111-1111"
    }"#;

    println!("  📊 Analyzing test data for PII...");
    println!("  📝 Original data size: {} bytes", test_data.len());

    let context = SecurityContext::new(Uuid::new_v4(), "192.168.1.100".to_string())
        .with_security_level(SecurityLevel::Confidential);

    // Validate security requirements
    let validation_result = security_manager.validate_security(test_data.as_bytes(), &context).await?;
    
    println!("  🔍 Security validation results:");
    println!("    - Valid: {}", validation_result.is_valid);
    println!("    - Risk Score: {:.2}", validation_result.risk_score);
    println!("    - Violations: {}", validation_result.violations.len());
    
    for violation in &validation_result.violations {
        println!("    - ⚠️  {}: {}", 
            format!("{:?}", violation.violation_type), 
            violation.description
        );
    }

    // Apply data protection
    let protected_data = security_manager.secure_data(test_data.as_bytes(), &context).await?;
    println!("  🛡️  Data protection applied");
    println!("    - Protected size: {} bytes", protected_data.len());
    println!("    - Reduction: {:.1}%", 
        (1.0 - protected_data.len() as f64 / test_data.len() as f64) * 100.0
    );

    Ok(())
}

async fn demo_encryption() -> Result<(), Box<dyn std::error::Error>> {
    println!("  🔐 Initializing encryption system...");
    
    let encryption_config = EncryptionConfig::default();
    let mut encryptor = DataEncryptor::new(&encryption_config)?;

    // Test data encryption
    let sensitive_data = "This is highly sensitive information that must be encrypted";
    println!("  📝 Original data: {}", sensitive_data);

    let encrypted_data = encryptor.encrypt(sensitive_data.as_bytes(), "demo_context")?;
    println!("  🔒 Data encrypted successfully");
    println!("  📊 Encrypted size: {} bytes", encrypted_data.len());

    // Test decryption
    let decrypted_data = encryptor.decrypt(&encrypted_data)?;
    let decrypted_string = String::from_utf8(decrypted_data)?;
    println!("  🔓 Data decrypted: {}", decrypted_string);

    // Test key rotation
    if encryptor.should_rotate_key() {
        encryptor.rotate_key()?;
        println!("  🔄 Encryption key rotated");
    }

    let metadata = encryptor.get_encryption_metadata();
    println!("  📋 Encryption metadata:");
    println!("    - Algorithm: {:?}", metadata.algorithm);
    println!("    - Current Key ID: {}", metadata.current_key_id);
    println!("    - Key Count: {}", metadata.key_count);

    Ok(())
}

async fn demo_audit_logging() -> Result<(), Box<dyn std::error::Error>> {
    println!("  📝 Initializing audit logging system...");
    
    let audit_config = AuditConfig::default();
    let mut auditor = AuditLogger::new(&audit_config)?;

    let context = SecurityContext::new(Uuid::new_v4(), "192.168.1.100".to_string())
        .with_user("demo_user".to_string(), Some("demo_org".to_string()));

    // Log various types of events
    println!("  📊 Logging audit events...");

    // Authentication event
    let mut auth_details = HashMap::new();
    auth_details.insert("method".to_string(), serde_json::Value::String("jwt".to_string()));
    auth_details.insert("user_agent".to_string(), serde_json::Value::String("DevDocs-Demo/1.0".to_string()));

    auditor.log_authentication("demo_user", "192.168.1.100", true, auth_details).await?;
    println!("  ✅ Authentication event logged");

    // Data access event
    auditor.log_data_access(&context, 1024).await?;
    println!("  ✅ Data access event logged");

    // Security violation event
    auditor.log_security_violation(&context, "rate_limit_exceeded", "User exceeded rate limit").await?;
    println!("  ✅ Security violation event logged");

    // Query audit events
    let query = AuditQuery {
        start_time: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        end_time: Some(chrono::Utc::now()),
        user_id: Some("demo_user".to_string()),
        event_types: None,
        organization_id: None,
        ip_address: None,
        min_severity: None,
        resource: None,
        result: None,
        limit: None,
        offset: None,
    };

    let events = auditor.query_events(&query).await?;
    println!("  📊 Retrieved {} audit events", events.len());

    // Get audit statistics
    let stats = auditor.get_statistics(&query).await?;
    println!("  📈 Audit statistics:");
    println!("    - Total events: {}", stats.total_events);
    println!("    - Unique users: {}", stats.unique_users);
    println!("    - Security incidents: {}", stats.security_incidents);

    Ok(())
}

async fn demo_rate_limiting() -> Result<(), Box<dyn std::error::Error>> {
    println!("  🚦 Initializing rate limiting system...");
    
    let rate_config = RateLimitingConfig::default();
    let rate_limiter = RateLimiter::new(&rate_config)?;

    // Test IP-based rate limiting
    println!("  🌐 Testing IP-based rate limiting...");
    
    let test_ip = "192.168.1.200";
    for i in 1..=5 {
        match rate_limiter.check_rate_limit(test_ip).await {
            Ok(()) => println!("  ✅ Request {} from {} allowed", i, test_ip),
            Err(e) => println!("  ❌ Request {} from {} blocked: {}", i, test_ip, e),
        }
    }

    // Test user-based rate limiting
    println!("  👤 Testing user-based rate limiting...");
    
    let test_user = "demo_user_123";
    for i in 1..=3 {
        match rate_limiter.check_user_rate_limit(test_user).await {
            Ok(()) => println!("  ✅ Request {} from user {} allowed", i, test_user),
            Err(e) => println!("  ❌ Request {} from user {} blocked: {}", i, test_user, e),
        }
    }

    // Get rate limiting statistics
    let stats = rate_limiter.get_statistics().await;
    println!("  📊 Rate limiting statistics:");
    println!("    - Blocked IPs: {}", stats.blocked_ips_count);
    println!("    - Active IP limiters: {}", stats.active_ip_limiters);
    println!("    - Active user limiters: {}", stats.active_user_limiters);

    Ok(())
}

async fn demo_compliance_checking() -> Result<(), Box<dyn std::error::Error>> {
    println!("  ⚖️  Initializing compliance checking system...");
    
    let compliance_config = ComplianceConfig::default();
    let compliance_checker = ComplianceChecker::new(&compliance_config)?;

    let context = SecurityContext::new(Uuid::new_v4(), "192.168.1.100".to_string())
        .with_security_level(SecurityLevel::Confidential);

    // Test data with potential compliance issues
    let test_data = r#"{
        "personal_data": {
            "email": "user@example.com",
            "medical_record": "Patient has diabetes",
            "payment_info": "4111-1111-1111-1111"
        }
    }"#;

    println!("  🔍 Checking compliance for test data...");
    let compliance_result = compliance_checker.check_compliance(test_data.as_bytes(), &context).await?;

    println!("  📊 Compliance check results:");
    println!("    - Compliance Score: {:.2}", compliance_result.compliance_score);
    println!("    - Violations: {}", compliance_result.violations.len());
    println!("    - Recommendations: {}", compliance_result.recommendations.len());

    for (standard, status) in &compliance_result.standards_status {
        println!("    - {}: {:?}", standard, status);
    }

    for recommendation in &compliance_result.recommendations {
        println!("    - 💡 {}: {}", recommendation.standard, recommendation.description);
    }

    // Generate compliance report
    println!("  📋 Generating compliance report...");
    let report = compliance_checker.generate_compliance_report().await?;
    println!("  ✅ Compliance report generated");
    println!("    - Overall Score: {:.2}", report.overall_score);
    println!("    - Standards Covered: {}", report.standards.len());

    Ok(())
}

async fn demo_security_monitoring() -> Result<(), Box<dyn std::error::Error>> {
    println!("  👁️  Initializing security monitoring system...");
    
    let monitoring_config = SecurityMonitoringConfig::default();
    let mut monitor = SecurityMonitor::new(&monitoring_config)?;

    // Create test security events
    println!("  📊 Processing security events...");

    let context = SecurityContext::new(Uuid::new_v4(), "192.168.1.100".to_string())
        .with_user("demo_user".to_string(), Some("demo_org".to_string()));

    // Authentication failure event
    let auth_event = SecurityEvent {
        id: Uuid::new_v4().to_string(),
        event_type: SecurityEventType::AuthenticationFailure,
        severity: Severity::Medium,
        timestamp: chrono::Utc::now(),
        source: SecurityEventSource {
            component: "auth_service".to_string(),
            instance: "auth-1".to_string(),
            version: "1.0.0".to_string(),
        },
        context: context.clone(),
        details: HashMap::new(),
        threat_indicators: Vec::new(),
        response_actions: Vec::new(),
    };

    monitor.process_event(auth_event).await?;
    println!("  ✅ Authentication failure event processed");

    // Data access event
    let data_event = SecurityEvent {
        id: Uuid::new_v4().to_string(),
        event_type: SecurityEventType::DataAccess,
        severity: Severity::Low,
        timestamp: chrono::Utc::now(),
        source: SecurityEventSource {
            component: "api_service".to_string(),
            instance: "api-1".to_string(),
            version: "1.0.0".to_string(),
        },
        context,
        details: HashMap::new(),
        threat_indicators: Vec::new(),
        response_actions: Vec::new(),
    };

    monitor.process_event(data_event).await?;
    println!("  ✅ Data access event processed");

    // Get security dashboard
    let dashboard = monitor.get_dashboard_data().await?;
    println!("  📊 Security dashboard:");
    println!("    - Threat Level: {:?}", dashboard.threat_level);
    println!("    - Recent Events: {}", dashboard.recent_events);
    println!("    - Active Threats: {}", dashboard.active_threats);
    println!("    - System Health: {:?}", dashboard.system_health);

    Ok(())
}

async fn demo_secrets_management() -> Result<(), Box<dyn std::error::Error>> {
    println!("  🔐 Initializing secrets management system...");
    
    let secrets_config = SecretsConfig::default();
    let mut secrets_manager = SecretsManager::new(&secrets_config)?;

    // Store various types of secrets
    println!("  💾 Storing secrets...");

    let api_key_id = secrets_manager.store_secret(
        "demo_api_key".to_string(),
        "sk_demo_1234567890abcdef".to_string(),
        SecretType::ApiKey,
    ).await?;
    println!("  ✅ API key stored with ID: {}", api_key_id);

    let db_password_id = secrets_manager.store_secret(
        "demo_db_password".to_string(),
        "super_secure_password_123!".to_string(),
        SecretType::DatabasePassword,
    ).await?;
    println!("  ✅ Database password stored with ID: {}", db_password_id);

    // Retrieve secrets
    println!("  🔍 Retrieving secrets...");

    if let Some(api_key) = secrets_manager.get_secret(&api_key_id, "demo_user").await? {
        println!("  ✅ Retrieved API key: {}***", &api_key[..8]);
    }

    // List all secrets (metadata only)
    let secrets_list = secrets_manager.list_secrets("demo_user").await?;
    println!("  📋 Secrets inventory:");
    for secret in &secrets_list {
        println!("    - {}: {:?} (created: {})", 
            secret.name, 
            secret.secret_type,
            secret.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    // Rotate a secret
    println!("  🔄 Rotating API key...");
    let new_api_key = secrets_manager.rotate_secret(&api_key_id, "demo_user").await?;
    println!("  ✅ API key rotated: {}***", &new_api_key[..8]);

    // Check for secrets needing rotation
    let rotation_due = secrets_manager.check_rotation_due().await?;
    println!("  📅 Secrets due for rotation: {}", rotation_due.len());

    // Get access logs
    let access_logs = secrets_manager.get_access_logs(Some(&api_key_id)).await;
    println!("  📊 Access logs for API key: {} entries", access_logs.len());

    Ok(())
}

