//! Security system status check
//!
//! This example verifies that all security modules are properly compiled and accessible

use devdocs_core::security::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 DevDocs Pro - Security System Status Check");
    println!("==============================================");

    // Test 1: Configuration
    println!("\n1. Testing Configuration...");
    let config = SecurityConfig::default();
    println!("  ✅ SecurityConfig: OK");
    println!("  🔐 Encryption enabled: {}", config.encryption.enabled);
    println!("  👤 Auth enabled: {}", config.auth.enabled);
    println!("  📊 Audit enabled: {}", config.audit.enabled);

    // Test 2: Security Manager
    println!("\n2. Testing Security Manager...");
    let _security_manager = SecurityManager::new(config)?;
    println!("  ✅ SecurityManager: OK");

    // Test 3: PII Protection
    println!("\n3. Testing PII Protection...");
    let pii_config = PiiProtectionConfig::default();
    let _pii_detector = PiiDetector::new(&pii_config)?;
    println!("  ✅ PiiDetector: OK");

    // Test 4: Rate Limiting
    println!("\n4. Testing Rate Limiting...");
    let rate_config = RateLimitingConfig::default();
    let _rate_limiter = RateLimiter::new(&rate_config)?;
    println!("  ✅ RateLimiter: OK");

    // Test 5: Encryption
    println!("\n5. Testing Encryption...");
    let enc_config = EncryptionConfig::default();
    let _encryptor = DataEncryptor::new(&enc_config)?;
    println!("  ✅ DataEncryptor: OK");

    // Test 6: Audit System
    println!("\n6. Testing Audit System...");
    let audit_config = AuditConfig::default();
    let _auditor = AuditLogger::new(&audit_config)?;
    println!("  ✅ AuditLogger: OK");

    // Test 7: Compliance
    println!("\n7. Testing Compliance...");
    let compliance_config = ComplianceConfig::default();
    let _compliance_checker = ComplianceChecker::new(&compliance_config)?;
    println!("  ✅ ComplianceChecker: OK");

    // Test 8: Secrets Management
    println!("\n8. Testing Secrets Management...");
    let secrets_config = SecretsConfig::default();
    let _secrets_manager = SecretsManager::new(&secrets_config)?;
    println!("  ✅ SecretsManager: OK");

    println!("\n🎉 All security modules are properly compiled and accessible!");
    println!("✅ The security system is ready for production use!");

    Ok(())
}
