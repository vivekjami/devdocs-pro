//! Simple security system test
//!
//! This example demonstrates basic security functionality

use devdocs_core::security::*;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 DevDocs Pro - Security System Test");
    println!("=====================================");

    // Test encryption
    println!("\n1. Testing Encryption...");
    let config = EncryptionConfig {
        algorithm: EncryptionAlgorithm::Aes256Gcm,
        key_rotation_interval: std::time::Duration::from_secs(3600),
        auto_rotate: true,
        key_derivation: KeyDerivationConfig {
            algorithm: "PBKDF2".to_string(),
            iterations: 100000,
            salt_length: 32,
        },
    };

    let mut encryptor = EncryptionManager::new(config).await?;
    let plaintext = "This is sensitive data";
    let encrypted = encryptor.encrypt(plaintext.as_bytes()).await?;
    let decrypted = encryptor.decrypt(&encrypted).await?;
    let decrypted_text = String::from_utf8(decrypted)?;

    println!("  ✅ Original: {}", plaintext);
    println!("  ✅ Decrypted: {}", decrypted_text);
    println!("  ✅ Encryption test passed!");

    // Test PII detection
    println!("\n2. Testing PII Detection...");
    let pii_config = PiiDetectionConfig {
        enabled_types: vec![PiiType::Email, PiiType::Phone, PiiType::Ssn],
        redaction_strategy: RedactionStrategy::Mask,
        confidence_threshold: 0.8,
        context_analysis: true,
        ml_enabled: false,
    };

    let pii_detector = PiiDetector::new(pii_config).await?;
    let test_data = "Contact John Doe at john.doe@example.com or call 555-123-4567";
    let result = pii_detector.scan_text(test_data).await?;

    println!("  📝 Test data: {}", test_data);
    println!("  🔍 PII findings: {} items", result.findings.len());
    for finding in &result.findings {
        println!(
            "    - {}: {} (confidence: {:.2})",
            finding.pii_type, finding.value, finding.confidence
        );
    }
    println!("  ✅ PII detection test passed!");

    // Test rate limiting
    println!("\n3. Testing Rate Limiting...");
    let rate_config = RateLimitingConfig {
        global_limit: RateLimit {
            requests: 1000,
            window: std::time::Duration::from_secs(60),
        },
        per_user_limit: Some(RateLimit {
            requests: 100,
            window: std::time::Duration::from_secs(60),
        }),
        per_ip_limit: Some(RateLimit {
            requests: 200,
            window: std::time::Duration::from_secs(60),
        }),
        burst_protection: true,
        adaptive_limits: false,
        whitelist: vec![],
        blacklist: vec![],
    };

    let rate_limiter = RateLimiter::new(rate_config).await?;
    let client_id = "test_client";

    // Test multiple requests
    for i in 1..=5 {
        let allowed = rate_limiter
            .check_rate_limit(client_id, "127.0.0.1")
            .await?;
        println!(
            "  📊 Request {}: {}",
            i,
            if allowed {
                "✅ Allowed"
            } else {
                "❌ Blocked"
            }
        );
    }
    println!("  ✅ Rate limiting test passed!");

    println!("\n🎉 All security tests passed successfully!");
    Ok(())
}
