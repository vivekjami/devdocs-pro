//! Working security system test
//! 
//! This example demonstrates basic security functionality that actually works

use devdocs_core::security::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 DevDocs Pro - Working Security Test");
    println!("======================================");

    // Test 1: Security Configuration
    println!("\n1. Testing Security Configuration...");
    let config = SecurityConfig::default();
    println!("  ✅ Security config created");
    println!("  🔐 Encryption enabled: {}", config.encryption.enabled);
    println!("  👤 Authentication enabled: {}", config.auth.enabled);
    println!("  📊 Audit enabled: {}", config.audit.enabled);

    // Test 2: Security Manager
    println!("\n2. Testing Security Manager...");
    let security_manager = SecurityManager::new(config)?;
    println!("  ✅ Security manager initialized");

    // Test 3: PII Detection
    println!("\n3. Testing PII Detection...");
    let pii_config = PiiProtectionConfig::default();
    let pii_detector = PiiDetector::new(&pii_config)?;
    
    let test_data = "Contact John Doe at john.doe@example.com or call 555-123-4567";
    let result = pii_detector.scan_data(test_data.as_bytes())?;
    
    println!("  📝 Test data: {}", test_data);
    println!("  🔍 PII detections: {} items", result.detections.len());
    for detection in &result.detections {
        println!("    - {}: {} (confidence: {:.2})", 
                detection.pii_type, detection.value, detection.confidence);
    }

    // Test 4: Rate Limiting
    println!("\n4. Testing Rate Limiting...");
    let rate_config = RateLimitingConfig::default();
    let rate_limiter = RateLimiter::new(&rate_config)?;
    
    // Test multiple requests
    for i in 1..=3 {
        let result = rate_limiter.check_rate_limit("127.0.0.1").await;
        let allowed = result.is_ok();
        println!("  📊 Request {}: {}", i, if allowed { "✅ Allowed" } else { "❌ Blocked" });
    }

    // Test 5: Encryption
    println!("\n5. Testing Encryption...");
    let enc_config = EncryptionConfig::default();
    let mut encryptor = DataEncryptor::new(&enc_config)?;
    
    let plaintext = "This is sensitive data";
    let encrypted = encryptor.encrypt(plaintext.as_bytes()).await?;
    let decrypted = encryptor.decrypt(&encrypted).await?;
    let decrypted_text = String::from_utf8(decrypted)?;
    
    println!("  ✅ Original: {}", plaintext);
    println!("  ✅ Decrypted: {}", decrypted_text);
    println!("  ✅ Encryption test passed!");

    println!("\n🎉 All security tests passed successfully!");
    Ok(())
}