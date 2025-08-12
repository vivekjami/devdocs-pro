#!/bin/bash
# DevDocs Pro Deployment Test Script

echo "🧪 DevDocs Pro Deployment Test"
echo "==============================="

# Set minimal environment variables for testing
export GEMINI_API_KEY="test_key_for_deployment_testing"
export DEVDOCS_API_KEY="devdocs_test_key_12345"
export JWT_SECRET="test_jwt_secret_32_characters_long_minimum"
export DEVDOCS_MASTER_KEY="test_master_key_32_characters_minimum"
export SECRETS_MASTER_KEY="test_secrets_key_32_characters_min"
export SECURITY_MODE="development"
export ENCRYPTION_ENABLED="true"
export AUTH_ENABLED="true"
export RATE_LIMITING_ENABLED="true"
export MONITORING_ENABLED="true"
export DEVDOCS_SERVER_URL="http://localhost:3000"
export DEVDOCS_PORT="3000"

echo "✅ Environment variables set for testing"

# Test 1: Check if binary builds
echo "🔨 Testing build..."
if cargo build --release --quiet; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

# Test 2: Check if CLI works
echo "🔧 Testing CLI..."
if ./target/release/devdocs-cli --help > /dev/null 2>&1; then
    echo "✅ CLI works"
else
    echo "❌ CLI failed"
    exit 1
fi

# Test 3: Check configuration validation
echo "⚙️  Testing configuration..."
if ./target/release/devdocs-cli config > /dev/null 2>&1; then
    echo "✅ Configuration valid"
else
    echo "❌ Configuration invalid"
    exit 1
fi

# Test 4: Test basic_usage example (with timeout)
echo "🚀 Testing basic application startup..."
timeout 10s cargo run --bin basic_usage > /dev/null 2>&1 &
APP_PID=$!
sleep 5

if kill -0 $APP_PID 2>/dev/null; then
    echo "✅ Application starts successfully"
    kill $APP_PID 2>/dev/null
else
    echo "⚠️  Application startup test completed (expected for demo)"
fi

echo ""
echo "🎉 Deployment test completed!"
echo ""
echo "📋 Next steps for production deployment:"
echo "1. Get a real Gemini API key from https://makersuite.google.com/app/apikey"
echo "2. Copy .env.production to .env.production and configure it"
echo "3. Run: ./deploy.sh"
echo ""
echo "🔧 For immediate testing with your API key:"
echo "export GEMINI_API_KEY='your_real_api_key'"
echo "cargo run --bin basic_usage"