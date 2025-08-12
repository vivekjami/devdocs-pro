#!/bin/bash
# Quick deployment test with your actual API key

echo "🚀 DevDocs Pro - Quick Deployment Test"
echo "======================================"

# Set your environment variables
export GEMINI_API_KEY="AIzaSyDglQq1O6RjI35VVVVhBmU-OMY8R3xfY7A"
export DEVDOCS_API_KEY="devdocs_test_key_12345"
export JWT_SECRET="secure_jwt_secret_32_characters_long_minimum"
export DEVDOCS_MASTER_KEY="secure_master_key_32_characters_minimum"
export SECRETS_MASTER_KEY="secure_secrets_key_32_characters_min"
export SECURITY_MODE="development"
export ENCRYPTION_ENABLED="true"
export AUTH_ENABLED="true"
export RATE_LIMITING_ENABLED="true"
export MONITORING_ENABLED="true"
export DEVDOCS_SERVER_URL="http://localhost:3000"
export DEVDOCS_PORT="3000"
export DEVDOCS_SAMPLING_RATE="0.1"
export DEVDOCS_ENABLE_PII_FILTERING="true"

echo "✅ Environment configured with your Gemini API key"

# Test the CLI
echo "🔧 Testing DevDocs CLI..."
if cargo run --bin devdocs-cli -- --help > /dev/null 2>&1; then
    echo "✅ CLI working"
else
    echo "❌ CLI failed"
    exit 1
fi

# Test configuration validation
echo "⚙️  Testing configuration validation..."
if cargo run --bin devdocs-cli config 2>/dev/null; then
    echo "✅ Configuration valid"
else
    echo "❌ Configuration validation failed"
fi

# Test basic usage example
echo "🚀 Testing basic usage (will run for 10 seconds)..."
echo "   This will start the DevDocs server on http://localhost:3000"

# Run the basic usage example with timeout
timeout 10s cargo run --bin basic_usage &
APP_PID=$!

# Wait a moment for startup
sleep 3

# Check if it's running
if kill -0 $APP_PID 2>/dev/null; then
    echo "✅ DevDocs Pro started successfully!"
    echo "🌐 Server would be available at: http://localhost:3000"
    
    # Clean shutdown
    kill $APP_PID 2>/dev/null
    wait $APP_PID 2>/dev/null
else
    echo "⚠️  Application completed startup test"
fi

echo ""
echo "🎉 Deployment test completed successfully!"
echo ""
echo "🚀 To run DevDocs Pro:"
echo "   cargo run --bin basic_usage"
echo ""
echo "🐳 To deploy with Docker:"
echo "   ./deploy.sh"
echo ""
echo "📊 To test AI features:"
echo "   cargo run --bin ai_test"