#!/bin/bash
# DevDocs Pro Deployment Script

set -e

echo "🚀 DevDocs Pro Deployment Script"
echo "================================="

# Check if .env.production exists
if [ ! -f ".env.production" ]; then
    echo "❌ Error: .env.production file not found!"
    echo "Please copy .env.production.example to .env.production and configure it."
    exit 1
fi

# Load environment variables
export $(cat .env.production | grep -v '^#' | xargs)

# Validate required environment variables
required_vars=(
    "GEMINI_API_KEY"
    "DEVDOCS_API_KEY"
    "JWT_SECRET"
    "DEVDOCS_MASTER_KEY"
    "SECRETS_MASTER_KEY"
)

echo "🔍 Validating environment variables..."
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Error: $var is not set in .env.production"
        exit 1
    fi
    echo "✅ $var is set"
done

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Error: Docker Compose is not installed"
    exit 1
fi

echo "🔨 Building DevDocs Pro..."
docker-compose --env-file .env.production build

echo "🚀 Starting DevDocs Pro..."
docker-compose --env-file .env.production up -d

echo "⏳ Waiting for services to start..."
sleep 10

# Health check
echo "🏥 Performing health check..."
if curl -f http://localhost:3000/health &> /dev/null; then
    echo "✅ DevDocs Pro is running successfully!"
    echo "🌐 Access your DevDocs Pro at: http://localhost:3000"
else
    echo "⚠️  Health check failed, checking logs..."
    docker-compose --env-file .env.production logs devdocs-pro
fi

echo ""
echo "📋 Useful commands:"
echo "  View logs:    docker-compose --env-file .env.production logs -f"
echo "  Stop:         docker-compose --env-file .env.production down"
echo "  Restart:      docker-compose --env-file .env.production restart"
echo "  Status:       docker-compose --env-file .env.production ps"