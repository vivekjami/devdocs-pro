# 🚀 DevDocs Pro Deployment Guide

## Quick Fix for Current Deployment Errors

The deployment errors you're seeing are due to missing environment variables. Here's how to fix them:

### 1. **Immediate Fix - Set Required Environment Variables**

```bash
# Set minimum required environment variables
export GEMINI_API_KEY="your_gemini_api_key_here"
export DEVDOCS_API_KEY="devdocs_dev_key_12345"
export JWT_SECRET="your_jwt_secret_at_least_32_characters_long"
export DEVDOCS_MASTER_KEY="your_master_key_32_chars_minimum_here"
export SECRETS_MASTER_KEY="your_secrets_key_32_chars_minimum_here"
export SECURITY_MODE="development"
export ENCRYPTION_ENABLED="true"
export AUTH_ENABLED="true"
export RATE_LIMITING_ENABLED="true"
export MONITORING_ENABLED="true"

# Now try running your application
cargo run --bin basic_usage
```

### 2. **Production Deployment Options**

#### Option A: Docker Deployment (Recommended)

```bash
# 1. Configure environment
cp .env.production.example .env.production
# Edit .env.production with your actual values

# 2. Deploy with Docker
./deploy.sh
```

#### Option B: Direct Binary Deployment

```bash
# 1. Build release binary
cargo build --release

# 2. Set environment variables
source .env.production

# 3. Run the binary
./target/release/devdocs-cli start
```

#### Option C: Development Mode

```bash
# 1. Copy example environment
cp .env.example .env
# Edit .env with your values

# 2. Run in development mode
cargo run --bin devdocs-cli start
```

## Environment Variables Reference

### Required Variables
- `GEMINI_API_KEY`: Get from https://makersuite.google.com/app/apikey
- `DEVDOCS_API_KEY`: Your API authentication key
- `JWT_SECRET`: JWT signing secret (32+ characters)
- `DEVDOCS_MASTER_KEY`: Master encryption key (32+ characters)
- `SECRETS_MASTER_KEY`: Secrets encryption key (32+ characters)

### Security Variables
- `SECURITY_MODE`: "development" or "production"
- `ENCRYPTION_ENABLED`: "true" or "false"
- `AUTH_ENABLED`: "true" or "false"
- `RATE_LIMITING_ENABLED`: "true" or "false"
- `MONITORING_ENABLED`: "true" or "false"

### Service Configuration
- `DEVDOCS_SERVER_URL`: Your server URL
- `DEVDOCS_PORT`: Port to run on (default: 3000)
- `DEVDOCS_SAMPLING_RATE`: Traffic sampling rate (0.0-1.0)

## Troubleshooting Common Deployment Issues

### Issue 1: "GEMINI_API_KEY environment variable is required"
**Solution**: Set the GEMINI_API_KEY environment variable
```bash
export GEMINI_API_KEY="your_actual_api_key"
```

### Issue 2: "Configuration error"
**Solution**: Check all required environment variables are set
```bash
# Use the deployment script which validates all variables
./deploy.sh
```

### Issue 3: "Permission denied"
**Solution**: Make sure the deploy script is executable
```bash
chmod +x deploy.sh
```

### Issue 4: Docker build fails
**Solution**: Ensure Docker is installed and running
```bash
docker --version
docker-compose --version
```

## Production Checklist

- [ ] Set all required environment variables
- [ ] Configure security keys (change defaults!)
- [ ] Set up SSL/TLS certificates
- [ ] Configure firewall rules
- [ ] Set up monitoring and logging
- [ ] Configure backup strategy
- [ ] Test health endpoints
- [ ] Validate security configuration

## Quick Test

After deployment, test your installation:

```bash
# Health check
curl http://localhost:3000/health

# API test
curl -H "Authorization: Bearer your_api_key" http://localhost:3000/api/status
```

## Support

If you're still experiencing deployment issues:

1. Check the logs: `docker-compose logs -f devdocs-pro`
2. Verify environment variables: `env | grep DEVDOCS`
3. Test the binary directly: `./target/release/devdocs-cli --help`
4. Validate configuration: `cargo run --bin devdocs-cli config`