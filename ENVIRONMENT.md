# Environment Setup for DevDocs Pro

## Quick Start

1. **Copy the example environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Get your Gemini API key:**
   - Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Create a free API key
   - Replace `AIzaSy...` in `.env` with your actual key

3. **Start the development server:**
   ```bash
   cargo run --bin devdocs-server
   ```

## Environment Variables Reference

### Required Variables
- `GEMINI_API_KEY`: Your Google Gemini API key (required for AI features)
- `DEVDOCS_API_KEY`: API key for DevDocs Pro access

### Core Configuration
- `DEVDOCS_SAMPLING_RATE`: Fraction of traffic to process (0.0-1.0)
- `DEVDOCS_PORT`: Server port (default: 3000)
- `DEVDOCS_MAX_BODY_SIZE`: Maximum request/response body size in bytes

### AI Processing
- `DEVDOCS_AI_BATCH_SIZE`: Number of endpoints to process together
- `DEVDOCS_AI_BATCH_TIMEOUT`: Timeout for batch processing (seconds)
- `DEVDOCS_AI_TEMPERATURE`: AI response creativity (0.0-1.0)

### Security & Privacy
- `DEVDOCS_ENABLE_PII_FILTERING`: Enable automatic PII detection/removal
- `DEVDOCS_EXCLUDED_PATHS`: Comma-separated paths to exclude from capture

## Development vs Production

The `.env` file includes development-friendly settings:
- High sampling rate (100%) for complete traffic capture
- Verbose logging for debugging
- Shorter retention periods
- Smaller batch sizes for faster feedback

For production, adjust these values based on your traffic volume and cost requirements.
