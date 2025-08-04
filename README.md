# DevDocs Pro

**Real-time API documentation generated from actual HTTP traffic**

Generate and maintain API documentation automatically by analyzing live requests. No manual schemas, no outdated specs.

## The Problem

API documentation is always wrong. Teams spend hours every week updating docs manually, but they fall behind immediately after deployment. Current tools require extensive setup and produce documentation with fake examples that don't match real API behavior.

## How DevDocs Pro Works

Install lightweight middleware that intercepts HTTP requests and responses. The system analyzes real traffic patterns to generate accurate documentation automatically.

**One line of code:**

```python
# FastAPI
from devdocs_pro import DevDocsMiddleware
app.add_middleware(DevDocsMiddleware, api_key="your_key")
```

```javascript
// Express
const { devDocsMiddleware } = require('devdocs-pro');
app.use(devDocsMiddleware({ apiKey: 'your_key' }));
```

```python
# Django
MIDDLEWARE = [
    'devdocs_pro.middleware.DevDocsMiddleware',
    # ... other middleware
]
```

Documentation appears at `https://your-api.devdocs.pro`

## Why This Works Better

**Traditional tools**: Require manual schema definition and constant maintenance. Documentation becomes outdated within days.

**DevDocs Pro**: Analyzes actual production traffic. Documentation updates automatically when endpoints change. Examples come from real requests, not mock data.

| Feature | Manual Tools | DevDocs Pro |
|---------|-------------|-------------|
| Setup time | 2-4 hours | 30 seconds |
| Maintenance | 8-12 hours/week | Zero |
| Accuracy | Manual updates, often wrong | 100% from real traffic |
| Examples | Fake data | Real production data |

## Quick Start

1. **Install**
   ```bash
   pip install devdocs-pro    # Python
   npm install devdocs-pro    # Node.js
   ```

2. **Add middleware** (one line of code)

3. **View documentation** at your generated URL

## Architecture

The middleware captures HTTP requests with sub-millisecond overhead. Traffic analysis engine infers API schemas from real usage patterns. Documentation generator creates interactive docs that update in real-time.

## Security

- Automatic PII detection and filtering
- Configurable request sampling
- SOC 2 compliant infrastructure
- On-premise deployment available

## Pricing

- Free: 1,000 requests/month
- Pro: $39/month for 100K requests/month
- Enterprise: Custom pricing

## Framework Support

Works with any HTTP-based API:
- Python: FastAPI, Django, Flask
- Node.js: Express, Koa, NestJS
- Go: Gin, Echo, Chi
- Java: Spring Boot
- Ruby: Rails, Sinatra

## Performance

- Sub-millisecond request overhead
- Real-time documentation updates
- Horizontal scaling support
- 99.9% uptime SLA

## Development

```bash
git clone https://github.com/yourusername/devdocs-pro
cd devdocs-pro
cargo build --release
npm install && npm run dev
```

## License

MIT
