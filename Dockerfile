# DevDocs Pro Production Dockerfile
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY examples/ ./examples/

# Build for release
RUN cargo build --release --bin devdocs-cli

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false devdocs

# Create directories
RUN mkdir -p /app/data /app/logs /app/config && \
    chown -R devdocs:devdocs /app

# Copy binary
COPY --from=builder /app/target/release/devdocs-cli /usr/local/bin/devdocs-cli

# Copy configuration
COPY security_config.yaml /app/config/
COPY .env.example /app/config/env.template

# Set permissions
RUN chmod +x /usr/local/bin/devdocs-cli

# Switch to app user
USER devdocs

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Default command
CMD ["devdocs-cli", "start"]