# ONRouter Gateway - Production Docker Image
FROM rust:1.98-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Build in release mode
RUN cargo build --release --bin onrouter

# Production stage - minimal image
FROM debian:bookworm-slim

LABEL maintainer="yxpil"
LABEL description="ONRouter: High-performance gateway server like Nginx, 100% in Rust"
LABEL version="0.2.0"
LABEL org.opencontainers.image.source="https://github.com/yxpil/ONRouter"
LABEL org.opencontainers.image.description="ONRouter Gateway Server"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r onrouter && useradd -r -g onrouter -d /app -s /sbin/nologin onrouter

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/onrouter /usr/local/bin/onrouter

# Copy branding assets
COPY public/logo.png /app/assets/logo.png

# Create necessary directories
RUN mkdir -p /app/conf /app/logs /app/certs /app/assets && \
    chown -R onrouter:onrouter /app

# Expose ports
EXPOSE 80/tcp 443/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/ || exit 1

# Switch to non-root user
USER onrouter

ENTRYPOINT ["onrouter"]
CMD ["-c", "/app/conf/onrouter.conf"]
