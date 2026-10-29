# ==============================================================================
# Sentris Multi-Arch Production Container Image
# Multi-stage minimal Alpine build (<15MB runtime footprint, non-root user)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Rust Builder
# ------------------------------------------------------------------------------
FROM rust:alpine3.20 AS builder

RUN apk add --no-cache musl-dev git

WORKDIR /usr/src/sentris

# Cache dependency compilation layers
COPY Cargo.toml Cargo.lock ./
# Create dummy src/main.rs to build dependencies
RUN mkdir -p src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs && \
    echo 'pub fn dummy() {}' > src/lib.rs && \
    cargo build --release && \
    rm -rf src target/release/deps/sentris*

# Copy complete source code
COPY src ./src
COPY tests ./tests

# Build optimized and stripped release binary
RUN cargo build --release && \
    strip target/release/sentris

# ------------------------------------------------------------------------------
# Stage 2: Hardened Runtime Container
# ------------------------------------------------------------------------------
FROM alpine:3.20

# Install minimal TLS certificates and git for repository inspection
RUN apk --no-cache add ca-certificates git && \
    rm -rf /var/cache/apk/*

# Create dedicated unprivileged non-root system user and group (UID/GID 10001)
RUN addgroup -g 10001 -S sentris && \
    adduser -u 10001 -S -G sentris -h /home/sentris sentris

# Copy compiled binary from builder stage
COPY --from=builder /usr/src/sentris/target/release/sentris /usr/local/bin/sentris
RUN chmod +x /usr/local/bin/sentris

# OpenContainer Image (OCI) Metadata specifications
LABEL org.opencontainers.image.title="Sentris" \
      org.opencontainers.image.description="High-performance, memory-safe, zero-knowledge secret scanner with autonomous remediation" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.url="https://github.com/Bharath-code/sentris" \
      org.opencontainers.image.source="https://github.com/Bharath-code/sentris" \
      org.opencontainers.image.vendor="Sentris Security"

# Run as non-root user
USER 10001:10001

# Default workdir where repository volume mounts
WORKDIR /workspace

# CLI Entrypoint and default command
ENTRYPOINT ["/usr/local/bin/sentris"]
CMD ["scan", "."]
