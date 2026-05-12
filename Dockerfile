# =============================================================================
# TOTAL Analyzer Dockerfile (v2.0)
# Multi-stage build with dependency caching
# =============================================================================

# Stage 1: Builder
FROM rust:1.75-alpine AS builder

# Install musl for fully static binary
RUN apk add --no-cache musl-dev

WORKDIR /build

# 1. Copy dependency manifests first (for caching)
COPY Cargo.toml Cargo.lock* ./

# 2. Create dummy source to pre-fetch dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# 3. Remove dummy source & copy real source
RUN rm -rf src
COPY src ./src

# 4. Rebuild with real source (only changed files)
RUN cargo build --release --frozen

# Stage 2: Runtime (distroless-like, but Alpine for small size)
FROM alpine:latest

# Install CA certificates for HTTPS (if needed for future features)
RUN apk add --no-cache ca-certificates

# Copy binary from builder stage
COPY --from=builder /build/target/release/total-analyzer /usr/local/bin/total-analyzer

# Ensure binary is executable
RUN chmod +x /usr/local/bin/total-analyzer

# Entrypoint
ENTRYPOINT ["total-analyzer"]

# Default help
CMD ["--help"]
