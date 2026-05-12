# Stage 1: Builder
FROM rust:1.75-alpine AS builder

# Install musl for fully static binary
RUN apk add --no-cache musl-dev

WORKDIR /usr/src/total-analyzer

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to fetch dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Copy real source code and rebuild
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM alpine:latest

# Install ca-certificates for HTTPS (if needed for future features)
RUN apk add --no-cache ca-certificates

# Copy binary from builder
COPY --from=builder /usr/src/total-analyzer/target/release/total-analyzer /usr/local/bin/total-analyzer

# Entrypoint
ENTRYPOINT ["total-analyzer"]

# Default command shows help
CMD ["--help"]
