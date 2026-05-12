# Stage 1: Builder
FROM rust:1.75-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /usr/src/total-analyzer

# Копируем только Cargo.toml (без lock)
COPY Cargo.toml ./

# Создаём заглушку main.rs для предварительной загрузки зависимостей
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Копируем реальный исходный код и пересобираем
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /usr/src/total-analyzer/target/release/total-analyzer /usr/local/bin/total-analyzer

ENTRYPOINT ["total-analyzer"]
CMD ["--help"]
