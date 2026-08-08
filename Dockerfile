# Build stage
FROM rust:1.96-alpine3.22 AS builder

# rusqlite's bundled SQLite compiles from C source, so the build stage needs a
# C toolchain. The runtime image is alpine:3.22, which ships musl's shared
# libraries natively — the binary is dynamically linked against musl, not
# static, and needs nothing beyond that to run in the runtime stage below.
RUN apk add --no-cache musl-dev gcc

WORKDIR /app

# Cache dependencies ahead of the source copy.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY src ./src

ARG VERSION
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && \
    cp /app/target/release/sentinel /app/sentinel

# Final stage
FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata curl

ENV PORT=8888

COPY --from=builder /app/sentinel /app/sentinel

RUN mkdir -p /app/db && chmod 750 /app/db

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider "http://127.0.0.1:${PORT}/api/health" || exit 1

CMD ["/app/sentinel"]
