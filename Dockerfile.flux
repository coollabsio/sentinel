FROM rust:1.97.1-alpine3.24 AS builder

RUN apk add --no-cache musl-dev gcc

WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked -p flux && \
    cp /app/target/release/flux /flux

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=builder /flux /usr/local/bin/flux
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/flux"]
