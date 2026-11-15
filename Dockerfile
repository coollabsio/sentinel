# One Dockerfile builds every Rust image, with a single compile per arch:
#   default (last stage)  -> coollabsio/sentinel       (alpine + sentinel)
#   --target host         -> coollabsio/sentinel-host  (scratch + sentinel)
#   --target flux         -> coollabsio/flux           (alpine + flux)
#
# cargo-chef puts the dependency compile in its own layer, keyed only on the
# Cargo manifests and lockfile. With a registry cache (`cache-from: type=gha`)
# a source-only change recompiles the workspace crates and nothing else.

FROM rust:1.97.1-alpine3.24 AS chef
# rusqlite's bundled SQLite and ring compile from C source, so the build needs
# a C toolchain. `file` checks that the binaries are static.
RUN apk upgrade --no-cache && apk add --no-cache musl-dev gcc file
RUN cargo install --locked cargo-chef --version 0.1.78
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# Static binaries: the same sentinel binary ships in the alpine image and in
# the scratch host image. The explicit `--target` keeps RUSTFLAGS away from
# build scripts and proc-macros, which must stay dynamic on a musl host.
ENV RUSTFLAGS="-C target-feature=+crt-static"
# `--features sentinel/traffic`: the workspace default is `default = []`, so
# without it the shipped binary has no traffic routes and no traffic service,
# and `TRAFFIC_ENABLED=true` silently 404s every endpoint. The runtime gate is
# `TRAFFIC_ENABLED` (default false), like every other optional subsystem.
# Only sentinel and flux are built: the workspace also contains
# `sentinel-bench` (a host-side harness from BENCHMARK.md), which never ships.
ENV CARGO_ARGS="--release --locked -p sentinel -p flux --features sentinel/traffic"
COPY rust-toolchain.toml ./
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook $CARGO_ARGS --target "$(rustc -vV | sed -n 's/^host: //p')" --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
ARG VERSION
# Visible to option_env!("SENTINEL_BUILD_VERSION") at compile time, so a dev
# build tagged via `--build-arg VERSION=...` (see scripts/coolify-dev.sh)
# shows up in logs and /api/version. Declared after the cook step, so a new
# VERSION does not rebuild the dependencies.
ENV SENTINEL_BUILD_VERSION=$VERSION
RUN target="$(rustc -vV | sed -n 's/^host: //p')" && \
    cargo build $CARGO_ARGS --target "$target" && \
    cp "target/$target/release/sentinel" "target/$target/release/flux" / && \
    file /sentinel | grep -Eq 'static.*linked' && \
    file /flux | grep -Eq 'static.*linked'

FROM scratch AS host
COPY --from=builder /sentinel /sentinel

FROM alpine:3.24 AS flux
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=builder /flux /usr/local/bin/flux
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/flux"]

# Default target: keep it last, so a plain `docker build .` builds it.
FROM alpine:3.24 AS sentinel

RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata curl

ENV PORT=8888

COPY --from=builder /sentinel /app/sentinel

RUN mkdir -p /app/db && chmod 750 /app/db

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider "http://127.0.0.1:${PORT}/api/health" || exit 1

CMD ["/app/sentinel"]
