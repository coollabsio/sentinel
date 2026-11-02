# coolify-builder: the one-shot build container that `image.build.v1` starts.
# It clones one commit and builds it through the BuildKit socket of the Node.
FROM docker.io/moby/buildkit:v0.34.1-rootless@sha256:f68752a5a94acfcdad2d07867b7075601a421638e17fc5f28efc1c814d0c4f89 AS buildkit

FROM alpine:3.24 AS railpack
ARG TARGETARCH
ARG RAILPACK_VERSION=v0.43.0
RUN apk add --no-cache curl && \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl; sum=248a8f60f36854aabed6124113631078a802de3461660855fc4de9c26065c1fb ;; \
      arm64) target=arm64-unknown-linux-musl; sum=732ece14eb4f4676a43ebba19431f954edf7b130acb76159ef0f2ff86ac42ac9 ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/railpack.tar.gz "https://github.com/railwayapp/railpack/releases/download/${RAILPACK_VERSION}/railpack-${RAILPACK_VERSION}-${target}.tar.gz" && \
    echo "${sum}  /tmp/railpack.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/railpack.tar.gz -C /usr/local/bin railpack

FROM alpine:3.24
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates git git-lfs jq && \
    addgroup -g 1000 build && adduser -D -u 1000 -G build -h /home/build build
COPY --from=buildkit /usr/bin/buildctl /usr/local/bin/buildctl
COPY --from=railpack /usr/local/bin/railpack /usr/local/bin/railpack
COPY scripts/builder-entrypoint.sh /usr/local/bin/coolify-build
# The Railpack frontend must match the Railpack CLI above.
ENV RAILPACK_FRONTEND=ghcr.io/railwayapp/railpack-frontend:v0.43.0@sha256:355ef61fae6f2551103cd8b10c710cb07167dd353d561f15c69b8d7ac1c676cc \
    GIT_TERMINAL_PROMPT=0
USER 1000:1000
WORKDIR /home/build
ENTRYPOINT ["/usr/local/bin/coolify-build"]
