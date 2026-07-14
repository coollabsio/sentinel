# Build stage
FROM golang:1.25.5-alpine3.22 AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go mod files for better caching
COPY go.mod go.sum ./

# Download dependencies with cache mount
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

# Build with cache mounts and optimizations
ARG VERSION
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    VERSION_LDFLAG="" && \
    if [ -n "${VERSION}" ]; then VERSION_LDFLAG="-X github.com/coollabsio/sentinel/pkg/config.Version=${VERSION}"; fi && \
    CGO_ENABLED=1 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w ${VERSION_LDFLAG}" \
    -o /app/sentinel ./

# Final stage
FROM alpine:3.22

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Set environment
ENV GIN_MODE=release \
    PORT=8888

# Copy binary
COPY --from=builder /app/sentinel /app/sentinel

# Create directory for database with proper permissions
RUN mkdir -p /app/db && chmod 755 /app/db

# Health check using wget (included in alpine base)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider "http://127.0.0.1:${PORT}/api/health" || exit 1

# Run the binary as root (required for bind mounts and Docker socket access)
CMD ["/app/sentinel"]
