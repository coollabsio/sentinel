FROM golang:1.23-bullseye AS deps

WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

FROM golang:1.23-bullseye AS build

WORKDIR /app
COPY --from=deps /go/pkg/mod /go/pkg/mod
COPY . .
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && apt-get install -y gcc g++
ENV CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -o /app/bin/sentinel ./

FROM debian:bullseye-slim
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
ENV GIN_MODE=release
COPY --from=build /app/ /app
COPY --from=build /app/bin/sentinel /app/sentinel
CMD ["/app/sentinel"]
