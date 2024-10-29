FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN --mount=type=cache,target=/var/cache/apk \
    apk update && \
    apk add gcc g++ && \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /app/sentinel ./

FROM alpine:latest
RUN --mount=type=cache,target=/var/cache/apk \
    apk update && \
    apk add ca-certificates curl

ENV GIN_MODE=release
COPY --from=builder /app/sentinel /app/sentinel
CMD ["/app/sentinel"]
