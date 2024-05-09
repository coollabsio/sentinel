FROM golang:1.22-alpine3.19 AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
RUN go build -o /app/bin/sentinel ./cmd/sentinel

FROM alpine:3.19
RUN apk add --no-cache ca-certificates curl
ENV GIN_MODE=release
COPY --from=build /app/bin/sentinel /app/sentinel
CMD ["/app/sentinel"]
