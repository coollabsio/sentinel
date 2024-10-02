FROM golang:1.23 AS deps

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

FROM golang:1.23 AS build

WORKDIR /app
COPY --from=deps /go/pkg/mod /go/pkg/mod
COPY . .
RUN apt-get update && apt-get install -y gcc g++
ENV CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

RUN go build -ldflags="-s -w" -o /app/bin/sentinel ./

FROM gcr.io/distroless/cc-debian11
ENV GIN_MODE=release
COPY --from=build /app/bin/sentinel /app/sentinel
CMD ["/app/sentinel"]