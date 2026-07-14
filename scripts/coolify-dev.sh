#!/usr/bin/env bash

set -euo pipefail

command="${1:-build}"
image="${SENTINEL_DEV_IMAGE:-sentinel:dev}"
container="${SENTINEL_CONTAINER:-coolify-sentinel}"

release_version="$(sed -n 's/^var Version = "\([^"]*\)"/\1/p' pkg/config/config.go)"
revision="$(git rev-parse --short HEAD)"
dirty=""
if [[ -n "$(git status --porcelain)" ]]; then
    dirty=".dirty"
fi
dev_version="${SENTINEL_DEV_VERSION:-${release_version}-dev+${revision}${dirty}}"

environment_value() {
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" \
        | awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print; exit }'
}

case "$command" in
build)
    docker build --build-arg VERSION="$dev_version" -t "$image" .
    echo "Built $image with Sentinel version $dev_version."
    echo "Set it as Coolify's Custom Sentinel Docker Image (Dev Only)."
    if docker ps --format '{{.Names}}' | grep -qx coolify-testing-host; then
        docker exec coolify-testing-host docker image inspect "$image" >/dev/null
        echo "Coolify's testing host can access $image."
    fi
    ;;
smoke)
    docker inspect "$container" >/dev/null
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}not-configured{{end}}' "$container")"
    if [[ "$health" != "healthy" ]]; then
        echo "$container health is $health" >&2
        exit 1
    fi
    docker exec "$container" sh -c 'wget -qO- http://127.0.0.1:${PORT:-8888}/api/health'
    echo
    docker exec "$container" sh -c 'wget -qO- --header="Authorization: Bearer ${TOKEN}" http://127.0.0.1:${PORT:-8888}/api/cpu/history'
    echo
    echo "Sentinel health and authenticated metrics checks passed."
    ;;
integration)
    docker inspect "$container" >/dev/null
    token="$(environment_value TOKEN)"
    endpoint="$(environment_value PUSH_ENDPOINT)"
    if [[ -z "$token" || -z "$endpoint" ]]; then
        echo "Could not read TOKEN and PUSH_ENDPOINT from $container" >&2
        exit 1
    fi

    candidate="coolify-sentinel-integration"
    candidate_port="${SENTINEL_TEST_PORT:-18888}"
    docker rm -f "$candidate" >/dev/null 2>&1 || true
    trap 'docker rm -f "$candidate" >/dev/null 2>&1 || true' EXIT
    docker run -d --name "$candidate" \
        -e TOKEN="$token" \
        -e PUSH_ENDPOINT="$endpoint" \
        -e PORT="$candidate_port" \
        -e PUSH_INTERVAL_SECONDS=1 \
        -e COLLECTOR_ENABLED=true \
        -e COLLECTOR_REFRESH_RATE_SECONDS=1 \
        -e COLLECTOR_RETENTION_PERIOD_DAYS=1 \
        -v /var/run/docker.sock:/var/run/docker.sock \
        --pid host \
        --add-host=host.docker.internal:host-gateway \
        "$image" >/dev/null

    for _ in {1..30}; do
        if [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$candidate")" == "healthy" ]]; then
            break
        fi
        sleep 1
    done
    if [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$candidate")" != "healthy" ]]; then
        docker logs "$candidate" >&2
        exit 1
    fi

    reported_version="$(docker exec "$candidate" sh -c 'wget -qO- http://127.0.0.1:${PORT}/api/version')"
    if [[ "$reported_version" != "$dev_version" ]]; then
        echo "Sentinel reported version $reported_version, expected $dev_version" >&2
        exit 1
    fi

    history="$(docker exec "$candidate" sh -c 'wget -qO- --header="Authorization: Bearer ${TOKEN}" http://127.0.0.1:${PORT}/api/cpu/history')"
    if [[ "$history" == "[]" ]]; then
        echo "Sentinel collector did not store CPU history" >&2
        exit 1
    fi
    sleep 2
    logs="$(docker logs "$candidate" 2>&1)"
    if ! grep -q 'Pushing to' <<<"$logs"; then
        echo "Sentinel did not attempt a Coolify push" >&2
        exit 1
    fi
    if grep -Eq 'Push operation failed|Error pushing' <<<"$logs"; then
        printf '%s\n' "$logs" >&2
        exit 1
    fi
    echo "Local Sentinel image passed health, authenticated metrics, collection, and Coolify push checks."
    ;;
*)
    echo "Usage: $0 [build|smoke|integration]" >&2
    exit 2
    ;;
esac
