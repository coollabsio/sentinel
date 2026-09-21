# https://just.systems

set unstable
set dotenv-load
default:
    just --choose

dev:
    # DOCKER_HOST defaults to the rootless Podman socket; override by
    # exporting it (e.g. DOCKER_HOST=unix:///var/run/docker.sock).
    # Watch only source trees: sentinel writes ./db/*.sqlite-shm on startup,
    # and watching the project root self-triggers a restart loop.
    TOKEN=your-secret-token PUSH_ENABLED=false DOCKER_HOST=${DOCKER_HOST:-unix://$XDG_RUNTIME_DIR/podman/podman.sock} cargo watch -c -w src -w crates -w Cargo.toml -w Cargo.lock -x run
