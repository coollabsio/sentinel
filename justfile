# https://just.systems

set unstable
set dotenv-load
default:
    just --choose

dev:
    TOKEN=your-secret-token cargo watch -c -x run
