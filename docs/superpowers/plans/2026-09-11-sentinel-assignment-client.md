# Sentinel Assignment Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add an isolated assignment client that uses Sentinel's existing Coolify URL and token to request an in-memory Flux assignment.

**Architecture:** Create a `control` workspace crate with a typed HTTP client. It appends the assignment route to the existing `PUSH_ENDPOINT`, authenticates with the existing `TOKEN`, advertises the shared protocol range and capabilities, validates enabled or disabled responses, and maps failures to stable retry categories. Nothing invokes the client from Sentinel startup in this change.

**Tech Stack:** Rust 1.97.1, reqwest 0.13, serde 1, url 2, time 0.3, tokio 1.53, axum 0.8 test server, the local `protocol` crate.

## Global constraints

- Add no environment variable.
- Reuse `TOKEN` and `PUSH_ENDPOINT` through constructor arguments.
- Do not modify `src/main.rs` or start a background task.
- Do not connect to Flux.
- Store the token only inside the client and never include it in `Debug` or error text.
- Keep assignments and credentials in memory.
- Build custom base paths correctly instead of replacing them.
- Limit response bodies through typed JSON decoding and never return raw response bodies in errors.
- Use test-driven development and observe the missing crate or API failure before implementation.

---

### Task 1: Add the isolated assignment client

**Files:**
- Create: `crates/control/Cargo.toml`
- Create: `crates/control/src/lib.rs`
- Create: `crates/control/src/assignment.rs`
- Create: `crates/control/src/tests.rs`
- Modify: `Cargo.lock`

**Interfaces:**
- Produces: `AssignmentClient::new(endpoint: &str, token: &str, sentinel_version: &str) -> Result<Self, AssignmentError>`.
- Produces: `AssignmentClient::request(&self) -> Result<AssignmentOutcome, AssignmentError>`.
- Produces: `AssignmentOutcome::Enabled(Assignment)` and `AssignmentOutcome::Disabled { retry_after: Duration }`.
- Produces: `Assignment` with server ID, Flux URL, credential, expiry, protocol range, and heartbeat interval.
- Produces stable errors for invalid configuration, invalid response, authentication rejection, unsupported Coolify, incompatible state, rate limiting, and temporary failure.

- [x] **Step 1: Create crate scaffolding and failing behavior tests**

Create the package and test module before production types exist. Use a local Axum listener to test real HTTP requests.

Tests must prove:

- The request uses `POST` on a custom base path plus `/api/v1/sentinel/control/assignment`.
- The request uses `Authorization: Bearer <TOKEN>`.
- The request sends the Sentinel version, protocol range, and exactly the two initial capabilities.
- A valid enabled response becomes a typed in-memory assignment.
- A valid disabled response returns its retry duration.
- Empty server ID, credential, invalid Flux URL, invalid expiry, incompatible protocol range, and heartbeat outside 10 through 120 seconds are rejected.
- `401` and `403` map to authentication rejection.
- `404` maps to unsupported Coolify.
- `409` maps to incompatible state.
- `429` parses an integer `Retry-After` header.
- `5xx` and request failures map to temporary failure.
- Debug and display representations never contain the token.

- [x] **Step 2: Run the focused test and observe red**

Run:

```bash
cargo test -p control
```

Expected result: compilation fails because the public assignment types and methods do not exist.

- [x] **Step 3: Implement request and response types**

Use serde structs with the JSON field names from the approved specification. Build the request from `PROTOCOL_MIN`, `PROTOCOL_MAX`, `CAPABILITY_SYSTEM_PING`, and `CAPABILITY_SYSTEM_INFO`.

Represent credential expiry as a parsed `time::OffsetDateTime` and Flux URL as `url::Url`. Keep the credential as a private string exposed only by an explicit accessor needed by the later gRPC client.

- [x] **Step 4: Implement URL construction and HTTP request**

Parse the base endpoint once in the constructor. Reject non-HTTP schemes, missing hosts, credentials, queries, and fragments. Append the assignment route after any existing base path.

Build one reqwest client with a 10-second request timeout. Send JSON with bearer authentication. Do not log the token, request headers, or enabled response body.

- [x] **Step 5: Implement status mapping and response validation**

Map `401`, `403`, `404`, `409`, `429`, and `5xx` before JSON decoding. Parse integer `Retry-After` seconds for `429`. Treat other non-success status codes and malformed success JSON as invalid responses.

For enabled responses, require non-empty server ID and credential, an HTTP or HTTPS Flux URL with a host, an RFC 3339 expiry, an overlapping non-zero protocol range, and heartbeat from 10 through 120 seconds. For disabled responses, require a positive retry duration.

- [x] **Step 6: Run focused tests and observe green**

Run:

```bash
cargo test -p control
```

Expected result: all assignment client tests pass.

- [x] **Step 7: Run full verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked
cargo clippy --workspace --all-targets --features traffic -- -D warnings
cargo test --workspace --features traffic
cargo build --release --locked --features traffic
cargo audit
```

Expected result: format, lint, tests, and builds exit with status 0. Audit must report no known vulnerabilities. Existing allowed warnings must be reported.

- [x] **Step 8: Commit the assignment client**

```bash
git add Cargo.lock crates/control docs/superpowers/plans/2026-09-11-sentinel-assignment-client.md
git commit -m "feat(control): add dormant assignment client"
```
