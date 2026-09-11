# Shared Control Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an inert `protocol` workspace crate that defines the version 1 Sentinel-to-Flux gRPC contract, the first two capabilities, and pure compatibility helpers.

**Architecture:** Generate client and server Rust types from one protobuf file with tonic 0.14 and prost 0.14. Keep this crate independent from Sentinel runtime services. Expose only generated wire types, fixed protocol constants, protocol-range selection, and deterministic capability intersection.

**Tech Stack:** Rust 1.97.1, Protocol Buffers 3, tonic 0.14.6, tonic-prost 0.14.6, prost 0.14.4, tonic-prost-build 0.14.6, prost-build 0.14.4, protoc-bin-vendored 3.2.0.

**References:**
- https://docs.rs/tonic-prost-build/0.14.6
- https://docs.rs/prost/0.14.4
- https://protobuf.dev/programming-guides/dos-donts/

## Global constraints

- The package name is `protocol`; its Rust library name is `sentinel_protocol`.
- The protobuf package is `coolify.sentinel.control.v1`.
- Protocol version 1 is both the minimum and maximum supported version.
- Initial capabilities are exactly `system.ping.v1` and `system.info.v1`.
- The change starts no service and makes no network request.
- The change does not modify Sentinel startup or its environment configuration.
- Generated client and server code must use vendored `protoc`, so developer machines and CI need no system `protoc` package.
- Use test-driven development and observe the public-contract test fail before adding the schema and helpers.

---

### Task 1: Add the version 1 protocol crate

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/protocol/Cargo.toml`
- Create: `crates/protocol/build.rs`
- Create: `crates/protocol/proto/control.proto`
- Create: `crates/protocol/src/lib.rs`
- Create: `crates/protocol/src/tests.rs`

**Interfaces:**
- Produces: `sentinel_protocol::control::v1`, with generated `AgentClient`, `AgentServer`, `AgentMessage`, `ControlMessage`, and all version 1 payload types.
- Produces: `PROTOCOL_MIN: u32`, `PROTOCOL_MAX: u32`, `CAPABILITY_SYSTEM_PING: &str`, and `CAPABILITY_SYSTEM_INFO: &str`.
- Produces: `select_protocol(local_min: u32, local_max: u32, remote_min: u32, remote_max: u32) -> Option<u32>`.
- Produces: `intersect_capabilities(granted: &[String], advertised: &[String], supported: &[&str]) -> Vec<String>`.

- [x] **Step 1: Create test-only crate scaffolding and failing contract tests**

Add `crates/protocol` to the workspace. Create a package manifest with the selected dependency versions. Create `src/lib.rs` with only `#[cfg(test)] mod tests;` and create tests that reference the planned constants, helpers, and generated message module.

Tests must cover:

- Version constants equal 1.
- Exact capability strings.
- Highest overlapping version selection.
- Invalid zero and inverted ranges return `None`.
- Capability intersection returns only values present in all three inputs, in supported-list order, without duplicates.
- `Hello` protobuf encode and decode round trip.
- An appended unknown protobuf field is ignored during decode.
- Both generated gRPC client and server modules exist.

- [x] **Step 2: Run tests and verify the expected red state**

Run:

```bash
cargo test -p protocol
```

Expected result: compilation fails because the constants, helpers, and generated `control::v1` module do not exist.

- [x] **Step 3: Add the protobuf build pipeline**

Add the workspace dependencies and protocol package dependencies. In `build.rs`, get the vendored `protoc` path, set it on `prost_build::Config::protoc_executable`, and pass that config to `tonic_prost_build::configure().build_client(true).build_server(true).compile_with_config(...)`.

The build script must return an error instead of panicking and must emit a rerun directive for `proto/control.proto`.

- [x] **Step 4: Add the minimum version 1 protobuf schema**

Define:

```protobuf
service Agent {
  rpc Stream(stream AgentMessage) returns (stream ControlMessage);
}
```

Define `AgentMessage` variants `Hello`, `Heartbeat`, `CommandAccepted`, and `CommandResult`. Define `ControlMessage` variants `Welcome`, `Command`, `EventAck`, and `ShutdownHint`.

Define typed request and result payloads for `system.ping.v1` and `system.info.v1`. Use signed 64-bit Unix milliseconds for wire timestamps. Use `optional` fields for host facts that Sentinel can fail to collect. Reserve field numbers 5 through 9 in command and result payload unions for future envelope extensions.

- [x] **Step 5: Add generated exports and pure compatibility helpers**

Include the generated package under `control::v1`. Add the four constants and the two pure helper functions with the exact signatures in the Interfaces section.

`select_protocol` returns the highest value in the overlap and rejects zero or inverted ranges. `intersect_capabilities` follows `supported` order and emits each capability at most once.

- [x] **Step 6: Run focused tests and verify green**

Run:

```bash
cargo test -p protocol
```

Expected result: every protocol test passes.

- [x] **Step 7: Run full verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked
```

Expected result: every command exits with status 0 and produces no warnings.

- [x] **Step 8: Commit the protocol crate**

```bash
git add Cargo.toml Cargo.lock crates/protocol docs/superpowers/plans/2026-09-11-shared-control-protocol.md
git commit -m "feat(protocol): add Sentinel control contract"
```
