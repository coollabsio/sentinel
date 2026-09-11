# Dormant Control-Plane Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the disabled-by-default `CONTROL_PLANE_ENABLED` Sentinel configuration without starting a service, making a request, or changing existing runtime behavior.

**Architecture:** Extend the existing `config::Config` value with one boolean parsed through the established `bool_from_env` helper. Keep the main process and all current services unchanged. Prove the default, enabled, invalid, and test-helper values in the existing serialized environment tests.

**Tech Stack:** Rust 1.97.1, Cargo workspace, the existing `config` crate test framework.

## Global constraints

- `CONTROL_PLANE_ENABLED` defaults to `false`.
- This change adds no URL or token environment variable.
- Sentinel continues to use `TOKEN` and `PUSH_ENDPOINT`.
- This change creates no control task, network request, file, SQLite table, Cargo dependency, or compile-time feature.
- Existing Sentinel behavior must remain unchanged when the variable is absent or false.
- Follow test-driven development and observe the new test fail before production code changes.

---

### Task 1: Parse the dormant control-plane gate

**Files:**
- Modify: `crates/config/src/lib.rs`
- Modify: `crates/config/src/tests.rs`
- Modify: `crates/traffic/src/service/tests.rs` to keep its direct `Config` test fixture complete
- Modify: `docs/superpowers/specs/2026-09-11-control-channel-foundation-design.md` only if implementation finds a contradiction

**Interfaces:**
- Consumes: the existing `bool_from_env(key: &'static str, fallback: bool) -> Result<bool, ConfigError>` helper.
- Produces: `Config::control_plane_enabled: bool`, populated from `CONTROL_PLANE_ENABLED` with a `false` fallback.

- [x] **Step 1: Write failing configuration tests**

Add three focused tests to `crates/config/src/tests.rs`:

```rust
#[test]
fn control_plane_defaults_to_disabled() {
    let _l = env_lock().lock().unwrap();
    let _g = EnvGuard::set(&[
        ("TOKEN", "t"),
        ("PUSH_ENDPOINT", "https://example.com"),
        ("CONTROL_PLANE_ENABLED", ""),
    ]);
    let config = Config::load(false).unwrap();
    assert!(!config.control_plane_enabled);
}

#[test]
fn control_plane_can_be_enabled() {
    let _l = env_lock().lock().unwrap();
    let _g = EnvGuard::set(&[
        ("TOKEN", "t"),
        ("PUSH_ENDPOINT", "https://example.com"),
        ("CONTROL_PLANE_ENABLED", "true"),
    ]);
    let config = Config::load(false).unwrap();
    assert!(config.control_plane_enabled);
}

#[test]
fn control_plane_rejects_invalid_boolean() {
    let _l = env_lock().lock().unwrap();
    let _g = EnvGuard::set(&[
        ("TOKEN", "t"),
        ("PUSH_ENDPOINT", "https://example.com"),
        ("CONTROL_PLANE_ENABLED", "enabled"),
    ]);
    assert!(matches!(
        Config::load(false),
        Err(ConfigError::InvalidBool("CONTROL_PLANE_ENABLED"))
    ));
}
```

Also add this assertion to a config test that calls `Config::load_for_test()`:

```rust
assert!(!Config::load_for_test().control_plane_enabled);
```

If no focused `load_for_test` test exists, add:

```rust
#[test]
fn test_config_disables_control_plane() {
    assert!(!Config::load_for_test().control_plane_enabled);
}
```

- [x] **Step 2: Run the focused tests and verify the expected compile failure**

Run:

```bash
cargo test -p config control_plane -- --nocapture
```

Expected result: compilation fails because `Config` has no `control_plane_enabled` field. This is the required red state.

- [x] **Step 3: Add the minimum configuration field and parser call**

In `Config`, add:

```rust
pub control_plane_enabled: bool,
```

In `Config::load`, parse:

```rust
let control_plane_enabled = bool_from_env("CONTROL_PLANE_ENABLED", false)?;
```

Set the field in the returned `Config`:

```rust
control_plane_enabled,
```

Set the test helper field in `Config::load_for_test()`:

```rust
control_plane_enabled: false,
```

Do not change `src/main.rs` and do not create a control crate in this task.

- [x] **Step 4: Run the focused tests and verify green**

Run:

```bash
cargo test -p config control_plane -- --nocapture
```

Expected result: all focused control-plane configuration tests pass.

- [x] **Step 5: Run configuration and workspace verification**

Run:

```bash
cargo fmt --all -- --check
cargo test -p config
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked
```

Expected result: every command exits with status 0 and produces no warnings.

- [x] **Step 6: Commit the implementation**

```bash
git add crates/config/src/lib.rs crates/config/src/tests.rs
git commit -m "feat(config): add dormant control plane gate"
```
