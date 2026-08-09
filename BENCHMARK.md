# Sentinel Benchmark Spec

How to measure Sentinel so results are comparable across **versions**, **implementations** (Go vs Rust), and **machines**.

This is a **specification**, not a one-off report. Record every run in a dated results file (suggested: `docs/benchmark-results/YYYY-MM-DD-<label>.md`) using the template at the end.

Dated run reports live under `docs/benchmark-results/` (canonical run: the Go vs Rust suite).

**Harness:** all HTTP load / latency / stress work uses the in-tree Rust tool:

```bash
cargo build -p sentinel-bench --release
./target/release/sentinel-bench --help
```

(`sentinel-bench` is a workspace member for **host use only**. The Docker image builds `-p sentinel` only and does not ship the harness.)

---

## 1. Goals

| Goal | Why it matters for Coolify |
|------|----------------------------|
| **Small image / binary** | Faster pulls on every server; less disk |
| **Low idle memory** | Always-on sidecar on every host; RSS multiplies by server count |
| **Fast cold start** | Docker HEALTHCHECK / Coolify “is agent up?” time |
| **Healthy API latency & throughput** | Dashboard and polling should stay snappy under concurrent reads |
| **Survives stress** | Spikes of concurrent reads must not crash the agent or break health |
| **Stable under collector load** | Real deployments enable metrics collection |

We care about **relative** comparisons (A vs B on the same host) more than absolute “industry” numbers.

---

## 2. Fair-comparison rules

Always hold these constant between candidates:

1. **Same host**, same day, as little other load as possible.
2. **Same env** (see §3).
3. **Same ports pattern** (e.g. Go `18888`, candidate `18889`) — never fight for one port.
4. **Collector on** for memory / API runs (`COLLECTOR_ENABLED=true`).
5. **Docker socket mounted** read-only so container metrics paths exercise real I/O.
6. **Push endpoint is a blackhole** (`http://127.0.0.1:9` or similar). Push failures must not dominate the bench; we are not measuring the Coolify API.
7. **Use `sentinel-bench` only** for latency / load / stress (not ad-hoc shell curl loops — they under-count under concurrency).
8. Report **min / avg / median / max** for cold start (n≥5). Report **avg / p50 / p95 / p99** for latency and **RPS + p50 + error%** for load/stress.
9. **Always include system configuration** (§2.1) at the top of every results file — numbers without host context are not comparable.

### 2.1 System configuration (required)

Every benchmark results document **must** open with a system-configuration section. Capture it with:

```bash
./target/release/sentinel-bench sys
```

(`latency` / `load` / `stress` / `suite` also print this banner automatically unless `--no-sysinfo` is passed.)

Minimum fields (the harness emits these as `key=value`):

| Field | Meaning |
|-------|---------|
| `date_utc` | When the capture was taken |
| `hostname` | Machine name |
| `uname` | Kernel + arch (`uname -srm`) |
| `os` | Distro pretty name |
| `arch` | e.g. `x86_64`, `aarch64` |
| `virt` | Hypervisor/container (`lxc`, `kvm`, `none`, …) |
| `cpu_model` | CPU model string |
| `cpu_logical` | Logical CPUs visible to the harness |
| `cpu_online` | Online CPU list when available |
| `mem_total` / `mem_available` | Host RAM at capture time |
| `loadavg` | 1/5/15-minute load averages |
| `cgroup_v2` | Whether cgroup v2 is in use |
| `cgroup_cpu_max` / `cgroup_memory_max` | Limits if constrained (containers/VMs) |
| `docker_server` / `docker_info` | Engine version + driver/cgroup/ncpu/mem |
| `harness` | `sentinel-bench` version |

Paste the full banner into the results file under **System configuration**. Do not summarize it away — constrained cgroups (e.g. LXC with 8 of 16 CPUs) explain large RPS differences across machines.

### Identity of a build

Record for every candidate:

| Field | Example |
|-------|---------|
| Label | `rust-0.0.22` / `go-0.0.22` |
| Image ref | `sentinel:rust` / `coollabsio/sentinel:latest` |
| Image digest or ID | `sha256:…` or short ID |
| `/api/version` | `0.0.22` |
| Git SHA (if local build) | `git rev-parse --short HEAD` |
| Host (full) | output of `sentinel-bench sys` — see §2.1 |
| Harness | `sentinel-bench` version / git SHA |

---

## 3. Standard run configuration

```bash
export TOKEN=bench-token-compare
export PUSH_ENDPOINT=http://127.0.0.1:9   # blackhole; intentional
export COLLECTOR_ENABLED=true
export COLLECTOR_REFRESH_RATE_SECONDS=5
export PUSH_INTERVAL_SECONDS=3600         # effectively off for the bench window
export DEBUG=false

# Matching defaults for the harness:
export SENTINEL_BENCH_TOKEN="$TOKEN"
# export SENTINEL_BENCH_BASE=http://127.0.0.1:18889
```

Container mounts:

```text
-v /var/run/docker.sock:/var/run/docker.sock:ro
# optional: named volume or tmpfs for /app/db so runs don't share SQLite state
```

Example start:

```bash
docker run -d --name sentinel-bench-a \
  -p 127.0.0.1:18888:8888 \
  -e TOKEN -e PUSH_ENDPOINT \
  -e COLLECTOR_ENABLED -e COLLECTOR_REFRESH_RATE_SECONDS \
  -e PUSH_INTERVAL_SECONDS -e DEBUG \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  "$IMAGE_A"
```

Warm-up before memory / API benches: **≥15 seconds** after `/api/health` is OK (lets collector tick a few times).

---

## 4. Metrics

### 4.1 Size (static)

| Metric | How |
|--------|-----|
| Image size (bytes) | `docker image inspect "$IMAGE" --format '{{.Size}}'` |
| Binary size (bytes) | `docker run --rm --entrypoint sh "$IMAGE" -c 'stat -c%s /app/sentinel'` |

Convert to MiB for humans: `bytes / 1024 / 1024`. Prefer raw bytes in tables for diffs.

### 4.2 Cold start

**Definition:** wall time from `docker run -d …` returning until `GET /api/health` returns HTTP 200.

- Trials: **n = 5** (destroy container each trial).
- Poll interval: ≤20 ms.
- Report: min, avg, median, max (ms).

```bash
start_ns=$(date +%s%N)
docker run -d --name "$NAME" ... "$IMAGE" >/dev/null
until curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null; do
  sleep 0.02
done
end_ns=$(date +%s%N)
echo $(( (end_ns - start_ns) / 1000000 ))   # ms
docker rm -f "$NAME" >/dev/null
```

**Regression guard (unit):** `HostSampler::new` must stay fast (no full 200 ms CPU sleep on the critical path):

```bash
cargo test -p collector host_sampler_new_is_fast -- --nocapture
```

### 4.3 Memory

After warm-up (≥15 s), sample **5 times** every 2 s:

| Metric | How |
|--------|-----|
| Docker reported usage | `docker stats --no-stream --format '{{.MemUsage}}' "$NAME"` |
| Process RSS / peak / threads | `docker exec "$NAME" sh -c 'pid=$(pidof sentinel); grep -E "VmRSS[|]VmHWM[|]Threads" /proc/$pid/status'` |

Repeat **after** the load grid (§4.5) and again **after stress** (§4.6) for post-load / post-stress memory.

Primary comparison column: **process `VmRSS` idle** (most implementation-honest). Docker `MemUsage` is secondary (includes page cache noise).

### 4.4 Sequential latency (`sentinel-bench latency`)

```bash
./target/release/sentinel-bench latency \
  --base http://127.0.0.1:18889 \
  --token "$TOKEN"
```

Default samples (HTTP 200 only for latency stats):

| Endpoint | n |
|----------|---|
| `/api/health` | 80 |
| `/api/version` | 80 |
| `/api/cpu/current` | 80 |
| `/api/memory/current` | 80 |
| `/api/cpu/history` | 40 |
| `/api/memory/history` | 40 |

Report: ok, fail, avg, p50, p95, p99, min, max (ms).

### 4.5 Concurrent throughput (`sentinel-bench load`)

Fixed grid: each path × each concurrency for a timed window.

```bash
./target/release/sentinel-bench load \
  --base http://127.0.0.1:18889 \
  --token "$TOKEN" \
  --duration 8 \
  --concurrency 1,10,32 \
  --warmup 20
```

| Endpoint | concurrency | duration |
|----------|-------------|----------|
| `/api/health` | 1, 10, 32 | 8 s each |
| `/api/cpu/current` | 1, 10, 32 | 8 s each |
| `/api/memory/current` | 1, 10, 32 | 8 s each |
| `/api/cpu/history` | 1, 10, 32 | 8 s each |

Report: ok, fail, **RPS**, avg / p50 / p95 / p99 / max (ms), **error %**.

### 4.6 Stress testing (`sentinel-bench stress`)

Stress answers: *“Under a nasty concurrent read mix, does the agent stay correct and alive?”*

```bash
# Default mixed stress (recommended minimum for every release candidate)
./target/release/sentinel-bench stress \
  --base http://127.0.0.1:18889 \
  --token "$TOKEN" \
  --profile mixed \
  --concurrency 256 \
  --duration 30 \
  --max-error-pct 1.0 \
  --health-every-secs 2

# Ramp: concurrency climbs 1 → peak over the window
./target/release/sentinel-bench stress --base … --profile ramp --concurrency 256 --duration 45

# Burst: 2s at peak, 2s nearly idle, repeat
./target/release/sentinel-bench stress --base … --profile burst --concurrency 512 --duration 40

# Soak: same as mixed; use a longer duration intentionally
./target/release/sentinel-bench stress --base … --profile soak --concurrency 128 --duration 300
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--profile` | `mixed` | `mixed` \| `ramp` \| `burst` \| `soak` |
| `--concurrency` | `256` | Peak in-flight requests |
| `--duration` | `30` | Seconds |
| `--max-error-pct` | `1.0` | Exit non-zero if error rate exceeds this |
| `--max-p99-ms` | `0` (off) | Optional p99 ceiling |
| `--health-every-secs` | `2` | Mid-run `/api/health` probes (0 = off) |

**Traffic mix (weighted):** health 4, version 1, cpu/current 3, memory/current 3, cpu/history 2, memory/history 2.

**Pass criteria (default):**

1. Error rate ≤ `--max-error-pct`
2. Mid-stress health probes all succeed
3. Post-stress `GET /api/health` returns 200
4. Optional: p99 ≤ `--max-p99-ms` when set

Exit code **2** on stress failure (so CI can gate).

**Also record after stress:** process `VmRSS` / `VmHWM` / threads (same as §4.3). A large RSS spike that never returns, or thread explosion, is a soft regression even if stress “passes”.

### 4.7 Full suite shortcut

```bash
./target/release/sentinel-bench suite \
  --base http://127.0.0.1:18889 \
  --token "$TOKEN" \
  --stress-profile mixed \
  --stress-concurrency 256 \
  --stress-duration 30
```

Runs **latency → load → stress** with the shared target.

### 4.8 Optional / out of scope (for now)

| Item | Status |
|------|--------|
| Push payload success rate against a real Coolify mock | Not in default suite |
| Container history endpoints | Optional; need a long-lived container ID |
| Multi-host / noisy neighbor | Not required |
| Absolute production capacity | Not claimed |
| Writing load (mutating DB beyond collector) | Not in suite |

---

## 5. Suggested full procedure (checklist)

1. `cargo build -p sentinel-bench --release`
2. **`./target/release/sentinel-bench sys`** → paste into results (§2.1). Re-run if the machine or cgroup limits change mid-day.
3. Build or pull candidate images; record digests and `/api/version`.
4. **Size** (§4.1) for each image.
5. **Cold start** (§4.2) n=5 per image; stop containers between trials.
6. Start candidate(s) for steady-state benches; **warm ≥15 s**.
7. **Idle memory** (§4.3) ×5 samples.
8. **`sentinel-bench latency`** (§4.4) — includes sysinfo banner.
9. **`sentinel-bench load`** (§4.5).
10. **Post-load memory** (§4.3).
11. **`sentinel-bench stress`** (§4.6) — at least `mixed` 256×30s; add `ramp` / `burst` for release candidates.
12. **Post-stress memory** (§4.3).
13. `docker rm -f` bench containers; paste numbers into the results template.
14. Note log noise (Docker stats errors, push failures — expected for blackhole push).

Quick path when you only care about “is this build sane under load?”:

```bash
./target/release/sentinel-bench suite --base http://127.0.0.1:18889 --token "$TOKEN"
```

---

## 6. How to read results

| If this regresses… | Prefer checking… |
|--------------------|------------------|
| Cold start +≥100 ms | Blocking work before `TcpListener::bind` (sleeps, heavy init, Docker connect ordering) |
| Idle VmRSS | New threads, larger SQLite cache, eager sysinfo/Docker state |
| Latency / RPS | Lock contention on sampler/store, sync work on the async path |
| Stress error% / health fails | Panic under load, accept queue overflow, DB lock storms, runtime starvation |
| Post-stress RSS / threads | Leaks, unbounded task spawn, connection piles |
| Image/binary size | New deps, lost LTO/strip, debug symbols |

Comparisons are only valid **same machine, same method**. When publishing a cross-version claim, attach host `uname` and the raw table, not only percentages.

---

## 7. Baseline snapshot (2026-08-09, `sentinel-bench` 1.0.0)

One reference point so future runs have a known anchor. **Do not treat these as SLOs** — historical numbers on one Linux Docker host. Full tables: `docs/benchmark-results/2026-08-09-go-vs-rust-sentinel-bench.md`.

| Metric | Go `coollabsio/sentinel:latest` 0.0.22 | Rust `sentinel:rust` 1.0.0 |
|--------|----------------------------------------|------------------------------|
| Image size | 13 351 554 B (~12.7 MiB) | 11 230 869 B (~10.7 MiB) |
| Binary size | 17 585 816 B | 9 886 224 B |
| Cold start avg (n=5) | ~313 ms | ~291 ms |
| Idle VmRSS | ~12.8 MB | ~4.7 MB |
| Health RPS c=10 | ~25 700 | ~41 052 |
| cpu/current RPS c=10 | ~19 475 | ~39 084 |
| memory/current RPS c=32 | ~24 599 | ~50 647 |
| Stress mixed 256×30s RPS | ~24 821 | ~41 393 |
| Stress mixed p99 | ~56 ms | ~28 ms |

Earlier Rust cold start was ~590 ms avg; fixed by removing a 200 ms CPU warm-up sleep before bind (see §8).

---

## 8. Cold-start design note (why the suite cares)

CPU usage from `sysinfo` is **delta-based**: you need two samples over time for a real percentage. Sleeping 200 ms (`MINIMUM_CPU_UPDATE_INTERVAL`) *before* binding the HTTP port made `/api/health` wait for that sleep.

**Policy:** do not block process startup (or health) on CPU warm-up. A first `/api/cpu/current` may report ~0% (same idea as Go’s `cpu.Percent(0, …)`). The collector’s normal refresh interval supplies a real window for stored history.

Unit guard: `cargo test -p collector host_sampler_new_is_fast`.

---

## 9. Results template

Copy into `docs/benchmark-results/YYYY-MM-DD-<label>.md`:

````markdown
# Benchmark results — YYYY-MM-DD

## System configuration
```text
(paste full output of: ./target/release/sentinel-bench sys)
```

## Environment
- Method: BENCHMARK.md + sentinel-bench (git: <sha>)
- Agent env: COLLECTOR_ENABLED=true, refresh 5s, push blackhole, docker.sock ro

## Candidates
| Label | Image | ID/digest | /api/version | Git SHA |
|-------|-------|-----------|--------------|---------|
| A | | | | |
| B | | | | |

## Size
| Candidate | Image bytes | Binary bytes |
|-----------|-------------|--------------|
| A | | |
| B | | |

## Cold start (ms, n=5)
| Candidate | min | avg | med | max |
|-----------|-----|-----|-----|-----|
| A | | | | |
| B | | | | |

## Memory idle (after ≥15s warm)
| Candidate | VmRSS | VmHWM | Threads | docker MemUsage |
|-----------|-------|-------|---------|-----------------|
| A | | | | |
| B | | | | |

## Memory post-load
| Candidate | VmRSS | VmHWM | Threads | docker MemUsage |
|-----------|-------|-------|---------|-----------------|
| A | | | | |
| B | | | | |

## Memory post-stress
| Candidate | VmRSS | VmHWM | Threads | docker MemUsage |
|-----------|-------|-------|---------|-----------------|
| A | | | | |
| B | | | | |

## Sequential latency
(paste `sentinel-bench latency` output)

## Concurrent throughput
(paste `sentinel-bench load` output)

## Stress
- profile / concurrency / duration:
- result: PASS|FAIL
(paste `sentinel-bench stress` summary)

## Notes
- 
````

---

## 10. Related files

| File | Role |
|------|------|
| `BENCHMARK.md` (this file) | Spec — how to measure |
| `crates/sentinel-bench/` | Rust harness (`sys` / `latency` / `load` / `stress` / `suite`) |
| `docs/benchmark-results/` | Dated run reports (canonical history) |
| `crates/collector/tests/startup_timing.rs` | Guards against reintroducing constructor sleep |
| `Dockerfile` | Builds `-p sentinel` only (bench stays on the host) |
