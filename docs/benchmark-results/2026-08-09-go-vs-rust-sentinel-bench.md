# Sentinel Go vs Rust Benchmark

**Method:** [BENCHMARK.md](../../BENCHMARK.md) + `sentinel-bench` 1.0.0
**Repo git:** `e4740c9` (branch `go-to-rust-duckdb-migration`)
**Agent env:** `COLLECTOR_ENABLED=true`, refresh 5s, Docker socket mounted RO, push → `http://127.0.0.1:9` (blackhole)

This is the single canonical Go-vs-Rust run. It re-measures the migration on the
**current Rust build** (1.0.0, with the cached-memory snapshot and bounded
history-query admission that landed after the first draft) against the released
Go image, same host, same day, same method.

## System configuration

Captured on the bench host (required for every run — see BENCHMARK.md §2.1):

```
date_utc=2026-08-09T08:18:41Z
hostname=coder
uname=Linux 7.0.2-3-pve x86_64
os=Debian GNU/Linux 13 (trixie)
arch=x86_64
virt=lxc
cpu_model=AMD Ryzen 7 3700X 8-Core Processor
cpu_logical=8
cpu_online=1,4-5,7-9,11-12
mem_total=10.00 GiB (10485760 kB)
mem_available=5.94 GiB (6229223 kB)
loadavg=2.66 2.10 1.72
cgroup_v2=true
cgroup_cpu_max=max 100000
cgroup_memory_max=max
docker_server=29.7.2
docker_info=driver=overlayfs cgroup_driver=systemd cgroup_version=2 ncpu=8 mem_total=10737418240
harness=sentinel-bench 1.0.0
```

**Reading this host:** Proxmox **LXC** guest — 8 logical CPUs visible, **10 GiB**
RAM cap, cgroup v2, Docker 29.7.2. Absolute RPS is for this machine only;
re-capture with `./target/release/sentinel-bench sys` on every new results file.
Note `/proc/meminfo` is served by lxcfs here (slower than a bare-metal procfs read),
which slightly inflates the memory-endpoint gains vs a non-container host.

## Candidates

| Label | Image | ID (short) | `/api/version` |
|-------|-------|------------|----------------|
| **Go** | `coollabsio/sentinel:latest` | `275644b8fb14` | 0.0.22 (current release) |
| **Rust** | `sentinel:rust` (this branch) | `310dea0622c5` | 1.0.0 |

> Both were exercised as Docker containers, same run config and ports (Go 18888,
> Rust 18889). The Go image is the current published release (0.0.22); the Rust
> build is this branch at 1.0.0.

---

## Size

| Metric | Go | Rust | Rust vs Go |
|--------|-----|------|------------|
| Docker image | 13 351 554 B (12.73 MiB) | 11 230 869 B (10.71 MiB) | **−16%** |
| `/app/sentinel` binary | 17 585 816 B (16.77 MiB) | 9 886 224 B (9.43 MiB) | **−44%** |

---

## Cold start

**Definition:** `docker run -d` return → first successful `GET /api/health` (n=5, destroy between trials).

| | Go | Rust |
|--|-----|------|
| trials (ms) | 376, 291, 304, 302, 293 | 293, 285, 295, 285, 297 |
| min / avg / med / max | 291 / **313** / 302 / 376 | 285 / **291** / 293 / 297 |
| | | **Rust ~7% faster & tighter spread** |

> Both stacks open health in ~300 ms; ~290 ms is the Docker container-creation
> floor on this host. Rust is marginally faster with less run-to-run jitter.

---

## Memory (process `VmRSS` primary)

### Idle (after ≥20 s warm-up, 5 samples)

| | Go | Rust |
|--|-----|------|
| VmRSS range | 12 612–12 976 kB | 4 648–4 864 kB |
| VmRSS avg | **~12.8 MB** | **~4.7 MB (−63%)** |
| Threads | 13 | 10 |
| Docker MemUsage (typical) | ~8.3–9.2 MiB | ~3.3–4.0 MiB |

### After load grid (`sentinel-bench load`)

| | Go | Rust |
|--|-----|------|
| VmRSS | 18 808 kB (~18.4 MB) | 5 232 kB (~5.1 MB) |
| VmHWM | 23 392 kB | 6 176 kB |
| Threads | 45 | 25 |
| Docker MemUsage | 15.19 MiB | 3.72 MiB |

### After stress mixed 256×30 s

| | Go | Rust |
|--|-----|------|
| VmRSS | 39 856 kB (~38.9 MB) | 3 932 kB (~3.8 MB) |
| VmHWM | 63 372 kB | 14 248 kB |
| Threads | 191 | 30 |
| Docker MemUsage | 42.78 MiB | 4.64 MiB |

Rust stays **~5–10× lower RSS** under load, returns to its idle footprint after
stress, and grows threads far less than Go (30 vs 191 at peak).

---

## Sequential latency (`sentinel-bench latency`)

Only HTTP 200 counted. Values in milliseconds.

| Endpoint | Go avg / p50 / p95 | Rust avg / p50 / p95 |
|----------|--------------------|----------------------|
| `/api/health` | 0.16 / 0.15 / 0.19 | **0.12 / 0.12 / 0.14** |
| `/api/version` | 0.14 / 0.13 / 0.18 | **0.10 / 0.09 / 0.13** |
| `/api/cpu/current` | 0.23 / 0.22 / 0.27 | **0.10 / 0.10 / 0.15** |
| `/api/memory/current` | 0.22 / 0.20 / 0.27 | **0.12 / 0.11 / 0.18** |
| `/api/cpu/history` | 0.25 / 0.22 / 0.36 | **0.19 / 0.19 / 0.25** |
| `/api/memory/history` | 0.25 / 0.24 / 0.30 | **0.19 / 0.17 / 0.23** |

**Rust wins every sequential latency row** (roughly 1.3–2× lower p50).

---

## Concurrent throughput (`sentinel-bench load`)

Duration 8 s per cell; concurrencies 1 / 10 / 32; warmup 20. Error rate **0%** on both for all cells.

| Endpoint | c | Go RPS (p50 ms) | Rust RPS (p50 ms) |
|----------|---|-----------------|-------------------|
| health | 1 | 7 040 (0.14) | **9 953 (0.09)** |
| health | 10 | 25 700 (0.36) | **41 052 (0.23)** |
| health | 32 | 41 981 (0.70) | **57 336 (0.52)** |
| cpu/current | 1 | 4 590 (0.21) | **10 240 (0.09)** |
| cpu/current | 10 | 19 475 (0.47) | **39 084 (0.24)** |
| cpu/current | 32 | 24 652 (1.12) | **45 969 (0.66)** |
| memory/current | 1 | 5 023 (0.19) | **10 895 (0.09)** |
| memory/current | 10 | 20 097 (0.45) | **39 703 (0.24)** |
| memory/current | 32 | 24 599 (1.12) | **50 647 (0.59)** |
| cpu/history | 1 | 4 254 (0.23) | **6 382 (0.15)** |
| cpu/history | 10 | 8 592 (0.72) | **13 980 (0.68)** |
| cpu/history | 32 | 6 401 (3.58) | **14 143 (2.22)** |

**Notes**

- **Rust wins every cell this time**, including `memory/current` c=32 (50 647 vs
  24 599 RPS, **+106%**) — the one cell the earlier draft lost. The cached host
  memory snapshot removed the per-request `/proc/meminfo` read that was
  serializing that endpoint.
- `cpu/history` c=32: Rust 14 143 vs Go 6 401 RPS (**+121%**). Go's history RPS
  actually *drops* from c=10 to c=32 (8 592 → 6 401) under lock pressure; Rust
  holds throughput as concurrency climbs.

---

## Stress (`sentinel-bench stress`)

Pass criteria: error% ≤ 1%, mid-run health probes OK, post-stress `/api/health` = 200.

### Mixed — peak 256, 30 s

| | Go | Rust |
|--|-----|------|
| Result | **PASS** | **PASS** |
| OK requests | 747 593 | **1 244 173** |
| RPS | 24 821 | **41 393 (+67%)** |
| p50 / p95 / p99 | 7.02 / 35.2 / 55.6 ms | **3.76 / 23.5 / 28.4 ms** |
| max | 181 ms | **62 ms** |
| Errors | 0% | 0% |
| Health probe fails | 0 | 0 |

Both implementations survive stress cleanly. Rust delivers **+67% mixed
throughput**, roughly **2× tighter p99**, a **~3× lower max**, and far smaller
memory/thread growth.

---

## Bottom line

| Dimension | Winner |
|-----------|--------|
| Image / binary size | **Rust** (−16% image, −44% binary) |
| Idle & stress RSS | **Rust** (~3× idle, ~10× under stress) |
| Cold start | **Rust** (~291 vs ~313 ms, tighter spread) |
| Sequential latency | **Rust** (every endpoint) |
| Load grid RPS | **Rust** (every cell) |
| Stress mixed RPS + p99 | **Rust** (+67% RPS, ~2× lower p99) |
| Stress survival | **Both PASS** (0% errors) |

For Coolify's always-on sidecar, **Rust is the better default across every axis
measured**: smaller footprint, dramatically lower memory under load, faster cold
start, and stronger HTTP performance under `sentinel-bench` load and stress.

---

## How this run was produced

```bash
cargo build -p sentinel-bench --release
docker build -t sentinel:rust .
docker pull coollabsio/sentinel:latest

# cold start: n=5 create→health for each image (see BENCHMARK.md §4.2)

# steady state (collector on, socket mounted RO), warm ≥20 s, then:
./target/release/sentinel-bench latency --base http://127.0.0.1:18888 --token "$TOKEN"   # Go
./target/release/sentinel-bench latency --base http://127.0.0.1:18889 --token "$TOKEN"   # Rust
./target/release/sentinel-bench load    --base … --duration 8 --concurrency 1,10,32 --warmup 20
./target/release/sentinel-bench stress  --base … --profile mixed --concurrency 256 --duration 30
```

## Caveats

- Numbers are **comparative on one host**, not SLOs or multi-tenant capacity.
- Go is the current release (0.0.22); Rust is this branch (1.0.0) — same-method,
  not same-source-version.
- LXC `/proc/meminfo` via lxcfs is slower than bare-metal procfs, which inflates
  the `memory/current` gain somewhat; the architectural win (no per-request
  meminfo read) holds regardless.
- Push is intentionally blackholed; not part of the score.
- Client is async Rust (`reqwest`); do not mix with old Python-thread numbers
  without re-running both sides.
