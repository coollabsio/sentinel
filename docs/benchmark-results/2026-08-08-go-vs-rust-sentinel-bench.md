# Sentinel Go vs Rust Benchmark

**Method:** [BENCHMARK.md](../../BENCHMARK.md) + `sentinel-bench` 0.0.22
**Repo git:** `f0c41e5`  
**Agent env:** `COLLECTOR_ENABLED=true`, refresh 5s, Docker socket mounted RO, push → `http://127.0.0.1:9` (blackhole)

## System configuration

Captured on the bench host (required for every run — see BENCHMARK.md §2.1):

```
date_utc=2026-08-08T17:56:39Z
hostname=coder
uname=Linux 7.0.2-3-pve x86_64
os=Debian GNU/Linux 13 (trixie)
arch=x86_64
virt=lxc
cpu_model=AMD Ryzen 7 3700X 8-Core Processor
cpu_logical=8
cpu_online=1,4-5,7-9,11-12
mem_total=10.00 GiB (10485760 kB)
mem_available=6.63 GiB (6946825 kB)   # at later sample; varies during stress
loadavg=2.01 6.11 5.73                # sample; elevated under load
cgroup_v2=true
cgroup_cpu_max=max 100000
cgroup_memory_max=max
docker_server=29.7.2
docker_info=driver=overlayfs cgroup_driver=systemd cgroup_version=2 ncpu=8 mem_total=10737418240
harness=sentinel-bench 0.0.22
```

**Reading this host:** Proxmox **LXC** guest — 8 logical CPUs visible (`nproc=8`; host CPU has more threads offline in the guest), **10 GiB** RAM cap, cgroup v2, Docker 29.7.2. Absolute RPS is for this machine only; re-capture with `./target/release/sentinel-bench sys` on every new results file.

## Candidates

| Label | Image | ID (short) | `/api/version` |
|-------|-------|------------|----------------|
| **Go** | `coollabsio/sentinel:latest` | `275644b8fb14` | 0.0.22 |
| **Rust** | `sentinel:rust` (this branch) | `a0f082125152` | 0.0.22 |

---

## Size

| Metric | Go | Rust | Rust vs Go |
|--------|-----|------|------------|
| Docker image | 13 351 554 B (12.73 MiB) | 11 208 346 B (10.69 MiB) | **−16%** |
| `/app/sentinel` binary | 17 585 816 B (16.77 MiB) | 9 820 560 B (9.37 MiB) | **−44%** |

---

## Cold start

**Definition:** `docker run -d` return → first successful `GET /api/health` (n=5, destroy between trials).

| | Go | Rust |
|--|-----|------|
| trials (ms) | 361, 291, 295, 326, 307 | 314, 296, 303, 287, 303 |
| min / avg / med / max | 291 / **316** / 307 / 361 | 287 / **301** / 303 / 314 |
| | | **Rust ~5% faster** (≈ equal) |

> Earlier Rust builds slept 200 ms warming CPU before bind (~590 ms avg). That warm-up was removed; both stacks now open health in ~300 ms on this host.

---

## Memory (process `VmRSS` primary)

### Idle (after ≥15 s warm-up, 5 samples)

| | Go | Rust |
|--|-----|------|
| VmRSS range | 12 992–13 396 kB | 4 564–4 776 kB |
| VmRSS avg | **~12.9 MB** | **~4.6 MB (−64%)** |
| Threads | 13 | 9 |
| Docker MemUsage (typical) | ~8–9 MiB | ~2–4 MiB |

### After load grid (`sentinel-bench load`)

| | Go | Rust |
|--|-----|------|
| VmRSS | 18 312 kB (~17.9 MB) | 5 264 kB (~5.1 MB) |
| VmHWM | 23 144 kB | 6 216 kB |
| Threads | 44 | 45 |
| Docker MemUsage | 14.67 MiB | 3.98 MiB |

### After stress mixed 256×30 s

| | Go | Rust |
|--|-----|------|
| VmRSS | 34 776 kB (~34.0 MB) | 6 028 kB (~5.9 MB) |
| VmHWM | 57 960 kB | 13 528 kB |
| Threads | 167 | 78 |
| Docker MemUsage | 34.73 MiB | 6.62 MiB |

### Final (after ramp + burst as well)

| | Go | Rust |
|--|-----|------|
| VmRSS | 43 484 kB (~42.5 MB) | 6 796 kB (~6.6 MB) |
| VmHWM | 93 128 kB | 24 652 kB |
| Threads | 184 | 62 |
| Docker MemUsage | 43.32 MiB | 7.44 MiB |

Rust stays **~5–7× lower RSS** under heavy stress and grows threads far less than Go.

---

## Sequential latency (`sentinel-bench latency`)

Only HTTP 200 counted. Values in milliseconds.

| Endpoint | Go avg / p50 / p95 | Rust avg / p50 / p95 |
|----------|--------------------|----------------------|
| `/api/health` | 0.18 / 0.16 / 0.23 | **0.15 / 0.10 / 0.16** |
| `/api/version` | 0.22 / 0.20 / 0.29 | **0.11 / 0.10 / 0.16** |
| `/api/cpu/current` | 0.32 / 0.26 / 0.88 | **0.12 / 0.11 / 0.16** |
| `/api/memory/current` | 0.25 / 0.24 / 0.32 | **0.16 / 0.15 / 0.21** |
| `/api/cpu/history` | 0.28 / 0.24 / 0.52 | **0.16 / 0.15 / 0.19** |
| `/api/memory/history` | 0.32 / 0.27 / 0.56 | **0.19 / 0.18 / 0.24** |

**Rust wins every sequential latency row** (often ~1.5–2× lower p50).

---

## Concurrent throughput (`sentinel-bench load`)

Duration 8 s per cell; concurrencies 1 / 10 / 32; warmup 20. Error rate **0%** on both for all cells.

| Endpoint | c | Go RPS (p50 ms) | Rust RPS (p50 ms) |
|----------|---|-----------------|-------------------|
| health | 1 | 7 231 (0.13) | **10 068 (0.10)** |
| health | 10 | 23 971 (0.37) | **40 435 (0.23)** |
| health | 32 | 37 973 (0.78) | **55 396 (0.55)** |
| cpu/current | 1 | 4 660 (0.20) | **9 490 (0.10)** |
| cpu/current | 10 | 16 125 (0.55) | **36 452 (0.25)** |
| cpu/current | 32 | 26 821 (1.05) | **45 575 (0.67)** |
| memory/current | 1 | 4 512 (0.20) | **8 339 (0.11)** |
| memory/current | 10 | 20 046 (0.45) | **21 008 (0.46)** |
| memory/current | 32 | **25 565 (1.08)** | 22 137 (1.40) |
| cpu/history | 1 | 4 048 (0.23) | **6 138 (0.14)** |
| cpu/history | 10 | 8 724 (0.70) | **12 633 (0.71)** |
| cpu/history | 32 | 6 575 (3.37) | **13 823 (2.25)** |

**Notes**

- Rust is substantially faster on health / cpu/current / cpu/history.
- `memory/current` at c=32 is the one cell where Go edged RPS (likely sysinfo / host memory refresh cost under contention).
- Absolute RPS is higher than the older Python-thread harness (async `reqwest` client) — compare only runs that use the same `sentinel-bench` binary.

---

## Stress (`sentinel-bench stress`)

Pass criteria: error% ≤ 1%, mid-run health probes OK, post-stress `/api/health` = 200.

### Mixed — peak 256, 30 s

| | Go | Rust |
|--|-----|------|
| Result | **PASS** | **PASS** |
| OK requests | 791 472 | **1 208 035** |
| RPS | 26 277 | **40 232 (+53%)** |
| p50 / p95 / p99 | 6.74 / 33.7 / 54.2 ms | **2.41 / 15.5 / 17.9 ms** |
| max | 155 ms | 64 ms |
| Errors | 0% | 0% |
| Health probe fails | 0 | 0 |

### Ramp — peak 256, 20 s

| | Go | Rust |
|--|-----|------|
| Result | **PASS** | **PASS** |
| RPS | 13 269 | **22 243** |
| p50 / p99 | 6.39 / 51.1 ms | **4.39 / 21.8 ms** |
| Errors | 0% | 0% |

### Burst — peak 512, 20 s (2 s on / 2 s quiet)

| | Go | Rust |
|--|-----|------|
| Result | **PASS** | **PASS** |
| RPS | 13 610 | **19 464** |
| p50 / p99 | 8.59 / 131 ms | **1.52 / 44 ms** |
| max | 486 ms | 1119 ms (single spike; p99 still much lower) |
| Errors | 0% | 0% |

Both implementations survive stress cleanly. Rust delivers higher mixed throughput and tighter tail latency, with far smaller memory growth.

---

## Bottom line

| Dimension | Winner |
|-----------|--------|
| Image / binary size | **Rust** (−16% image, −44% binary) |
| Idle & stress RSS | **Rust** (~3× idle, ~5–7× under stress) |
| Cold start | **Tie / slight Rust** (~301 vs ~316 ms) |
| Sequential latency | **Rust** |
| Load grid RPS | **Rust** (most cells; memory/current c=32 exception) |
| Stress mixed RPS + p99 | **Rust** (+53% RPS, much lower p99) |
| Stress survival | **Both PASS** |

For Coolify’s always-on sidecar, **Rust is the better default**: smaller footprint, lower memory under load, equal-or-better cold start, and stronger HTTP performance under `sentinel-bench` load and stress.

---

## How this run was produced

```bash
cargo build -p sentinel-bench --release
docker build -t sentinel:rust .

# cold start: n=5 create→health for each image (see BENCHMARK.md §4.2)

# steady state (collector on, socket mounted), then:
./target/release/sentinel-bench latency --base http://127.0.0.1:18888 --token bench-token-compare
./target/release/sentinel-bench latency --base http://127.0.0.1:18889 --token bench-token-compare
./target/release/sentinel-bench load    --base … --duration 8 --concurrency 1,10,32
./target/release/sentinel-bench stress  --base … --profile mixed --concurrency 256 --duration 30
./target/release/sentinel-bench stress  --base … --profile ramp  --concurrency 256 --duration 20
./target/release/sentinel-bench stress  --base … --profile burst --concurrency 512 --duration 20
```

Raw machine capture for this run: `/tmp/sentinel-bench-run/` (local; not committed).

## Caveats

- Numbers are **comparative on one host**, not SLOs or multi-tenant capacity.
- Push is intentionally broken (blackhole); not part of the score.
- Client is async Rust (`reqwest`); do not mix with old Python-thread numbers without re-running both sides.
- Rust first CPU sample after process start may still be ~0% (by design; no blocking warm-up).
