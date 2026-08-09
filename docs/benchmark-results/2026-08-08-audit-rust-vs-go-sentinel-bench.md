# Benchmark results — 2026-08-08 (post-audit Rust vs Go)

Re-run after the data-accuracy / throughput audit fixes (reader/writer SQLite
split, sanitized container-id write path, collector `spawn_blocking` writes,
precomputed auth header, single push timestamp). Compares the **current Rust
build with those changes** against the Go release, on the same host, same day,
following `BENCHMARK.md`.

## System configuration
```
date_utc=2026-08-08T19:35:39Z
hostname=coder
uname=Linux 7.0.2-3-pve x86_64
os=Debian GNU/Linux 13 (trixie)
arch=x86_64
virt=lxc
cpu_model=AMD Ryzen 7 3700X 8-Core Processor
cpu_logical=8
cpu_online=1,4-5,7-9,11-12
mem_total=10.00 GiB (10485760 kB)
mem_available=6.53 GiB (6848347 kB)
loadavg=1.92 1.58 1.62
cgroup_v2=true
cgroup_cpu_max=max 100000
cgroup_memory_max=max
docker_server=29.7.2
docker_info=driver=overlayfs cgroup_driver=systemd cgroup_version=2 ncpu=8 mem_total=10737418240
harness=sentinel-bench 0.0.22
```
Note: shared LXC host with a running `coolify-sentinel` (0.0.21) and other
containers; loadavg ~1.9 during the run. Treat absolutes as noisy; the Go/Rust
comparison is same-host, back-to-back.

## Environment
- Method: BENCHMARK.md + sentinel-bench (base git 9e71fbb + uncommitted audit fixes)
- Agent env: COLLECTOR_ENABLED=true, refresh 5s, push blackhole (127.0.0.1:9), docker.sock ro
- Ports: Go 18888, Rust 18889

## Candidates
| Label | Image | ID | /api/version | Notes |
|-------|-------|----|--------------|-------|
| Go   | `coollabsio/sentinel:latest` | 275644b8fb14 | 0.0.22 | release |
| Rust | `sentinel:rust-audit` | 56532362a4db | 0.0.22-audit | branch `go-to-rust-duckdb-migration` + audit fixes |

## Size
| Candidate | Image bytes | Binary bytes |
|-----------|-------------|--------------|
| Go   | 13 351 554 (~12.7 MiB) | 17 585 816 (~16.8 MiB) |
| Rust | 11 214 191 (~10.7 MiB) | 9 841 104 (~9.4 MiB) |

## Cold start (ms, n=5)
| Candidate | min | avg | med | max | raw |
|-----------|-----|-----|-----|-----|-----|
| Go   | 295 | 307.4 | 305 | 320 | 313 320 295 305 304 |
| Rust | 299 | 318.6 | 319 | 338 | 305 299 332 319 338 |

Within run-to-run noise (sample ranges overlap; ~290 ms is the Docker
container-creation floor). The audit added one read-only SQLite connection open
at startup — microsecond cost, not visible above the jitter.

## Memory idle (after ≥20 s warm, 5 samples)
| Candidate | VmRSS | VmHWM | Threads | docker MemUsage |
|-----------|-------|-------|---------|-----------------|
| Go   | ~13.0 MB (12928–13348 kB) | ~13.0 MB | 13 | ~13.5–14.9 MiB |
| Rust | **4.62 MB** (flat 4620 kB) | 4.62 MB | 10 | ~5.7–6.7 MiB |

## Memory post-stress (mixed 256×30 s)
| Candidate | VmRSS | VmHWM | Threads | docker MemUsage |
|-----------|-------|-------|---------|-----------------|
| Go   | 33 444 kB (~32.7 MB) | 52 872 kB | **126** | 37.1 MiB |
| Rust | **5 320 kB (~5.2 MB)** | 15 004 kB | **12** | 7.2 MiB |

Go spikes to 126 OS threads and ~33 MB RSS under load; Rust stays at 12 threads
and returns to ~5 MB. No leak or thread pile on either.

## Sequential latency (ms)
| Endpoint | Go avg / p99 | Rust avg / p99 |
|----------|--------------|----------------|
| /api/health          | 0.19 / 0.28 | **0.10 / 0.12** |
| /api/version         | 0.18 / 0.42 | **0.09 / 0.12** |
| /api/cpu/current     | 0.24 / 0.38 | **0.11 / 0.14** |
| /api/memory/current  | 0.21 / 0.33 | **0.14 / 0.20** |
| /api/cpu/history     | 0.23 / 0.42 | **0.16 / 0.46** |
| /api/memory/history  | 0.26 / 0.30 | **0.14 / 0.22** |

All ok=80/80 (or 40/40 for history), 0 failures. Rust ~2× lower on the
constant-time endpoints.

## Concurrent throughput (RPS, err 0.00% everywhere)
| Endpoint | c | Go RPS / p99 | Rust RPS / p99 |
|----------|---|--------------|----------------|
| /api/health         | 1  | 7 300 / 0.23  | **11 078 / 0.14** |
| /api/health         | 10 | 27 487 / 0.88 | **37 356 / 0.61** |
| /api/health         | 32 | 40 751 / 2.36 | **58 248 / 1.39** |
| /api/cpu/current    | 1  | 4 674 / 0.36  | **10 824 / 0.15** |
| /api/cpu/current    | 10 | 19 874 / 1.23 | **38 877 / 0.58** |
| /api/cpu/current    | 32 | 27 112 / 3.68 | **50 403 / 1.53** |
| /api/memory/current | 1  | 4 805 / 0.44  | **8 219 / 0.19** |
| /api/memory/current | 10 | 19 659 / 1.30 | **22 007 / 0.85** |
| /api/memory/current | 32 | **26 553 / 3.71** | 22 420 / 2.40 |
| /api/cpu/history    | 1  | 4 072 / 0.45  | **6 202 / 0.26** |
| /api/cpu/history    | 10 | 8 734 / 3.86  | **14 084 / 1.46** |
| /api/cpu/history    | 32 | 6 496 / 16.27 | **14 334 / 6.80** |

Highlights:
- **`cpu/history` c=32: 6 496 → 14 334 RPS (+121%), p99 16.3 → 6.8 ms.** This is
  the endpoint the reader/writer split targeted — reads no longer serialize
  behind the collector's writes. Go's history RPS actually *drops* from c=10 to
  c=32 (8 734 → 6 496) under lock pressure; Rust holds/climbs.
- **One regression vs Go:** `memory/current` at c=32 (Rust 22 420 vs Go 26 553).
  This endpoint holds the shared warm `HostSampler` behind a `tokio::Mutex` and
  runs a blocking `sysinfo` memory refresh on the async path — the deferred
  audit finding #7. It saturates (~22 k flat from c=10→c=32) while Go's
  fresh-per-request sampling scales. Fix candidate: move the refresh to
  `spawn_blocking` or use a small reader pool of samplers.

## Stress — mixed 256×30 s
| Candidate | RPS | p50 | p95 | p99 | max | err% | health probes | result |
|-----------|-----|-----|-----|-----|-----|------|---------------|--------|
| Go   | 25 500 | 6.66 | 35.61 | 57.84 | 212.3 | 0.00 | 0 fail | PASS |
| Rust | **35 607** | **2.36** | **17.73** | **19.83** | **73.7** | 0.00 | 0 fail | PASS |

Rust +40% RPS, p99 ~2.9× better, max ~2.9× better. Both PASS (exit 0). Total
requests over the window: Go 767 481, Rust 1 069 024.

## Notes
- Push blackholed; expected periodic push-failure log noise on both (interval
  3600 s, so effectively none during the window).
- The Rust stress RPS here (35.6 k) is a touch below the earlier same-day
  baseline (~40 k) — attributable to higher host load (loadavg ~1.9 with the
  production `coolify-sentinel` + other containers active), not a code
  regression; the Go number moved down proportionally too.
- Net: the audit changes preserved Rust's size/memory/thread advantages and
  **materially improved history-read throughput** (the split's goal) with no
  correctness or stability regressions. The lone soft spot is `memory/current`
  under high concurrency (sampler mutex), a known/documented deferred item.
