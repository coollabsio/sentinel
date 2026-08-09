# Benchmark results — cached memory and bounded history (2026-08-09)

## Executive summary

The optimized Rust build was compared with the unmodified Rust baseline at commit `70480f6` and Go Sentinel `0.0.21`. All timed HTTP runs used the same host, token, collector settings, blackhole push endpoint, and `sentinel-bench` 1.0.0 harness.

The cached memory snapshot removed the only major current-metric bottleneck: `/api/memory/current` at concurrency 32 rose from **2,539 to 97,581 RPS (38.4x)** and p99 fell from **16.59 to 1.05 ms (-93.7%)**. In the standard mixed 256-concurrency stress test, the optimized Rust build rose from **11,259 to 107,119 RPS (9.51x)** and p99 fell from **76.26 to 7.96 ms (-89.6%)**. It also exceeded Go by **3.44x** in mixed-stress throughput with p99 **81.4% lower**.

With a retention-shaped 10,740-row history database, the eight-permit admission bound improved CPU-history throughput by **4.9%**, reduced p99 by **43.9%**, reduced peak RSS by **20.4%**, and limited threads from **74 to 17**.

## System configuration

```text
=== System configuration ===
date_utc=2026-08-09T06:21:13Z
hostname=coder
uname=Linux 7.0.2-3-pve x86_64
os=Debian GNU/Linux 13 (trixie)
arch=x86_64
virt=lxc
cpu_model=AMD Ryzen 7 3700X 8-Core Processor
cpu_logical=8
cpu_online=1,4-5,7-9,11-12
mem_total=10.00 GiB (10485760 kB)
mem_available=6.82 GiB (7155325 kB)
loadavg=2.53 2.06 1.89
cgroup_v2=true
cgroup_cpu_max=max 100000
cgroup_memory_max=max
docker_server=29.7.2
docker_info=driver=overlayfs cgroup_driver=systemd cgroup_version=2 ncpu=8 mem_total=10737418240
harness=sentinel-bench 1.0.0
============================
```

The host load varied during the sequential runs. Rust-after started at load average 4.43 and Go at 13.38, so small differences in already-fast endpoints should be treated as noise. The bottleneck-sized changes are much larger than this variability.

## Candidates and method

| Candidate | Version | Identity | Execution |
|---|---:|---|---|
| Rust before | 1.0.0 | commit `70480f6`; SHA-256 `1809cb57…` | local release process, port 18887 |
| Rust after | 1.0.0 | working tree after this optimization; SHA-256 `49d0d1af…` | local release process, port 18889 |
| Go | 0.0.21 | `coollabsio/sentinel:0.0.21`, image `sha256:389996c7…` | Docker, port 18888 |

Standard suite configuration:

- `COLLECTOR_ENABLED=true`
- `COLLECTOR_REFRESH_RATE_SECONDS=5`
- `PUSH_INTERVAL_SECONDS=3600`
- `PUSH_ENDPOINT=http://127.0.0.1:9`
- `DEBUG=false`
- 15-second warm-up
- load grid: concurrency 1, 10, and 32; 8 seconds per cell
- mixed stress: concurrency 256 for 30 seconds
- all candidates used a fresh empty metrics database for the standard suite

The Rust candidates ran directly while Go used Docker port forwarding, matching the earlier local comparison but making absolute Rust-vs-Go HTTP and cold-start figures less strict than the Rust-before/Rust-after A/B. The two Rust builds are directly comparable.

## Static size

| Candidate | Binary bytes | Difference from Rust before |
|---|---:|---:|
| Rust before | 9,685,096 | — |
| Rust after | 9,706,344 | +21,248 (+0.22%) |
| Go 0.0.21 | 17,621,784 | +81.6% vs Rust after |

The optimized Rust binary remains **44.9% smaller** than Go.

## Cold start (milliseconds, n=5)

| Candidate | Samples | Min | Average | Median | Max |
|---|---|---:|---:|---:|---:|
| Rust before | 26, 29, 27, 27, 26 | 26 | 27.0 | 27 | 29 |
| Rust after | 27, 29, 25, 25, 25 | 25 | 26.2 | 25 | 29 |
| Go 0.0.21 | 284, 268, 266, 282, 284 | 266 | 276.8 | 282 | 284 |

The memory refresher did not regress Rust startup. Go includes Docker container creation and is therefore contextual rather than a process-only comparison.

## Idle process resources

Measured after 15 seconds with collector enabled:

| Candidate | VmRSS | VmHWM | Threads |
|---|---:|---:|---:|
| Rust before | 9,448 KiB | 9,448 KiB | 10 |
| Rust after | 9,616 KiB | 9,616 KiB | 10 |
| Go 0.0.21 | 11,692 KiB | 11,692 KiB | 11 |

Rust-after uses 168 KiB more than Rust-before (+1.8%), while remaining 2,076 KiB below Go (-17.8%).

## Sequential latency

| Endpoint | Rust before avg | Rust after avg | Go avg | After vs before | After vs Go |
|---|---:|---:|---:|---:|---:|
| `/api/health` | 0.06 ms | 0.05 ms | 0.15 ms | -16.7% | -66.7% |
| `/api/version` | 0.06 ms | 0.05 ms | 0.14 ms | -16.7% | -64.3% |
| `/api/cpu/current` | 0.06 ms | 0.05 ms | 0.23 ms | -16.7% | -78.3% |
| `/api/memory/current` | 0.43 ms | **0.05 ms** | 0.20 ms | **-88.4%** | **-75.0%** |
| `/api/cpu/history` | 0.08 ms | 0.08 ms | 0.23 ms | unchanged | -65.2% |
| `/api/memory/history` | 0.08 ms | 0.08 ms | 0.21 ms | unchanged | -61.9% |

All sequential requests returned HTTP 200.

## Concurrent throughput at concurrency 32

| Endpoint | Rust before RPS | Rust after RPS | Go RPS | After/before | After/Go |
|---|---:|---:|---:|---:|---:|
| `/api/health` | 94,984 | 95,568 | 42,096 | 1.01x | 2.27x |
| `/api/cpu/current` | 84,151 | 86,312 | 26,420 | 1.03x | 3.27x |
| `/api/memory/current` | 2,539 | **97,581** | 26,487 | **38.44x** | **3.68x** |
| `/api/cpu/history` | 45,672 | 46,284 | 7,110 | 1.01x | 6.51x |

### Concurrency scaling for `/api/memory/current`

| Concurrency | Rust before RPS / p99 | Rust after RPS / p99 | Go RPS / p99 |
|---:|---:|---:|---:|
| 1 | 2,231 / 0.65 ms | 21,050 / 0.08 ms | 5,092 / 0.40 ms |
| 10 | 2,505 / 5.81 ms | 67,512 / 0.39 ms | 19,853 / 1.28 ms |
| 32 | 2,539 / 16.59 ms | 97,581 / 1.05 ms | 26,487 / 3.72 ms |

The baseline saturates near 2.5k RPS regardless of concurrency because every request serially refreshes `/proc/meminfo`. The optimized route scales like the in-memory health route.

All load-grid requests succeeded; error rate was **0.00%** for every candidate and cell.

## Mixed stress: concurrency 256, 30 seconds

| Metric | Rust before | Rust after | Go 0.0.21 |
|---|---:|---:|---:|
| Requests | 338,448 | **3,218,004** | 938,248 |
| Throughput | 11,259 RPS | **107,119 RPS** | 31,139 RPS |
| Average latency | 22.71 ms | **2.43 ms** | 9.09 ms |
| P50 | **0.11 ms** | 2.03 ms | 6.18 ms |
| P95 | 60.03 ms | **5.43 ms** | 27.00 ms |
| P99 | 76.26 ms | **7.96 ms** | 42.83 ms |
| Max | 205.23 ms | **28.84 ms** | 150.32 ms |
| Errors | 0% | 0% | 0% |
| Health probe failures | 0 | 0 | 0 |
| Result | PASS | PASS | PASS |

Rust-after versus Rust-before:

- **9.51x throughput**
- **89.3% lower average latency**
- **91.0% lower p95**
- **89.6% lower p99**

Rust-after versus Go:

- **3.44x throughput**
- **73.3% lower average latency**
- **79.9% lower p95**
- **81.4% lower p99**

The baseline's lower p50 is an artifact of the weighted mix: cheap routes complete immediately while memory requests queue behind `/proc/meminfo`. Rust-after has a much tighter distribution and radically better average/tail behavior.

## Retention-shaped history test

To test the semaphore under meaningful SQLite work, each Rust build received an identical seven-day, retention-shaped database with 10,740 CPU rows and 10,740 memory rows: one-minute rows for older history and five-second rows for the latest hour. Collector writes were disabled during this isolated test. The grid used concurrency 64 for eight seconds per endpoint.

### CPU full-history result

| Metric | Rust before | Rust after | Change |
|---|---:|---:|---:|
| Throughput | 417.6 RPS | 438.2 RPS | **+4.9%** |
| Average latency | 154.70 ms | 147.38 ms | **-4.7%** |
| P50 | 155.00 ms | 147.63 ms | **-4.8%** |
| P95 | 164.53 ms | 159.12 ms | **-3.3%** |
| P99 | 301.50 ms | 169.10 ms | **-43.9%** |
| Max | 324.98 ms | 180.71 ms | **-44.4%** |
| Errors | 0% | 0% | unchanged |

### Resource containment after the realistic load grid

| Metric | Rust before | Rust after | Change |
|---|---:|---:|---:|
| VmRSS / VmHWM | 42,220 KiB | 33,588 KiB | **-20.4%** |
| Threads | 74 | 17 | **-77.0%** |
| Idle VmRSS for this run | 9,908 KiB | 9,916 KiB | effectively unchanged |

The permit is released immediately after `spawn_blocking` completes, before row formatting and JSON serialization. This preserves CPU parallelism outside SQLite while preventing blocking-pool thread growth behind the store's single reader mutex.

## Implementation conclusions

1. **Cache memory only, at 500 ms cadence.** This preserves CPU-current semantics while eliminating request-driven `/proc/meminfo` reads.
2. **Limit history/stats DB admission to eight permits.** Eight was the best balance in the earlier permit sweep and again improved throughput, tail latency, RSS, and threads with realistic data.
3. **Do not truncate history responses in this change.** A hard row cap could silently break existing Coolify date-range behavior. Admission control contains concurrency without changing the wire contract.
4. **Do not add a history response cache yet.** Default range keys change each second; key bucketing and invalidation would add complexity before evidence justifies it.
5. **Do not change SQLite transactions/cache or allocator.** Earlier verification found no meaningful gain from those changes.

## Caveats

- Go is version 0.0.21 while Rust is 1.0.0, so this is not same-version source parity.
- The host is LXC; `/proc/meminfo` is supplied by lxcfs and is much slower than a normal procfs read. The architectural win remains, but the 38x endpoint multiplier will be smaller on bare metal.
- Standard-suite history tables were initially empty for all candidates. The separate retention-shaped test is the meaningful history-path comparison.
- Benchmark candidates ran sequentially, but host load was not perfectly constant. Repeated trials on an otherwise idle bare-metal host are recommended before publishing absolute capacity claims.
