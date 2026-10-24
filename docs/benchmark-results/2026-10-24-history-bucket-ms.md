# Benchmark results — 2026-10-24 — history `bucket_ms`

Feature benchmark of the optional `bucket_ms` param on the metric history endpoints
(`/api/{cpu,memory,disk,load,network}/history`, `/api/container/{id}/{cpu,memory,disk,network}/history`).
Coolify reads history over SSH (`docker exec … curl`) and averaged every raw row in PHP;
with `bucket_ms` Sentinel averages per epoch-aligned window in SQLite and returns ~1000 rows.

> One host, one dataset. Not SLOs. Without `bucket_ms` the SQL is unchanged, so the raw rows
> below are the baseline.

## System configuration
```text
=== System configuration ===
date_utc=2026-10-24T04:28:44Z
hostname=coder
uname=Linux 7.0.14-15-pve x86_64
os=Debian GNU/Linux 13 (trixie)
arch=x86_64
virt=lxc
cpu_model=AMD Ryzen 7 3700X 8-Core Processor
cpu_logical=8
cpu_online=7,9-15
mem_total=10.00 GiB (10485760 kB)
mem_available=2.56 GiB (2684699 kB)
loadavg=2.83 3.21 2.72
cgroup_v2=true
cgroup_cpu_max=max 100000
cgroup_memory_max=max
docker_server=29.7.2
docker_info=driver=overlayfs cgroup_driver=systemd cgroup_version=2 ncpu=16 mem_total=10737418240
harness=sentinel-bench 1.1.3
============================
```

## Environment
- Method: BENCHMARK.md §4.4 + `sentinel-bench latency` (base `947118d` + this branch)
- Dataset: copy of a live Sentinel `metrics.sqlite` (693 MB, 49 containers, 2026-10-17 → 2026-10-23,
  raw 5 s rows for the last 24 h, one-minute rows before that; disk rows predate the 1.1.3 mount
  fix, so 5 mounts per cycle)
- Server: `target/release/sentinel`, `SENTINEL_DEVELOPMENT=true`, `PORT=18899`, `COLLECTOR_ENABLED=false`,
  `STORAGE_ENABLED=false`, `TRAFFIC_ENABLED=false`, push blackhole
- Bucketed rows use `bucket_ms=600000` (10 min, what Coolify sends for a 7-day range)

## Response size (full history)
| Endpoint | Raw rows | Raw bytes | Bucketed rows | Bucketed bytes | Ratio |
|---|---:|---:|---:|---:|---:|
| `/api/cpu/history` | 13044 | 560428 | 941 | 40464 | 13.9× |
| `/api/memory/history` | 13044 | 1630620 | 941 | 121061 | 13.5× |
| `/api/disk/history` | 9385 | 1383899 | 4695 | 708057 | 2.0× |
| `/api/network/history` | 13044 | 912800 | 941 | 75067 | 12.2× |
| `/api/load/history` | 13044 | 844071 | 941 | 75153 | 11.2× |
| `/api/container/{id}/cpu/history` | 13030 | 547261 | 941 | 39523 | 13.8× |
| `/api/container/{id}/memory/history` | 13030 | 1589661 | 941 | 118890 | 13.4× |

Disk is sampled every 300 s, so a 600 s window only halves it. Before retention compacted the
same data (28k rows per series), 7-day memory was 2.1 MB raw vs 45 KB with Coolify's 30 min window.

## Sequential latency (n=40)
| Endpoint | Raw avg / p95 | `bucket_ms=600000` avg / p95 |
|---|---|---|
| `/api/cpu/history` | 6.58 / 7.34 ms | 3.70 / 4.26 ms |
| `/api/memory/history` | 10.37 / 11.86 ms | 7.22 / 8.82 ms |
| `/api/disk/history` | 9.75 / 11.16 ms | 10.58 / 11.03 ms |
| `/api/container/{id}/memory/history` | 27.03 / 31.62 ms | 22.85 / 26.44 ms |

Full output:
```text
=== Sequential latency ===
base=http://127.0.0.1:18899
/api/health                  ok=80   fail=0   avg=   0.05ms  p50=   0.04ms  p95=   0.06ms  p99=   0.14ms  min=   0.04ms  max=   0.46ms
/api/version                 ok=80   fail=0   avg=   0.06ms  p50=   0.05ms  p95=   0.07ms  p99=   0.09ms  min=   0.05ms  max=   0.10ms
/api/cpu/current             ok=80   fail=0   avg=   0.06ms  p50=   0.06ms  p95=   0.08ms  p99=   0.10ms  min=   0.05ms  max=   0.61ms
/api/memory/current          ok=80   fail=0   avg=   0.06ms  p50=   0.05ms  p95=   0.07ms  p99=   0.07ms  min=   0.05ms  max=   0.10ms
/api/cpu/history             ok=40   fail=0   avg=   6.58ms  p50=   6.46ms  p95=   7.34ms  p99=   8.47ms  min=   6.20ms  max=   8.47ms
/api/memory/history          ok=40   fail=0   avg=  10.37ms  p50=  10.25ms  p95=  11.86ms  p99=  12.15ms  min=   9.83ms  max=  12.15ms
/api/disk/current            ok=80   fail=0   avg=   0.11ms  p50=   0.10ms  p95=   0.14ms  p99=   0.18ms  min=   0.09ms  max=   0.24ms
/api/disk/history            ok=40   fail=0   avg=   9.75ms  p50=   9.54ms  p95=  11.16ms  p99=  11.51ms  min=   8.98ms  max=  11.51ms
/api/network/current         ok=80   fail=0   avg=   0.09ms  p50=   0.08ms  p95=   0.12ms  p99=   0.14ms  min=   0.07ms  max=   0.28ms
/api/network/history         ok=40   fail=0   avg=   6.44ms  p50=   6.33ms  p95=   7.01ms  p99=   7.60ms  min=   6.02ms  max=   7.60ms
/api/load/current            ok=80   fail=0   avg=   0.08ms  p50=   0.08ms  p95=   0.10ms  p99=   0.13ms  min=   0.07ms  max=   0.22ms
/api/load/history            ok=40   fail=0   avg=   8.01ms  p50=   7.91ms  p95=   8.80ms  p99=   9.12ms  min=   7.49ms  max=   9.12ms
/api/cpu/history?bucket_ms=600000 ok=40   fail=0   avg=   3.70ms  p50=   3.58ms  p95=   4.26ms  p99=   4.59ms  min=   3.39ms  max=   4.59ms
/api/memory/history?bucket_ms=600000 ok=40   fail=0   avg=   7.22ms  p50=   7.04ms  p95=   8.82ms  p99=   9.69ms  min=   6.70ms  max=   9.69ms
/api/disk/history?bucket_ms=600000 ok=40   fail=0   avg=  10.58ms  p50=  10.60ms  p95=  11.03ms  p99=  11.19ms  min=  10.18ms  max=  11.19ms
/api/summary                 ok=80   fail=0   avg=   0.12ms  p50=   0.12ms  p95=   0.14ms  p99=   0.17ms  min=   0.11ms  max=   0.29ms
/api/containers/current      ok=80   fail=0   avg=   0.82ms  p50=   0.79ms  p95=   0.84ms  p99=   1.76ms  min=   0.75ms  max=   1.78ms
/api/container/{id}/cpu/history ok=40   fail=0   avg=  20.76ms  p50=  20.15ms  p95=  25.16ms  p99=  26.40ms  min=  19.15ms  max=  26.40ms
/api/container/{id}/memory/history ok=40   fail=0   avg=  27.03ms  p50=  26.27ms  p95=  31.62ms  p99=  42.29ms  min=  24.41ms  max=  42.29ms
/api/container/{id}/disk/current ok=60   fail=0   avg=   0.09ms  p50=   0.08ms  p95=   0.10ms  p99=   0.11ms  min=   0.08ms  max=   0.25ms
/api/container/{id}/disk/history ok=40   fail=0   avg=   0.63ms  p50=   0.60ms  p95=   0.76ms  p99=   1.31ms  min=   0.57ms  max=   1.31ms
/api/container/{id}/network/history ok=40   fail=0   avg=  22.35ms  p50=  21.88ms  p95=  25.39ms  p99=  26.19ms  min=  20.57ms  max=  26.19ms
/api/container/{id}/memory/history?bucket_ms=600000 ok=40   fail=0   avg=  22.85ms  p50=  22.56ms  p95=  26.44ms  p99=  27.18ms  min=  20.40ms  max=  27.18ms
```

## SQL only (Python `sqlite3`, median of 7, same dataset before compaction)
| Query | Raw | `bucket_ms=600000` |
|---|---|---|
| cpu_usage | 18.2 ms (28061 rows) | 7.0 ms (1191 rows) |
| container_memory_usage (one id) | 70.3 ms | 44.0 ms |
| container_cpu_usage (one id) | 46.1 ms | 33.2 ms |
| disk_usage | 16.1 ms | 15.1 ms |

The bucketed plan uses the same index plus `USE TEMP B-TREE FOR GROUP BY`; the sort costs less
than the rows it saves, except for disk, where the window is close to the sample interval.

## Notes
- The win is mostly on the client path, not in Sentinel: Coolify moves 13–14× fewer bytes per
  series over SSH and decodes ~1000 rows instead of 13k–28k (PHP decode of 7-day memory was 30 ms).
- Container history stays the slowest read here (20–27 ms): `idx_c*_container_time` is not covering,
  so each row is a table lookup. The clustered container tables fix this; see
  [2026-10-24-container-tables-clustered.md](2026-10-24-container-tables-clustered.md).
- `load` / `stress` modes were not run: their load grid does not include history endpoints.
