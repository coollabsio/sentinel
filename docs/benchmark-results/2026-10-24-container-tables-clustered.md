# Benchmark results — 2026-10-24 — clustered container tables

The four per-container tables (`container_{cpu,memory,disk,network}_usage`) move from rowid
tables keyed on `(time, container_id)` with a `(container_id, time)` index to `WITHOUT ROWID`
tables clustered on `(container_id, time)`, plus a `time` index. A container history read was one
random table lookup per row; it is now one range scan.

> One host, one dataset. Not SLOs.

## System configuration
```text
=== System configuration ===
date_utc=2026-10-24T05:16:44Z
hostname=coder
uname=Linux 7.0.14-15-pve x86_64
os=Debian GNU/Linux 13 (trixie)
arch=x86_64
virt=lxc
cpu_model=AMD Ryzen 7 3700X 8-Core Processor
cpu_logical=8
cpu_online=7,9-15
mem_total=10.00 GiB (10485760 kB)
mem_available=4.22 GiB (4429443 kB)
loadavg=5.00 5.65 4.85
cgroup_v2=true
cgroup_cpu_max=max 100000
cgroup_memory_max=max
docker_server=29.7.2
docker_info=driver=overlayfs cgroup_driver=systemd cgroup_version=2 ncpu=16 mem_total=10737418240
harness=sentinel-bench 1.1.3
============================
```

## Environment
- Method: BENCHMARK.md §4.4 + `sentinel-bench latency` (base `947118d`)
- Dataset: copy of a live Sentinel `metrics.sqlite` (661 MB of pages, 49 containers, ~1.2M rows in
  each of the cpu / memory / network container tables), on ZFS (not tmpfs)
- Server: `target/release/sentinel`, `SENTINEL_DEVELOPMENT=true`, `COLLECTOR_ENABLED=false`,
  `STORAGE_ENABLED=false`, `TRAFFIC_ENABLED=false`, push blackhole; reader cache is the default 2 MB
- Before: `947118d` layout. After: this branch, same data after the startup rebuild

## Sequential latency (n=40, avg / p95 ms)
| Endpoint | Before | After |
|---|---|---|
| `/api/container/{id}/cpu/history` | 192.95 / 204.05 | 7.18 / 8.34 |
| `/api/container/{id}/memory/history` | 216.05 / 228.25 | 11.27 / 12.52 |
| `/api/container/{id}/network/history` | 196.60 / 207.59 | 8.33 / 9.57 |
| `/api/container/{id}/disk/history` | 1.00 / 0.62 | 0.50 / 0.56 |
| `/api/containers/current` | 1.41 / 2.91 | 1.03 / 1.34 |

## Store operations (Python `sqlite3`, 8 MB cache, same dataset)
| Operation | Before | After |
|---|---|---|
| container cpu history, one id (28k rows) | 457 ms | 18 ms |
| container memory history, one id | 536 ms | 40 ms |
| latest row per container (49 ids) | 0.17 ms | 0.17 ms |
| downsample one 12 h window (186k rows) | 1173 ms | 1247 ms |
| retention cleanup (141k rows deleted) | 827 ms | 904 ms |
| one collector insert cycle (49 rows) | 9.2 ms | 9.0 ms |

## Migration (one time, at startup)
| Table | Time |
|---|---|
| container_cpu_usage | 6.8 s |
| container_memory_usage | 7.8 s |
| container_network_usage | 6.4 s |
| container_disk_usage | 0.2 s |
| Full API ready after start | 21.5 s |

`/api/health` answered 200 during the rebuild (startup API). Database pages: 661 MB before, 731 MB
after, of which 354 MB are free pages that SQLite reuses for new rows: the live data went from
661 MB to 377 MB.

## Notes
- The rebuild runs one transaction and one WAL checkpoint per table, so it needs free disk for about
  one rebuilt table (~150 MB here). If it fails, the transaction rolls back, the table keeps the old
  layout and its history, and the rebuild runs again on the next start.
- Reading the old table in rowid order is key: `ORDER BY container_id, time` made the copy 7× slower
  (one random lookup per row). Building the `time` index after the copy saved another ~20%.
- Downsample and cleanup are ~6–9% slower (they now go through the `time` index); they run once a day.
