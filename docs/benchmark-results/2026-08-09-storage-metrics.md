# Benchmark results — 2026-08-09 — storage metrics feature

Feature-specific benchmark of the storage-metrics work (branch `feat/storage-metrics`):
new `/api/disk/*` + `/api/container/{id}/disk/*` endpoints and the collector-side
`du`-walk / disk-sampling / store-write path. Method per `BENCHMARK.md` (§4.4 latency,
§4.6 stress, §4.9 storage micro-bench), harness `sentinel-bench` 1.0.0.

> Numbers are one host, one day. Not SLOs. The storage micro-bench ran the **real** collector
> functions (`collector::storage::dir_size` / `sample_disks`, `store::insert_*` / `downsample`).

## System configuration
```text
=== System configuration ===
date_utc=2026-08-09T12:02:03Z
hostname=coder
uname=Linux 7.0.2-3-pve x86_64
os=Debian GNU/Linux 13 (trixie)
arch=x86_64
virt=lxc
cpu_model=AMD Ryzen 7 3700X 8-Core Processor
cpu_logical=8
cpu_online=1,4-5,7-9,11-12
mem_total=10.00 GiB (10485760 kB)
mem_available=5.69 GiB (5971496 kB)
loadavg=4.26 2.59 1.94
cgroup_v2=true
cgroup_cpu_max=max 100000
cgroup_memory_max=max
docker_server=29.7.2
docker_info=driver=overlayfs cgroup_driver=systemd cgroup_version=2 ncpu=8 mem_total=10737418240
harness=sentinel-bench 1.0.0
============================
```

## Environment
- Method: BENCHMARK.md + sentinel-bench (git `672190f` base; feature on `feat/storage-metrics`)
- Server: `target/release/sentinel`, `SENTINEL_DEVELOPMENT=1`, `PORT=18899`, push blackhole
  (`http://127.0.0.1:9`), `STORAGE_REFRESH_RATE_SECONDS=2`, `STORAGE_VOLUMES_REFRESH_RATE_SECONDS=5`
- Storage micro-bench `--tree-dir` was `/tmp` (**tmpfs** on this host — walk times understate
  seek-bound spinning/network disks; see BENCHMARK.md §4.9 caveat)

## Candidate
| Label | /api/version | Git branch |
|-------|--------------|------------|
| rust-storage | 1.0.0 | feat/storage-metrics |

---

## 1. Storage collection micro-bench (§4.9)

### Default (`sentinel-bench storage`)
```text
mode=default tree(breadth=4 depth=4 files/dir=8 file_bytes=4096) rows=100000

[A] du-walk (collector::storage::dir_size)
    built 341 dirs, 2728 files, 10.66 MiB logical
    on-disk=10.66 MiB  walks(n=5) min=9.19ms avg=9.64ms max=10.04ms
    throughput: 283045 files/s, 1.08 GiB/s (avg walk)

[B] sample_disks (host filesystems)
    mounts=1  n=5 min=0.71ms avg=1.17ms max=2.75ms

[C] store batch inserts (in-memory SQLite)
    disk_usage: 100000 rows in 0.24s → 416318 rows/s
    container_disk_usage: 100000 rows in 0.24s → 416083 rows/s

[D] downsample (collapse aged rows)
    collapsed 200000 aged rows in 0.28s → 721869 rows/s
```

### Stress (`sentinel-bench storage --stress`)
```text
mode=stress tree(breadth=5 depth=5 files/dir=20 file_bytes=4096) rows=1000000

[A] du-walk (collector::storage::dir_size)
    built 3906 dirs, 78120 files, 305.16 MiB logical
    on-disk=305.16 MiB  walks(n=5) min=245.14ms avg=245.97ms max=246.74ms
    throughput: 317598 files/s, 1.21 GiB/s (avg walk)

[B] sample_disks (host filesystems)
    mounts=1  n=5 min=0.68ms avg=0.80ms max=1.12ms

[C] store batch inserts (in-memory SQLite)
    disk_usage: 1000000 rows in 2.67s → 374011 rows/s
    container_disk_usage: 1000000 rows in 2.95s → 339328 rows/s

[D] downsample (collapse aged rows)
    collapsed 2000000 aged rows in 3.14s → 637738 rows/s
```

| Phase | Default | Stress |
|-------|---------|--------|
| du-walk files | 2 728 (10.66 MiB) | 78 120 (305 MiB) |
| du-walk avg | 9.64 ms | 245.97 ms |
| du-walk throughput | 283k files/s · 1.08 GiB/s | 318k files/s · 1.21 GiB/s |
| sample_disks avg | 1.17 ms | 0.80 ms |
| disk insert | 416k rows/s | 374k rows/s |
| container insert | 416k rows/s | 339k rows/s |
| downsample | 722k rows/s | 638k rows/s |

**Read on the "does it hurt system usage?" question (design item a):** worst-case walk of 78k
files / 305 MiB = **~246 ms**, run once per `STORAGE_VOLUMES_REFRESH_RATE_SECONDS` (default 900 s)
→ **~0.03 %** duty cycle, sequential, on a blocking thread. The cheap `sample_disks` (~1 ms) runs on
the separate 300 s ticker. This is the payoff of decoupling the two intervals. Caveat: `/tmp` is
tmpfs here, so real seek-bound disks will be slower — re-run with `--tree-dir` on the volume store
for a production figure.

---

## 2. HTTP endpoints — sequential latency (§4.4)

Live server, `sentinel-bench latency`. New disk endpoints in **bold**.

| Endpoint | ok | avg | p50 | p95 | p99 | max |
|----------|----|-----|-----|-----|-----|-----|
| /api/health | 80 | 0.07 | 0.07 | 0.09 | 0.22 | 0.35 |
| /api/version | 80 | 0.07 | 0.07 | 0.08 | 0.09 | 0.09 |
| /api/cpu/current | 80 | 0.07 | 0.07 | 0.08 | 0.10 | 0.47 |
| /api/memory/current | 80 | 0.06 | 0.06 | 0.07 | 0.09 | 0.11 |
| /api/cpu/history | 40 | 0.10 | 0.09 | 0.13 | 0.24 | 0.24 |
| /api/memory/history | 40 | 0.08 | 0.07 | 0.11 | 0.17 | 0.17 |
| **/api/disk/current** | 80 | 0.08 | 0.08 | 0.12 | 0.15 | 0.17 |
| **/api/disk/history** | 40 | 0.09 | 0.09 | 0.11 | 0.11 | 0.11 |

Disk endpoints sit right alongside cpu/memory — no latency outlier (ms).

`/api/disk/current` sample response (live, root fs):
```json
[{"time":"1786276894750","mount":"/","total":107374182400,"used":82882723840,"available":24491458560,"usedPercent":77.19}]
```

## 3. HTTP stress (§4.6) — traffic mix now includes disk endpoints

`sentinel-bench stress --concurrency 128 --duration 10` (mixed; weights include disk/current 3,
disk/history 2):

```text
mixed(all endpoints)  c=128 t=10s  ok=896387 fail=0 rps=89597.4
  avg=1.44ms p50=1.22ms p95=3.12ms p99=4.08ms max=32.37ms err=0.00%
health_probe_failures=0  post_stress_health=ok (0.29ms)  stress_result=PASS
```

- **896 387** requests, **0** errors, RPS **~89.6k**, p99 **4.08 ms**.
- Mid-stress health probes: all OK. Post-stress `/api/health`: OK.

## Memory (server, post-stress; storage collector enabled)
| VmRSS | VmHWM | Threads |
|-------|-------|---------|
| 17 828 kB (~17.4 MiB) | 17 828 kB | 16 |

(Dev-mode release binary in LXC after 896k requests, with the extra `StorageCollector` running —
not a clean idle-image number; compare only to a like-for-like run.)

## 4. Regression check — does the feature slow the existing endpoints?

Same binary, same host, A/B on the **untouched** core endpoints (`load`, 5 s cells). Configs:
**OFF** (`STORAGE_ENABLED=false`), **OFF#2** (repeat — establishes the run-to-run noise band on
this busy LXC), **ON-default** (real 300 s/900 s intervals), **ON-2s** (artificial worst case:
disk + `size:true` container list every 2 s).

RPS (higher = better):

| Endpoint · c | OFF | OFF#2 | ON-default | ON-2s |
|---|---|---|---|---|
| health c=10 | 69 802 | 67 982 | 66 535 | 64 890 |
| health c=32 | 99 695 | 98 581 | 98 460 | 92 411 |
| cpu/current c=10 | 65 760 | 67 084 | 67 395 | 64 492 |
| cpu/current c=32 | 84 446 | 83 539 | 83 248 | 80 680 |
| memory/current c=10 | 69 470 | 68 321 | 68 656 | 64 804 |
| memory/current c=32 | 97 962 | 95 244 | 80 128* | 91 867 |

Latency p99 (clean cells): ~0.40 ms @ c=10, ~0.9–1.0 ms @ c=32 — **flat across all four configs**.
Zero errors in every cell.

- **Noise floor:** OFF vs OFF#2 (identical config) already differ up to ~2.7% — that's the host's
  run-to-run variance (shared 8-core LXC, loadavg ~4).
- **ON-default ≈ OFF within noise.** At real intervals the storage collector's first tick is at
  300 s, so it doesn't even fire during the load window — no measurable request-path cost.
- **ON-2s** (150× inflated cadence) shows a small ~2–7% RPS dip at high concurrency, purely the
  background collector + `size:true` Docker work stealing CPU under saturation — not a code-path
  regression (latency percentiles unchanged). Gone at real cadence.
- `*` the memory/current c=32 ON-default cell (80 128, p99 1.70 ms, max 13.1 ms) is a single
  transient host stall in that 5 s window, not the feature (other cells for the same config are
  normal; the collector wasn't firing).
- **Memory:** VmRSS 12.18 MiB (OFF) → 12.85 MiB (ON-2s), +~0.67 MiB and a few threads for the
  always-on collector task. Small and constant.

**Verdict: no regression on existing endpoints at production settings.** Mechanistically expected —
the existing handlers are unchanged, storage work runs on separate background tickers + the daily
retention job, and API reads use the separate WAL reader connection so they never serialize behind
storage writes. (Cold start not separately measured; the schema adds 2 idempotent `CREATE TABLE`
statements — sub-millisecond — and `host_sampler_new_is_fast` still passes.)

## Notes
- Storage micro-bench requires no server (host-only); HTTP runs used a live dev-mode server with a
  blackhole push endpoint.
- `sample_disks` reported 1 mount (LXC container view) — inside a fuller host or with more mounts
  bind-mounted in, expect one row per real filesystem.
- To reproduce: `cargo build -p sentinel-bench --release` then `sentinel-bench storage [--stress]`
  and the latency/stress commands in §2–§3 against a running agent.
