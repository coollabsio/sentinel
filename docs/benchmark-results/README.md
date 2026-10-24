# Benchmark results index

Dated runs go here. Spec: [../../BENCHMARK.md](../../BENCHMARK.md).  
Harness: `cargo build -p sentinel-bench --release` → `./target/release/sentinel-bench`.

Every results file must include a **System configuration** block (`./target/release/sentinel-bench sys`).

| Date | File | Notes |
|------|------|-------|
| 2026-08-09 | [2026-08-09-go-vs-rust-sentinel-bench.md](2026-08-09-go-vs-rust-sentinel-bench.md) | Canonical Go vs Rust run — size/cold-start/memory/latency/load/stress (`sentinel-bench` 1.0.0) |
| 2026-08-09 | [2026-08-09-storage-metrics.md](2026-08-09-storage-metrics.md) | Storage-metrics feature — du-walk/sampling/store micro-bench (§4.9) + disk endpoint latency/stress |
| 2026-10-24 | [2026-10-24-history-bucket-ms.md](2026-10-24-history-bucket-ms.md) | History `bucket_ms` — response size and latency, raw vs bucketed, on a live-data copy |
| 2026-10-24 | [2026-10-24-container-tables-clustered.md](2026-10-24-container-tables-clustered.md) | Container tables clustered on `(container_id, time)` — history latency, store ops, one-time migration cost |
