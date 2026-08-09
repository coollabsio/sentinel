# Benchmark results index

Dated runs go here. Spec: [../../BENCHMARK.md](../../BENCHMARK.md).  
Harness: `cargo build -p sentinel-bench --release` → `./target/release/sentinel-bench`.

Every results file must include a **System configuration** block (`./target/release/sentinel-bench sys`).

| Date | File | Notes |
|------|------|-------|
| 2026-08-09 | [2026-08-09-go-vs-rust-sentinel-bench.md](2026-08-09-go-vs-rust-sentinel-bench.md) | Canonical Go vs Rust run — size/cold-start/memory/latency/load/stress (`sentinel-bench` 1.0.0) |
