//! Storage-feature micro-benchmark (BENCHMARK.md §4.9).
//!
//! Unlike the HTTP modes, this measures the *collector-side* cost of the
//! storage feature — the part with no HTTP surface and the real "does it hurt
//! system usage?" risk:
//!   1. `du`-walk throughput over a synthetic directory tree (`collector::storage::dir_size`)
//!   2. `sample_disks` cost against the host's real mountpoints
//!   3. store batch-insert throughput for disk + container_disk rows
//!   4. `downsample` cost over a large aged dataset
//!
//! It drives the *real* production functions, not copies, so numbers track the
//! shipped code. Host-only; never built into the Docker image.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use collector::storage::{dir_size, sample_disks};
use store::{ContainerDiskSample, DiskSample, Store};

#[derive(Debug, Clone)]
pub struct StorageOpts {
    /// Directory to build the synthetic tree under (a unique subdir is created).
    pub tree_dir: PathBuf,
    /// Child directories per directory level.
    pub breadth: usize,
    /// Nesting depth of the synthetic tree.
    pub depth: usize,
    /// Regular files per directory.
    pub files_per_dir: usize,
    /// Bytes per synthetic file.
    pub file_bytes: usize,
    /// Keep the synthetic tree after the run instead of deleting it.
    pub keep: bool,
    /// Total rows for the store write / downsample phases.
    pub rows: usize,
    /// Use larger, worst-case parameters (deep+wide tree, more rows).
    pub stress: bool,
}

impl StorageOpts {
    /// Apply the stress preset unless the user overrode the shape explicitly.
    fn effective(&self) -> StorageOpts {
        if !self.stress {
            return self.clone();
        }
        // ~3.9k dirs × 20 files ≈ 78k files (~305 MiB) — ~10× the default file
        // count for a real worst-case walk that still completes in ~1s and a few
        // hundred MiB, plus a 1M-row store/downsample burst.
        StorageOpts {
            breadth: self.breadth.max(5),
            depth: self.depth.max(5),
            files_per_dir: self.files_per_dir.max(20),
            rows: self.rows.max(1_000_000),
            ..self.clone()
        }
    }
}

struct Built {
    dirs: u64,
    files: u64,
    logical_bytes: u64,
}

/// Recursively materialise a tree of `breadth^depth` directories, each holding
/// `files_per_dir` files of `file_bytes` zero bytes.
fn build_tree(root: &Path, opts: &StorageOpts) -> std::io::Result<Built> {
    let buf = vec![0u8; opts.file_bytes];
    let mut built = Built {
        dirs: 0,
        files: 0,
        logical_bytes: 0,
    };
    build_level(root, opts.depth, opts, &buf, &mut built)?;
    Ok(built)
}

fn build_level(
    dir: &Path,
    depth: usize,
    opts: &StorageOpts,
    buf: &[u8],
    built: &mut Built,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    built.dirs += 1;
    for f in 0..opts.files_per_dir {
        let path = dir.join(format!("f{f}.bin"));
        std::fs::write(&path, buf)?;
        built.files += 1;
        built.logical_bytes += buf.len() as u64;
    }
    if depth > 0 {
        for b in 0..opts.breadth {
            build_level(&dir.join(format!("d{b}")), depth - 1, opts, buf, built)?;
        }
    }
    Ok(())
}

fn fmt_bytes(b: u64) -> String {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.2} {}", U[i])
}

fn min_avg_max(samples: &[Duration]) -> (Duration, Duration, Duration) {
    let min = samples.iter().copied().min().unwrap_or_default();
    let max = samples.iter().copied().max().unwrap_or_default();
    let sum: Duration = samples.iter().sum();
    let avg = sum / samples.len().max(1) as u32;
    (min, avg, max)
}

pub fn run(opts: &StorageOpts) -> Result<(), Box<dyn std::error::Error>> {
    let opts = opts.effective();
    println!("=== Storage collection micro-benchmark ===");
    println!(
        "mode={} tree(breadth={} depth={} files/dir={} file_bytes={}) rows={}",
        if opts.stress { "stress" } else { "default" },
        opts.breadth,
        opts.depth,
        opts.files_per_dir,
        opts.file_bytes,
        opts.rows
    );

    // Unique tree root so parallel runs / leftovers never collide.
    let root = opts
        .tree_dir
        .join(format!("sentinel-bench-storage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    // ---- Phase A: du-walk throughput ----
    println!("\n[A] du-walk (collector::storage::dir_size)");
    let t0 = Instant::now();
    let built = build_tree(&root, &opts)?;
    let build_elapsed = t0.elapsed();
    println!(
        "    built {} dirs, {} files, {} logical in {:.2}s",
        built.dirs,
        built.files,
        fmt_bytes(built.logical_bytes),
        build_elapsed.as_secs_f64()
    );

    let iters = 5;
    let mut walk_samples = Vec::with_capacity(iters);
    let mut on_disk = 0u64;
    for _ in 0..iters {
        let t = Instant::now();
        on_disk = dir_size(&root);
        walk_samples.push(t.elapsed());
    }
    let (wmin, wavg, wmax) = min_avg_max(&walk_samples);
    let avg_s = wavg.as_secs_f64().max(1e-9);
    println!(
        "    on-disk={}  walks(n={iters}) min={:.2}ms avg={:.2}ms max={:.2}ms",
        fmt_bytes(on_disk),
        wmin.as_secs_f64() * 1000.0,
        wavg.as_secs_f64() * 1000.0,
        wmax.as_secs_f64() * 1000.0,
    );
    println!(
        "    throughput: {:.0} files/s, {}/s (avg walk)",
        built.files as f64 / avg_s,
        fmt_bytes((built.logical_bytes as f64 / avg_s) as u64),
    );

    // ---- Phase B: sample_disks (real host mounts) ----
    println!("\n[B] sample_disks (host filesystems)");
    let mut s_samples = Vec::with_capacity(iters);
    let mut n_mounts = 0;
    for _ in 0..iters {
        let t = Instant::now();
        let disks = sample_disks();
        s_samples.push(t.elapsed());
        n_mounts = disks.len();
    }
    let (smin, savg, smax) = min_avg_max(&s_samples);
    println!(
        "    mounts={n_mounts}  n={iters} min={:.2}ms avg={:.2}ms max={:.2}ms",
        smin.as_secs_f64() * 1000.0,
        savg.as_secs_f64() * 1000.0,
        smax.as_secs_f64() * 1000.0,
    );

    // ---- Phase C: store batch-insert throughput ----
    println!("\n[C] store batch inserts (in-memory SQLite)");
    let store = Store::open_in_memory()?;

    // Disk: 8 mounts/cycle is a realistic server; insert exactly `rows` total,
    // with a partial final batch so the executed workload matches `--rows`.
    let mounts_per_cycle = 8usize;
    let disk_batch: Vec<DiskSample> = (0..mounts_per_cycle)
        .map(|m| DiskSample {
            mount: format!("/mnt/d{m}"),
            total: 1_000_000_000,
            used: 500_000_000,
            available: 500_000_000,
            used_percent: 50.0,
        })
        .collect();
    let t = Instant::now();
    let mut disk_rows = 0usize;
    let mut cycle = 0i64;
    while disk_rows < opts.rows {
        let n = (opts.rows - disk_rows).min(mounts_per_cycle);
        store.insert_disk_batch(cycle * 1000, &disk_batch[..n])?;
        disk_rows += n;
        cycle += 1;
    }
    let disk_elapsed = t.elapsed();
    let disk_rows = disk_rows as f64;
    println!(
        "    disk_usage: {} rows in {:.2}s → {:.0} rows/s",
        disk_rows as u64,
        disk_elapsed.as_secs_f64(),
        disk_rows / disk_elapsed.as_secs_f64().max(1e-9),
    );

    // Container: 100 containers/cycle; insert exactly `rows` total, with a
    // partial final batch so the executed workload matches `--rows`.
    let cont_per_cycle = 100usize;
    let cont_batch: Vec<ContainerDiskSample> = (0..cont_per_cycle)
        .map(|c| ContainerDiskSample {
            container_id: format!("container-{c:04}"),
            writable_layer: 12_000_000,
            volumes_total: 340_000_000,
        })
        .collect();
    let t = Instant::now();
    let mut cont_rows = 0usize;
    let mut cycle = 0i64;
    while cont_rows < opts.rows {
        let n = (opts.rows - cont_rows).min(cont_per_cycle);
        store.insert_container_disk_batch(cycle * 1000, &cont_batch[..n])?;
        cont_rows += n;
        cycle += 1;
    }
    let cont_elapsed = t.elapsed();
    let cont_rows = cont_rows as f64;
    println!(
        "    container_disk_usage: {} rows in {:.2}s → {:.0} rows/s",
        cont_rows as u64,
        cont_elapsed.as_secs_f64(),
        cont_rows / cont_elapsed.as_secs_f64().max(1e-9),
    );

    // ---- Phase D: downsample over the aged dataset just written ----
    println!("\n[D] downsample (collapse aged rows)");
    // The rows above were stamped at tiny timestamps (cycle*1000), so from a
    // "now" far in the future they are all older than the 24h window.
    let now = 400i64 * 24 * 60 * 60 * 1_000;
    let t = Instant::now();
    let collapsed = store.downsample(now)?;
    let ds_elapsed = t.elapsed();
    println!(
        "    collapsed {} aged rows in {:.2}s → {:.0} rows/s",
        collapsed,
        ds_elapsed.as_secs_f64(),
        collapsed as f64 / ds_elapsed.as_secs_f64().max(1e-9),
    );

    // Cleanup. Propagate removal failures so a leftover tree never reports OK.
    // (A tree left behind by an earlier `?` failure is intentional: it aids
    // debugging of a crashed run and is cleared by the next run's pre-clean.)
    if opts.keep {
        println!("\ntree kept at {}", root.display());
    } else {
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    println!("\nstorage_bench=OK");
    Ok(())
}
