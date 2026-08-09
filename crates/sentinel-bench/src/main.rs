//! HTTP benchmark client for Sentinel.
//!
//! Modes (see repo-root `BENCHMARK.md`):
//! - `sys`      — print host system configuration (always included in results)
//! - `latency`  — sequential request timing
//! - `load`     — fixed concurrency × duration grid (throughput)
//! - `stress`   — high concurrency, mixed traffic, ramp / burst / soak
//! - `suite`    — latency + load + stress in one run

#![forbid(unsafe_code)]

mod sysinfo_report;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use futures_util::future::join_all;
use reqwest::Client;
use tokio::sync::Semaphore;

const DEFAULT_TOKEN: &str = "bench-token-compare";

#[derive(Parser, Debug)]
#[command(
    name = "sentinel-bench",
    about = "Benchmark harness for Sentinel HTTP API (BENCHMARK.md)",
    version
)]
struct Cli {
    /// Skip printing the system-configuration banner at the start of a run.
    #[arg(long, global = true, default_value_t = false)]
    no_sysinfo: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print host system configuration (required section of every results file).
    Sys,
    /// Sequential latency (avg / p50 / p95 / p99).
    Latency(TargetOpts),
    /// Concurrent throughput grid (paths × concurrency × duration).
    Load(LoadOpts),
    /// Stress: high concurrency, mixed endpoints, optional ramp/burst/soak.
    Stress(StressOpts),
    /// Run latency + load + stress with shared target options.
    Suite {
        #[command(flatten)]
        target: TargetOpts,
        /// Stress profile used by the suite's stress phase.
        #[arg(long, value_enum, default_value_t = StressProfile::Mixed)]
        stress_profile: StressProfile,
        /// Peak concurrency for the suite stress phase.
        #[arg(long, default_value_t = 256)]
        stress_concurrency: usize,
        /// Duration (seconds) for the suite stress phase.
        #[arg(long, default_value_t = 30)]
        stress_duration: u64,
    },
}

#[derive(Parser, Debug, Clone)]
struct TargetOpts {
    /// Base URL, e.g. http://127.0.0.1:18889
    #[arg(
        long,
        env = "SENTINEL_BENCH_BASE",
        default_value = "http://127.0.0.1:18889"
    )]
    base: String,
    /// Bearer token (must match container TOKEN).
    #[arg(long, env = "SENTINEL_BENCH_TOKEN", default_value = DEFAULT_TOKEN)]
    token: String,
    /// Request timeout seconds.
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
}

#[derive(Parser, Debug)]
struct LoadOpts {
    #[command(flatten)]
    target: TargetOpts,
    /// Duration of each concurrency cell (seconds).
    #[arg(long, default_value_t = 8)]
    duration: u64,
    /// Warm-up requests per URL before timing.
    #[arg(long, default_value_t = 20)]
    warmup: u32,
    /// Comma-separated concurrency levels.
    #[arg(long, default_value = "1,10,32", value_delimiter = ',')]
    concurrency: Vec<usize>,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum StressProfile {
    /// Steady mixed traffic at fixed concurrency (default).
    Mixed,
    /// Linear ramp from 1 → peak concurrency over the duration.
    Ramp,
    /// Alternating 2s burst at peak and 2s idle.
    Burst,
    /// Long-ish steady load; same as mixed but intended for soak runs.
    Soak,
}

#[derive(Parser, Debug)]
struct StressOpts {
    #[command(flatten)]
    target: TargetOpts,
    /// Peak concurrent in-flight requests.
    #[arg(long, default_value_t = 256)]
    concurrency: usize,
    /// Total stress duration (seconds).
    #[arg(long, default_value_t = 30)]
    duration: u64,
    /// Warm-up requests on /api/health before starting.
    #[arg(long, default_value_t = 50)]
    warmup: u32,
    #[arg(long, value_enum, default_value_t = StressProfile::Mixed)]
    profile: StressProfile,
    /// Fail the process if error rate (non-200 or transport) exceeds this percent.
    #[arg(long, default_value_t = 1.0)]
    max_error_pct: f64,
    /// Fail if p99 latency exceeds this many milliseconds (0 = disabled).
    #[arg(long, default_value_t = 0.0)]
    max_p99_ms: f64,
    /// Interval for mid-stress health probes (seconds; 0 = disabled).
    #[arg(long, default_value_t = 2)]
    health_every_secs: u64,
}

#[derive(Clone, Copy)]
struct Endpoint {
    path: &'static str,
    /// Relative weight for mixed stress traffic.
    weight: u32,
    /// Sequential latency sample count (0 = skip in latency mode).
    latency_n: u32,
}

const ENDPOINTS: &[Endpoint] = &[
    Endpoint {
        path: "/api/health",
        weight: 4,
        latency_n: 80,
    },
    Endpoint {
        path: "/api/version",
        weight: 1,
        latency_n: 80,
    },
    Endpoint {
        path: "/api/cpu/current",
        weight: 3,
        latency_n: 80,
    },
    Endpoint {
        path: "/api/memory/current",
        weight: 3,
        latency_n: 80,
    },
    Endpoint {
        path: "/api/cpu/history",
        weight: 2,
        latency_n: 40,
    },
    Endpoint {
        path: "/api/memory/history",
        weight: 2,
        latency_n: 40,
    },
];

struct Stats {
    ok: AtomicU64,
    fail: AtomicU64,
    /// Latency samples in microseconds (capped to avoid huge memory under stress).
    samples: std::sync::Mutex<Vec<u64>>,
    sample_cap: usize,
}

impl Stats {
    fn new(sample_cap: usize) -> Self {
        Self {
            ok: AtomicU64::new(0),
            fail: AtomicU64::new(0),
            samples: std::sync::Mutex::new(Vec::with_capacity(sample_cap.min(1_000_000))),
            sample_cap,
        }
    }

    fn record_ok(&self, micros: u64) {
        self.ok.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.samples.lock() {
            if g.len() < self.sample_cap {
                g.push(micros);
            } else {
                // Reservoir-style overwrite of a random-ish slot using micros as entropy.
                let idx = (micros as usize).wrapping_mul(2654435761) % self.sample_cap;
                g[idx] = micros;
            }
        }
    }

    fn record_fail(&self) {
        self.fail.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Snapshot {
        let ok = self.ok.load(Ordering::Relaxed);
        let fail = self.fail.load(Ordering::Relaxed);
        let mut samples = self.samples.lock().map(|g| g.clone()).unwrap_or_default();
        samples.sort_unstable();
        Snapshot { ok, fail, samples }
    }
}

struct Snapshot {
    ok: u64,
    fail: u64,
    samples: Vec<u64>,
}

impl Snapshot {
    fn total(&self) -> u64 {
        self.ok + self.fail
    }

    fn error_pct(&self) -> f64 {
        let t = self.total();
        if t == 0 {
            return 0.0;
        }
        (self.fail as f64 / t as f64) * 100.0
    }

    fn rps(&self, duration_secs: f64) -> f64 {
        if duration_secs <= 0.0 {
            return 0.0;
        }
        self.ok as f64 / duration_secs
    }

    fn pct_ms(&self, p: f64) -> f64 {
        if self.samples.is_empty() {
            return f64::NAN;
        }
        let n = self.samples.len();
        let idx = ((p / 100.0) * (n.saturating_sub(1) as f64)).round() as usize;
        let idx = idx.min(n - 1);
        self.samples[idx] as f64 / 1000.0
    }

    fn avg_ms(&self) -> f64 {
        if self.samples.is_empty() {
            return f64::NAN;
        }
        let sum: u64 = self.samples.iter().sum();
        (sum as f64 / self.samples.len() as f64) / 1000.0
    }

    fn min_ms(&self) -> f64 {
        self.samples
            .first()
            .map(|v| *v as f64 / 1000.0)
            .unwrap_or(f64::NAN)
    }

    fn max_ms(&self) -> f64 {
        self.samples
            .last()
            .map(|v| *v as f64 / 1000.0)
            .unwrap_or(f64::NAN)
    }
}

fn normalize_base(base: &str) -> String {
    base.trim_end_matches('/').to_string()
}

fn build_client(timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .pool_max_idle_per_host(512)
        .tcp_nodelay(true)
        .build()
}

async fn one_get(
    client: &Client,
    url: &str,
    token: &str,
) -> Result<(u16, Duration), reqwest::Error> {
    let t0 = Instant::now();
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await?;
    let status = resp.status().as_u16();
    // Drain body so the connection can be reused.
    let _ = resp.bytes().await?;
    Ok((status, t0.elapsed()))
}

async fn warmup(client: &Client, url: &str, token: &str, n: u32) {
    for _ in 0..n {
        let _ = one_get(client, url, token).await;
    }
}

fn print_row(label: &str, c: usize, duration_secs: f64, snap: &Snapshot) {
    println!(
        "{label:<32} c={c:<3} t={duration_secs:>4.0}s  ok={:<8} fail={:<6} rps={:>8.1}  \
         avg={:>7.2}ms  p50={:>7.2}ms  p95={:>7.2}ms  p99={:>7.2}ms  max={:>7.2}ms  err={:>5.2}%",
        snap.ok,
        snap.fail,
        snap.rps(duration_secs),
        snap.avg_ms(),
        snap.pct_ms(50.0),
        snap.pct_ms(95.0),
        snap.pct_ms(99.0),
        snap.max_ms(),
        snap.error_pct(),
    );
}

fn print_latency_row(label: &str, snap: &Snapshot) {
    println!(
        "{label:<28} ok={:<4} fail={:<3} avg={:>7.2}ms  p50={:>7.2}ms  p95={:>7.2}ms  \
         p99={:>7.2}ms  min={:>7.2}ms  max={:>7.2}ms",
        snap.ok,
        snap.fail,
        snap.avg_ms(),
        snap.pct_ms(50.0),
        snap.pct_ms(95.0),
        snap.pct_ms(99.0),
        snap.min_ms(),
        snap.max_ms(),
    );
}

async fn run_latency(opts: &TargetOpts) -> Result<(), Box<dyn std::error::Error>> {
    let base = normalize_base(&opts.base);
    let client = build_client(opts.timeout_secs)?;
    println!("=== Sequential latency ===");
    println!("base={base}");

    for ep in ENDPOINTS.iter().filter(|e| e.latency_n > 0) {
        let url = format!("{base}{}", ep.path);
        let stats = Stats::new(ep.latency_n as usize * 2);
        for _ in 0..ep.latency_n {
            match one_get(&client, &url, &opts.token).await {
                Ok((200, d)) => stats.record_ok(d.as_micros() as u64),
                Ok(_) | Err(_) => stats.record_fail(),
            }
        }
        print_latency_row(ep.path, &stats.snapshot());
    }
    Ok(())
}

/// Fixed-concurrency load against a single URL for `duration`.
async fn run_load_cell(
    client: &Client,
    url: &str,
    token: &str,
    concurrency: usize,
    duration: Duration,
    sample_cap: usize,
) -> Snapshot {
    let stats = Arc::new(Stats::new(sample_cap));
    let stop = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + duration;
    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let client = client.clone();
        let url = url.to_string();
        let token = token.to_string();
        let stats = stats.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                if Instant::now() >= deadline || stop.load(Ordering::Relaxed) {
                    break;
                }
                match one_get(&client, &url, &token).await {
                    Ok((200, d)) => stats.record_ok(d.as_micros() as u64),
                    Ok(_) | Err(_) => stats.record_fail(),
                }
            }
        }));
    }

    // Wait until duration elapses, then signal stop and join.
    let remaining = deadline.saturating_duration_since(Instant::now());
    tokio::time::sleep(remaining).await;
    stop.store(true, Ordering::Relaxed);
    let _ = join_all(handles).await;
    stats.snapshot()
}

async fn run_load(opts: &LoadOpts) -> Result<(), Box<dyn std::error::Error>> {
    let base = normalize_base(&opts.target.base);
    let client = build_client(opts.target.timeout_secs)?;
    let duration = Duration::from_secs(opts.duration);
    let conc: Vec<usize> = if opts.concurrency.is_empty() {
        vec![1, 10, 32]
    } else {
        opts.concurrency.clone()
    };

    println!("=== Concurrent load (throughput grid) ===");
    println!(
        "base={base} duration={}s concurrencies={conc:?} warmup={}",
        opts.duration, opts.warmup
    );

    let paths: Vec<&str> = ENDPOINTS
        .iter()
        .filter(|e| {
            matches!(
                e.path,
                "/api/health" | "/api/cpu/current" | "/api/memory/current" | "/api/cpu/history"
            )
        })
        .map(|e| e.path)
        .collect();

    for path in paths {
        let url = format!("{base}{path}");
        warmup(&client, &url, &opts.target.token, opts.warmup).await;
        for &c in &conc {
            if c == 0 {
                continue;
            }
            let snap = run_load_cell(&client, &url, &opts.target.token, c, duration, 200_000).await;
            print_row(path, c, opts.duration as f64, &snap);
        }
    }
    Ok(())
}

fn pick_endpoint(tick: u64) -> &'static Endpoint {
    let total: u32 = ENDPOINTS.iter().map(|e| e.weight).sum();
    let mut r = (tick.wrapping_mul(0x9E37_79B9) % total as u64) as u32;
    for ep in ENDPOINTS {
        if r < ep.weight {
            return ep;
        }
        r -= ep.weight;
    }
    &ENDPOINTS[0]
}

/// Effective concurrency at `elapsed` for the given stress profile.
fn stress_target_concurrency(
    profile: StressProfile,
    peak: usize,
    elapsed: Duration,
    total: Duration,
) -> usize {
    let peak = peak.max(1);
    match profile {
        StressProfile::Mixed | StressProfile::Soak => peak,
        StressProfile::Ramp => {
            if total.is_zero() {
                return peak;
            }
            let frac = (elapsed.as_secs_f64() / total.as_secs_f64()).clamp(0.0, 1.0);
            ((peak as f64) * frac).ceil().max(1.0) as usize
        }
        StressProfile::Burst => {
            // 2s on, 2s off.
            let phase = elapsed.as_secs() % 4;
            if phase < 2 { peak } else { 1 }
        }
    }
}

async fn run_stress(opts: &StressOpts) -> Result<bool, Box<dyn std::error::Error>> {
    let base = normalize_base(&opts.target.base);
    let client = build_client(opts.target.timeout_secs)?;
    let peak = opts.concurrency.max(1);
    let total = Duration::from_secs(opts.duration.max(1));
    let stats = Arc::new(Stats::new(500_000));
    let stop = Arc::new(AtomicBool::new(false));
    let in_flight_limit = Arc::new(Semaphore::new(peak));
    let health_fails = Arc::new(AtomicU64::new(0));

    println!("=== Stress ===");
    println!(
        "base={base} profile={:?} peak_concurrency={peak} duration={}s max_error_pct={}% max_p99_ms={}",
        opts.profile,
        opts.duration,
        opts.max_error_pct,
        if opts.max_p99_ms > 0.0 {
            format!("{:.1}", opts.max_p99_ms)
        } else {
            "off".into()
        }
    );

    let health_url = format!("{base}/api/health");
    warmup(&client, &health_url, &opts.target.token, opts.warmup).await;

    let start = Instant::now();
    let deadline = start + total;

    // Health probe task.
    let health_handle = if opts.health_every_secs > 0 {
        let client = client.clone();
        let url = health_url.clone();
        let token = opts.target.token.clone();
        let stop = stop.clone();
        let health_fails = health_fails.clone();
        let every = Duration::from_secs(opts.health_every_secs);
        Some(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                tokio::time::sleep(every).await;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match one_get(&client, &url, &token).await {
                    Ok((200, _)) => {}
                    _ => {
                        health_fails.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }))
    } else {
        None
    };

    // Worker pool: always `peak` tasks; each acquires permits based on target concurrency.
    // Simpler approach: always run `peak` workers that loop; for ramp/burst we sleep when
    // over target by only allowing `target` permits via resizing — Semaphore can't resize
    // easily, so workers check target and yield when in-flight would exceed.
    let active = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::with_capacity(peak);
    let tick = Arc::new(AtomicU64::new(0));

    for _ in 0..peak {
        let client = client.clone();
        let base = base.clone();
        let token = opts.target.token.clone();
        let stats = stats.clone();
        let stop = stop.clone();
        let active = active.clone();
        let tick = tick.clone();
        let profile = opts.profile;
        let peak_c = peak;
        let total_d = total;
        let start_t = start;
        let limit = in_flight_limit.clone();

        workers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                let elapsed = start_t.elapsed();
                let target = stress_target_concurrency(profile, peak_c, elapsed, total_d);
                // Only proceed if under target concurrency.
                let cur = active.load(Ordering::Relaxed) as usize;
                if cur >= target {
                    tokio::task::yield_now().await;
                    continue;
                }

                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    tokio::task::yield_now().await;
                    continue;
                };
                active.fetch_add(1, Ordering::Relaxed);

                let n = tick.fetch_add(1, Ordering::Relaxed);
                let ep = pick_endpoint(n);
                let url = format!("{base}{}", ep.path);

                match one_get(&client, &url, &token).await {
                    Ok((200, d)) => stats.record_ok(d.as_micros() as u64),
                    Ok(_) | Err(_) => stats.record_fail(),
                }

                active.fetch_sub(1, Ordering::Relaxed);
                drop(permit);
            }
        }));
    }

    // Progress ticks every 5s.
    while Instant::now() < deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        let slice = left.min(Duration::from_secs(5));
        tokio::time::sleep(slice).await;
        if Instant::now() >= deadline {
            break;
        }
        let partial = stats.snapshot();
        let elapsed = start.elapsed().as_secs_f64();
        eprintln!(
            "  … stress {elapsed:>5.1}s  ok={} fail={} rps={:.0} err={:.2}% p99={:.1}ms",
            partial.ok,
            partial.fail,
            partial.rps(elapsed),
            partial.error_pct(),
            partial.pct_ms(99.0),
        );
    }

    stop.store(true, Ordering::Relaxed);
    let _ = join_all(workers).await;
    if let Some(h) = health_handle {
        let _ = h.await;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let snap = stats.snapshot();
    let hf = health_fails.load(Ordering::Relaxed);

    println!("--- stress summary ---");
    print_row("mixed(all endpoints)", peak, elapsed, &snap);
    println!(
        "health_probe_failures={hf}  sample_count={}  total_requests={}",
        snap.samples.len(),
        snap.total()
    );

    // Post-stress health must still work.
    let post_ok = match one_get(&client, &health_url, &opts.target.token).await {
        Ok((200, d)) => {
            println!(
                "post_stress_health=ok latency_ms={:.2}",
                d.as_secs_f64() * 1000.0
            );
            true
        }
        Ok((code, _)) => {
            println!("post_stress_health=FAIL status={code}");
            false
        }
        Err(e) => {
            println!("post_stress_health=FAIL error={e}");
            false
        }
    };

    let mut pass = true;
    if snap.error_pct() > opts.max_error_pct {
        println!(
            "FAIL: error rate {:.2}% > max_error_pct {:.2}%",
            snap.error_pct(),
            opts.max_error_pct
        );
        pass = false;
    }
    if opts.max_p99_ms > 0.0 && snap.pct_ms(99.0) > opts.max_p99_ms {
        println!(
            "FAIL: p99 {:.2}ms > max_p99_ms {:.2}ms",
            snap.pct_ms(99.0),
            opts.max_p99_ms
        );
        pass = false;
    }
    if hf > 0 {
        println!("FAIL: mid-stress health probes failed ({hf})");
        pass = false;
    }
    if !post_ok {
        println!("FAIL: post-stress /api/health not OK");
        pass = false;
    }

    if pass {
        println!("stress_result=PASS");
    } else {
        println!("stress_result=FAIL");
    }
    Ok(pass)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut stress_pass = true;

    // Every results capture must include host configuration (BENCHMARK.md).
    // `sys` prints it alone; other commands print it once as a header unless
    // --no-sysinfo is set (e.g. when stitching logs that already have a banner).
    match &cli.command {
        Command::Sys => {
            sysinfo_report::print_system_config();
            return Ok(());
        }
        _ if !cli.no_sysinfo => {
            sysinfo_report::print_system_config();
            println!();
        }
        _ => {}
    }

    match cli.command {
        Command::Sys => unreachable!("handled above"),
        Command::Latency(t) => run_latency(&t).await?,
        Command::Load(l) => run_load(&l).await?,
        Command::Stress(s) => {
            stress_pass = run_stress(&s).await?;
        }
        Command::Suite {
            target,
            stress_profile,
            stress_concurrency,
            stress_duration,
        } => {
            run_latency(&target).await?;
            println!();
            run_load(&LoadOpts {
                target: target.clone(),
                duration: 8,
                warmup: 20,
                concurrency: vec![1, 10, 32],
            })
            .await?;
            println!();
            stress_pass = run_stress(&StressOpts {
                target,
                concurrency: stress_concurrency,
                duration: stress_duration,
                warmup: 50,
                profile: stress_profile,
                max_error_pct: 1.0,
                max_p99_ms: 0.0,
                health_every_secs: 2,
            })
            .await?;
        }
    }

    if !stress_pass {
        std::process::exit(2);
    }
    Ok(())
}
