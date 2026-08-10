//! Traffic-analytics pipeline and query benchmark.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::ValueEnum;
use config::TrafficSettings;
use reqwest::Client;
use store::traffic::{AnalyticsStore, Tier};
use traffic::aggregator::Aggregator;
use traffic::compaction::{compact_1h_to_1d, compact_1m_to_1h};
use traffic::enrich::{CountryLookup, Enricher, NoGeo};
use traffic::geoip::{self, GeoIp};
use traffic::parser::{ProxyType, parse_line};

/// Public resolvers / CDNs that GeoLite2/DB-IP usually map to a country.
/// Documentation ranges (203.0.113.0/24) deliberately avoided — they miss.
const GEOIP_IPS: &[&str] = &[
    "8.8.8.8",         // Google DNS
    "1.1.1.1",         // Cloudflare DNS
    "9.9.9.9",         // Quad9
    "208.67.222.222",  // OpenDNS
    "94.140.14.14",    // AdGuard
    "185.228.168.9",   // CleanBrowsing
    "149.112.112.112", // Quad9 secondary
    "64.6.64.6",       // Verisign
    "142.250.190.14",  // Google edge
    "104.16.1.1",      // Cloudflare edge
];

const CF_COUNTRIES: &[&str] = &["US", "DE", "FR", "JP", "BR", "IN", "GB", "AU", "CA", "NL"];

#[derive(Debug, Clone)]
pub struct AnalyticsOpts {
    pub events: usize,
    pub apps: usize,
    pub paths: usize,
    pub minutes: usize,
    pub topn: usize,
    pub query_iterations: usize,
    pub base: String,
    pub token: String,
    pub timeout_secs: u64,
    pub access_log: Option<PathBuf>,
    pub stress_duration: u64,
    pub stress_concurrency: usize,
    pub stress_log_rate: usize,
    pub max_error_pct: f64,
    pub max_p99_ms: f64,
    pub stress_profile: AnalyticsStressProfile,
    /// Percent of synthetic lines that carry `request_Cf-Ipcountry` (0–100).
    /// The remainder omit CF country so enrichment falls through to GeoIP.
    pub cf_header_pct: u8,
    /// Skip GeoIP bootstrap; country only comes from CF headers.
    pub no_geoip: bool,
    /// Fail if GeoIP cannot be loaded (in-process) or attribution stays null (live).
    pub require_geoip: bool,
    /// Directory for downloaded `.mmdb` files during in-process bootstrap.
    pub geoip_dir: PathBuf,
    pub geoip_db_url: Option<String>,
    pub geoip_maxmind_key: Option<String>,
    pub geoip_maxmind_edition: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AnalyticsStressProfile {
    Mixed,
    Ramp,
    Burst,
    Soak,
}

/// Whether line `i` of a stream should include a Cloudflare country header.
pub fn line_uses_cf_header(i: usize, cf_header_pct: u8) -> bool {
    let pct = u8::min(cf_header_pct, 100) as usize;
    (i % 100) < pct
}

/// Generate deterministic Traefik JSON lines with a mixed CF / GeoIP country path.
///
/// * CF path (`line_uses_cf_header`): sets `request_Cf-Ipcountry` so enrichment
///   never touches the database.
/// * GeoIP path: omits CF country (and CF connecting IP) and uses a public
///   `ClientHost` that a real GeoIP DB can resolve.
pub fn generate_lines(
    count: usize,
    apps: usize,
    paths: usize,
    ts_ms: i64,
    cf_header_pct: u8,
) -> Vec<String> {
    let apps = apps.max(1);
    let paths = paths.max(1);
    (0..count)
        .map(|i| {
            let app = format!("bench-app-{}", i % apps);
            let path = format!("/bench/path/{}", i % paths);
            let status = [200, 200, 200, 302, 404, 500][i % 6];
            let size = 512 + i % 4096;
            let duration = 1_000_000 + (i % 100) * 10_000;
            let req_size = i % 1024;
            let host_n = i % apps;
            let ua = "Mozilla/5.0 Chrome/120.0";
            if line_uses_cf_header(i, cf_header_pct) {
                let ip = format!("203.0.113.{}", i % 250 + 1);
                let country = CF_COUNTRIES[i % CF_COUNTRIES.len()];
                format!(
                    r#"{{"ClientHost":"{ip}","DownstreamContentSize":{size},"DownstreamStatus":{status},"Duration":{duration},"RequestContentSize":{req_size},"RequestHost":"app{host_n}.example.test","RequestMethod":"GET","RequestPath":"{path}?n={i}","RequestProtocol":"HTTP/1.1","RequestScheme":"https","RouterName":"https-0-{app}@docker","StartUTC":"2026-08-10T00:00:00Z","TLSVersion":"1.3","request_Cf-Connecting-Ip":"{ip}","request_Cf-Ipcountry":"{country}","request_User-Agent":"{ua}","time":"2026-08-10T00:00:00Z","bench_ts_ms":{ts_ms}}}"#
                )
            } else {
                let ip = GEOIP_IPS[i % GEOIP_IPS.len()];
                format!(
                    r#"{{"ClientHost":"{ip}","DownstreamContentSize":{size},"DownstreamStatus":{status},"Duration":{duration},"RequestContentSize":{req_size},"RequestHost":"app{host_n}.example.test","RequestMethod":"GET","RequestPath":"{path}?n={i}","RequestProtocol":"HTTP/1.1","RequestScheme":"https","RouterName":"https-0-{app}@docker","StartUTC":"2026-08-10T00:00:00Z","TLSVersion":"1.3","request_User-Agent":"{ua}","time":"2026-08-10T00:00:00Z","bench_ts_ms":{ts_ms}}}"#
                )
            }
        })
        .collect()
}

pub fn analytics_paths(app: &str) -> [String; 4] {
    [
        "/api/traffic/apps".into(),
        format!("/api/app/{app}/traffic/overview"),
        format!("/api/app/{app}/traffic/paths?limit=50"),
        format!("/api/app/{app}/traffic/breakdown/country?limit=50"),
    ]
}

fn stress_path(app: &str, tick: usize) -> String {
    analytics_paths(app)[tick % 4].clone()
}

fn lines_per_tick(rate: usize, tick: Duration) -> usize {
    if rate == 0 {
        0
    } else {
        ((rate as f64 * tick.as_secs_f64()).ceil() as usize).max(1)
    }
}

fn ingestion_wait_secs(configured: u64) -> u64 {
    configured.max(70)
}

fn stress_factor(profile: AnalyticsStressProfile, elapsed: Duration, total: Duration) -> f64 {
    match profile {
        AnalyticsStressProfile::Mixed | AnalyticsStressProfile::Soak => 1.0,
        AnalyticsStressProfile::Ramp => {
            (elapsed.as_secs_f64() / total.as_secs_f64().max(0.001)).clamp(0.01, 1.0)
        }
        AnalyticsStressProfile::Burst => {
            if elapsed.as_secs() % 4 < 2 {
                1.0
            } else {
                0.1
            }
        }
    }
}

fn live_overview_path(now_ms: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::{Duration as TimeDuration, OffsetDateTime};
    let now = OffsetDateTime::from_unix_timestamp_nanos(now_ms as i128 * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let from = (now - TimeDuration::minutes(59))
        .format(&Rfc3339)
        .unwrap_or_default();
    let to = (now + TimeDuration::minutes(59))
        .format(&Rfc3339)
        .unwrap_or_default();
    format!("/api/app/bench-app-0/traffic/overview?from={from}&to={to}")
}

fn percentile_ms(samples: &mut [Duration], pct: usize) -> f64 {
    samples.sort_unstable();
    let index = (samples.len().saturating_sub(1) * pct) / 100;
    samples
        .get(index)
        .copied()
        .unwrap_or_default()
        .as_secs_f64()
        * 1000.0
}

fn traffic_settings(opts: &AnalyticsOpts) -> TrafficSettings {
    TrafficSettings {
        enabled: true,
        access_log_path: PathBuf::from("/dev/null"),
        proxy_type: "traefik".into(),
        topn: 50,
        sample_threshold: 0,
        retention_1m_hours: 48,
        retention_1h_days: 30,
        retention_1d_days: 395,
        analytics_file: PathBuf::from(":memory:"),
        geoip_enabled: true,
        geoip_db_url: opts.geoip_db_url.clone(),
        geoip_maxmind_key: opts.geoip_maxmind_key.clone(),
        geoip_maxmind_edition: opts.geoip_maxmind_edition.clone(),
        geoip_refresh_days: 30,
    }
}

async fn load_geoip(
    opts: &AnalyticsOpts,
) -> Result<Arc<dyn CountryLookup>, Box<dyn std::error::Error>> {
    if opts.no_geoip {
        println!("[geoip] disabled (--no-geoip); CF-header lines only get country");
        return Ok(Arc::new(NoGeo));
    }

    std::fs::create_dir_all(&opts.geoip_dir)?;
    let cfg = traffic_settings(opts);
    let sources = geoip::resolve_sources(&cfg);
    println!(
        "[geoip] bootstrapping into {} (candidates={})",
        opts.geoip_dir.display(),
        sources.len()
    );
    match GeoIp::bootstrap(&cfg, &opts.geoip_dir).await {
        Ok(geo) => {
            let attribution = geo
                .attribution()
                .unwrap_or_else(|| "(unrecognized source)".into());
            println!("[geoip] loaded: {attribution}");
            Ok(geo)
        }
        Err(e) => {
            if opts.require_geoip {
                return Err(format!("geoip bootstrap failed and --require-geoip set: {e}").into());
            }
            println!("[geoip] bootstrap failed ({e}); continuing with NoGeo");
            Ok(Arc::new(NoGeo))
        }
    }
}

async fn wait_live_geoip(
    client: &Client,
    base: &str,
    token: &str,
    timeout: Duration,
    require: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    let mut last: Option<Option<String>> = None;
    loop {
        let attribution = client
            .get(format!("{base}/api/traffic/attribution"))
            .bearer_auth(token)
            .send()
            .await
            .ok()
            .filter(|r| r.status().is_success());
        if let Some(resp) = attribution
            && let Ok(body) = resp.json::<serde_json::Value>().await
        {
            let attr = body
                .get("attribution")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            last = Some(attr.clone());
            if let Some(s) = attr {
                println!("[geoip] live attribution ready: {s}");
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    match last {
        Some(None) | None => {
            let msg = "live Sentinel GeoIP attribution is null (database not loaded or GEOIP_ENABLED=false)";
            if require {
                return Err(msg.into());
            }
            println!("[geoip] WARN: {msg}; GeoIP-path lines will lack country");
            Ok(())
        }
        Some(Some(_)) => Ok(()), // unreachable: would have returned earlier
    }
}

pub async fn run(opts: &AnalyticsOpts) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Traffic analytics benchmark ===");
    println!(
        "events={} apps={} paths={} minutes={} topn={} query_iterations={} cf_header_pct={}%",
        opts.events,
        opts.apps,
        opts.paths,
        opts.minutes,
        opts.topn,
        opts.query_iterations,
        opts.cf_header_pct.min(100)
    );

    let lookup = load_geoip(opts).await?;
    let enricher = Enricher::new(lookup, 1024);

    let now = 1_700_000_000_000i64;
    let lines = generate_lines(opts.events, opts.apps, opts.paths, now, opts.cf_header_pct);
    let mut aggregator = Aggregator::new(opts.topn);
    let mut cf_country = 0u64;
    let mut geoip_country = 0u64;
    let mut unresolved = 0u64;
    let started = Instant::now();
    for (i, line) in lines.iter().enumerate() {
        let event = parse_line(ProxyType::Traefik, line.as_bytes())
            .ok_or("generated Traefik line did not parse")?;
        let used_cf = line_uses_cf_header(i, opts.cf_header_pct);
        let enriched = enricher.enrich(&event);
        match (&enriched.country, used_cf) {
            (Some(_), true) => cf_country += 1,
            (Some(_), false) => geoip_country += 1,
            (None, _) => unresolved += 1,
        }
        aggregator.record(&event, &enriched);
    }
    let ingest_elapsed = started.elapsed();
    println!(
        "[A] parse+enrich+aggregate: {:.2}ms ({:.0} events/s) cf_country={} geoip_country={} unresolved={}",
        ingest_elapsed.as_secs_f64() * 1000.0,
        opts.events as f64 / ingest_elapsed.as_secs_f64().max(1e-9),
        cf_country,
        geoip_country,
        unresolved
    );
    if opts.require_geoip && opts.cf_header_pct < 100 && geoip_country == 0 && opts.events > 0 {
        return Err(
            "expected GeoIP-resolved countries for non-CF lines but got none (--require-geoip)"
                .into(),
        );
    }

    let store = AnalyticsStore::open_in_memory()?;
    let rollup = aggregator.take_rollup(now - now % 60_000);
    let started = Instant::now();
    store.flush_window(&rollup.stats, &rollup.paths, &rollup.breakdown)?;
    println!(
        "[B] flush: rows={} elapsed={:.2}ms",
        rollup.stats.len() + rollup.paths.len() + rollup.breakdown.len(),
        started.elapsed().as_secs_f64() * 1000.0
    );

    // Seed closed minute buckets using the same real parser/aggregator/store path.
    let hour = 1_699_999_200_000i64; // aligned and safely before `now`
    for minute in 0..opts.minutes.max(60) {
        let bucket = hour - (minute as i64) * 60_000;
        let mut a = Aggregator::new(opts.topn);
        for line in generate_lines(
            opts.apps.max(1) * 2,
            opts.apps,
            opts.paths,
            bucket,
            opts.cf_header_pct,
        ) {
            if let Some(event) = parse_line(ProxyType::Traefik, line.as_bytes()) {
                let enriched = enricher.enrich(&event);
                a.record(&event, &enriched);
            }
        }
        let r = a.take_rollup(bucket);
        store.flush_window(&r.stats, &r.paths, &r.breakdown)?;
    }
    let started = Instant::now();
    let h_rows = compact_1m_to_1h(&store, now, opts.topn)?;
    let h_elapsed = started.elapsed();
    let started = Instant::now();
    let d_rows = compact_1h_to_1d(&store, now + 86_400_000, opts.topn)?;
    let d_elapsed = started.elapsed();
    println!(
        "[C] compaction: 1m->1h rows={h_rows} {:.2}ms; 1h->1d rows={d_rows} {:.2}ms",
        h_elapsed.as_secs_f64() * 1000.0,
        d_elapsed.as_secs_f64() * 1000.0
    );

    let app = "bench-app-0";
    let mut samples = Vec::with_capacity(opts.query_iterations * 4);
    let started = Instant::now();
    for _ in 0..opts.query_iterations {
        for query in 0..4 {
            let t = Instant::now();
            match query {
                0 => {
                    store.stats_range(Tier::D1, app, 0, now + 2 * 86_400_000)?;
                }
                1 => {
                    store.paths_range(Tier::D1, app, 0, now + 2 * 86_400_000, 1_000_000)?;
                }
                2 => {
                    store.breakdown_range(
                        Tier::D1,
                        app,
                        "country",
                        0,
                        now + 2 * 86_400_000,
                        1_000_000,
                    )?;
                }
                _ => {
                    store.apps()?;
                }
            }
            samples.push(t.elapsed());
        }
    }
    let query_elapsed = started.elapsed();
    println!(
        "[D] store queries: n={} total={:.2}ms p50={:.3}ms p95={:.3}ms p99={:.3}ms",
        samples.len(),
        query_elapsed.as_secs_f64() * 1000.0,
        percentile_ms(&mut samples, 50),
        percentile_ms(&mut samples.clone(), 95),
        percentile_ms(&mut samples.clone(), 99)
    );

    if let Some(path) = &opts.access_log {
        run_end_to_end(opts, path, &lines).await?;
        if opts.stress_duration > 0 {
            run_live_stress(opts, path).await?;
        }
    } else {
        println!(
            "[E] end-to-end: SKIPPED (pass --access-log for a running traffic-enabled Sentinel)"
        );
    }
    Ok(())
}

async fn overview_requests(client: &Client, base: &str, token: &str) -> Option<u64> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as i64;
    client
        .get(format!("{base}{}", live_overview_path(now_ms)))
        .bearer_auth(token)
        .send()
        .await
        .ok()?
        .json::<serde_json::Value>()
        .await
        .ok()?
        .get("requests")?
        .as_u64()
}

async fn run_live_stress(
    opts: &AnalyticsOpts,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(opts.timeout_secs))
        .build()?;
    let base = opts.base.trim_end_matches('/').to_string();
    let baseline = overview_requests(&client, &base, &opts.token)
        .await
        .unwrap_or(0);
    let stress_started = Instant::now();
    let total_duration = Duration::from_secs(opts.stress_duration);
    let deadline = stress_started + total_duration;
    let ok = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let written = Arc::new(AtomicU64::new(0));
    let health_failed = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(std::sync::Mutex::new(Vec::<Duration>::new()));

    let writer_path = path.to_path_buf();
    let writer_written = written.clone();
    let rate = opts.stress_log_rate;
    let profile = opts.stress_profile;
    let cf_header_pct = opts.cf_header_pct;
    let writer = tokio::spawn(async move {
        let tick = Duration::from_millis(100);
        let mut sequence = 0usize;
        let mut interval = tokio::time::interval(tick);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(writer_path)?;
        while Instant::now() < deadline {
            interval.tick().await;
            let factor = stress_factor(profile, stress_started.elapsed(), total_duration);
            let per_tick = lines_per_tick((rate as f64 * factor) as usize, tick);
            for line in generate_lines(
                per_tick,
                10,
                100,
                1_700_000_000_000 + sequence as i64,
                cf_header_pct,
            ) {
                writeln!(file, "{line}")?;
                sequence += 1;
            }
            file.flush()?;
            writer_written.fetch_add(per_tick as u64, Ordering::Relaxed);
        }
        Ok::<(), std::io::Error>(())
    });

    let mut workers = Vec::new();
    for worker in 0..opts.stress_concurrency.max(1) {
        let client = client.clone();
        let base = base.clone();
        let token = opts.token.clone();
        let ok = ok.clone();
        let failed = failed.clone();
        let latencies = latencies.clone();
        let profile = opts.stress_profile;
        let peak = opts.stress_concurrency.max(1);
        workers.push(tokio::spawn(async move {
            let mut tick = worker;
            while Instant::now() < deadline {
                let active = ((peak as f64
                    * stress_factor(profile, stress_started.elapsed(), total_duration))
                .ceil() as usize)
                    .max(1);
                if worker >= active {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                let started = Instant::now();
                let success = client
                    .get(format!("{base}{}", stress_path("bench-app-0", tick)))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);
                if success {
                    ok.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut samples) = latencies.lock()
                        && samples.len() < 1_000_000
                    {
                        samples.push(started.elapsed());
                    }
                } else {
                    failed.fetch_add(1, Ordering::Relaxed);
                }
                tick += 1;
            }
        }));
    }

    let health_client = client.clone();
    let health_base = base.clone();
    let health = health_failed.clone();
    let probe = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        while Instant::now() < deadline {
            interval.tick().await;
            let healthy = health_client
                .get(format!("{health_base}/api/health"))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if !healthy {
                health.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    writer.await??;
    for worker in workers {
        worker.await?;
    }
    probe.await?;

    let ok = ok.load(Ordering::Relaxed);
    let failed = failed.load(Ordering::Relaxed);
    let total = ok + failed;
    let error_pct = failed as f64 * 100.0 / total.max(1) as f64;
    let written = written.load(Ordering::Relaxed);
    let mut samples = latencies.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let p99 = percentile_ms(&mut samples, 99);
    let ingestion_deadline =
        Instant::now() + Duration::from_secs(ingestion_wait_secs(opts.timeout_secs));
    let mut observed = 0;
    while Instant::now() < ingestion_deadline {
        observed = overview_requests(&client, &base, &opts.token)
            .await
            .unwrap_or(0);
        if observed >= baseline.saturating_add(written / 10) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let health_failures = health_failed.load(Ordering::Relaxed);
    println!(
        "[F] live stress: profile={:?} duration={}s concurrency={} target_log_rate={}/s written={} queries={} query_rps={:.0} errors={:.2}% p99={:.2}ms health_failures={} observed_app0_delta={}",
        opts.stress_profile,
        opts.stress_duration,
        opts.stress_concurrency,
        opts.stress_log_rate,
        written,
        total,
        total as f64 / opts.stress_duration.max(1) as f64,
        error_pct,
        p99,
        health_failures,
        observed.saturating_sub(baseline)
    );
    if error_pct > opts.max_error_pct
        || (opts.max_p99_ms > 0.0 && p99 > opts.max_p99_ms)
        || health_failures > 0
        || observed < baseline.saturating_add(written / 10)
    {
        return Err("analytics stress thresholds failed".into());
    }
    Ok(())
}

async fn run_end_to_end(
    opts: &AnalyticsOpts,
    path: &Path,
    lines: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(opts.timeout_secs))
        .build()?;
    let base = opts.base.trim_end_matches('/');

    if !opts.no_geoip {
        // GeoIP bootstrap is deferred until after the API is up; wait so the
        // live mix exercises real lookups rather than racing empty enrichment.
        let wait = Duration::from_secs(ingestion_wait_secs(opts.timeout_secs).min(90));
        wait_live_geoip(&client, base, &opts.token, wait, opts.require_geoip).await?;
    }

    let baseline = overview_requests(&client, base, &opts.token)
        .await
        .unwrap_or(0);
    let started = Instant::now();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    file.flush()?;

    let expected = baseline.saturating_add((lines.len() / opts.apps.max(1)) as u64);
    let deadline = Instant::now() + Duration::from_secs(ingestion_wait_secs(opts.timeout_secs));
    loop {
        if overview_requests(&client, base, &opts.token)
            .await
            .unwrap_or(0)
            >= expected
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err("analytics ingestion was not visible before timeout".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!(
        "[E] end-to-end ingestion visible after {:.2}ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    for path in analytics_paths("bench-app-0") {
        let mut durations = Vec::with_capacity(opts.query_iterations);
        for _ in 0..opts.query_iterations {
            let t = Instant::now();
            let status = client
                .get(format!("{base}{path}"))
                .bearer_auth(&opts.token)
                .send()
                .await?
                .status();
            if !status.is_success() {
                return Err(format!("analytics endpoint {path} returned {status}").into());
            }
            durations.push(t.elapsed());
        }
        println!(
            "    {path}: p50={:.3}ms p95={:.3}ms p99={:.3}ms",
            percentile_ms(&mut durations, 50),
            percentile_ms(&mut durations.clone(), 95),
            percentile_ms(&mut durations.clone(), 99)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_traefik_lines_parse_with_requested_cardinality() {
        let lines = generate_lines(12, 3, 4, 1_700_000_000_000, 100);
        assert_eq!(lines.len(), 12);
        let events: Vec<_> = lines
            .iter()
            .map(|line| parse_line(ProxyType::Traefik, line.as_bytes()).unwrap())
            .collect();
        let apps: std::collections::HashSet<_> = events.iter().map(|e| e.app.as_ref()).collect();
        let paths: std::collections::HashSet<_> = events.iter().map(|e| e.path.as_ref()).collect();
        assert_eq!(apps.len(), 3);
        assert_eq!(paths.len(), 4);
    }

    #[test]
    fn cf_header_mix_is_deterministic() {
        assert!(line_uses_cf_header(0, 50));
        assert!(line_uses_cf_header(49, 50));
        assert!(!line_uses_cf_header(50, 50));
        assert!(!line_uses_cf_header(99, 50));
        assert!(line_uses_cf_header(0, 100));
        assert!(!line_uses_cf_header(0, 0));
    }

    #[test]
    fn mixed_lines_include_cf_and_geoip_paths() {
        let lines = generate_lines(100, 2, 2, 1_700_000_000_000, 50);
        let mut with_cf = 0;
        let mut without_cf = 0;
        for (i, line) in lines.iter().enumerate() {
            let event = parse_line(ProxyType::Traefik, line.as_bytes()).unwrap();
            if line_uses_cf_header(i, 50) {
                assert!(
                    event.cf_country.is_some(),
                    "line {i} should have CF country"
                );
                with_cf += 1;
            } else {
                assert!(
                    event.cf_country.is_none(),
                    "line {i} should omit CF country for GeoIP path"
                );
                assert!(
                    event.client_ip.is_some(),
                    "line {i} needs ClientHost for GeoIP"
                );
                // Public IPs, not documentation range.
                let ip = event.client_ip.as_ref().unwrap();
                assert!(
                    !ip.starts_with("203.0.113."),
                    "GeoIP path should not use TEST-NET IPs"
                );
                without_cf += 1;
            }
        }
        assert_eq!(with_cf, 50);
        assert_eq!(without_cf, 50);
    }

    #[test]
    fn analytics_urls_cover_each_query_surface() {
        assert_eq!(
            analytics_paths("app-1"),
            [
                "/api/traffic/apps",
                "/api/app/app-1/traffic/overview",
                "/api/app/app-1/traffic/paths?limit=50",
                "/api/app/app-1/traffic/breakdown/country?limit=50"
            ]
        );
    }

    #[test]
    fn stress_query_mix_cycles_across_all_analytics_endpoints() {
        let expected = analytics_paths("app-1");
        let actual: Vec<_> = (0..8).map(|i| stress_path("app-1", i)).collect();
        let repeated: Vec<_> = expected.iter().cycle().take(8).cloned().collect();
        assert_eq!(actual, repeated);
    }

    #[test]
    fn stress_rate_budget_distributes_lines_over_ticks() {
        assert_eq!(lines_per_tick(1_000, Duration::from_millis(100)), 100);
        assert_eq!(lines_per_tick(1, Duration::from_millis(100)), 1);
        assert_eq!(lines_per_tick(0, Duration::from_millis(100)), 0);
    }

    #[test]
    fn stress_profiles_scale_the_active_load() {
        assert_eq!(
            stress_factor(
                AnalyticsStressProfile::Ramp,
                Duration::from_secs(5),
                Duration::from_secs(10)
            ),
            0.5
        );
        assert_eq!(
            stress_factor(
                AnalyticsStressProfile::Burst,
                Duration::from_secs(1),
                Duration::from_secs(10)
            ),
            1.0
        );
        assert_eq!(
            stress_factor(
                AnalyticsStressProfile::Burst,
                Duration::from_secs(3),
                Duration::from_secs(10)
            ),
            0.1
        );
        assert_eq!(
            stress_factor(
                AnalyticsStressProfile::Mixed,
                Duration::from_secs(3),
                Duration::from_secs(10)
            ),
            1.0
        );
    }

    #[test]
    fn ingestion_wait_crosses_a_minute_boundary() {
        assert_eq!(ingestion_wait_secs(5), 70);
        assert_eq!(ingestion_wait_secs(120), 120);
    }
}
