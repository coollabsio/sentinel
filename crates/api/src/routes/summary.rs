//! Bulk current-snapshot endpoints. One request each replaces the per-series
//! (`/api/summary`) or per-container (`/api/containers/current`) round-trips a
//! fleet-wide dashboard would otherwise make. Both read the latest stored rows
//! from the reader connection; neither touches the collector or push paths.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::AppState;
use crate::routes::cpu::internal_error;
use crate::time::format_millis;
use crate::types::{
    ContainerCurrent, ContainerDiskUsage, ContainerStatus, CpuCurrent, CpuUsage, DiskUsage,
    HostInfo, HostSummary, LoadAverage, MemUsage, NetworkUsage,
};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/summary", get(summary))
        .route("/api/containers/current", get(containers_current))
}

/// Latest host CPU, memory and disk in one payload. Each key is `null` when its
/// table holds no rows yet.
async fn summary(State(state): State<Arc<AppState>>) -> Response {
    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || store.host_summary()).await;
    drop(permit);
    let store::HostSummaryRows {
        cpu,
        memory,
        disk,
        network,
        load,
        host,
    } = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    let body = HostSummary {
        // Matches /api/cpu/current: numeric percent, no human_friendly_time.
        cpu: cpu.map(|r| CpuCurrent {
            time: r.time.to_string(),
            percent: r.percent,
        }),
        memory: memory.map(|r| MemUsage {
            time: r.time.to_string(),
            total: r.total,
            available: r.available,
            used: r.used,
            used_percent: r.used_percent,
            free: r.free,
            human_friendly_time: debug.then(|| format_millis(r.time)),
        }),
        // Empty snapshot serializes as `null`, like the other keys.
        disk: Some(disk)
            .filter(|rows| !rows.is_empty())
            .map(|rows| rows.into_iter().map(|r| to_disk_usage(r, debug)).collect()),
        network: network.map(|r| to_network_usage(r.time, r.rx_bytes_per_sec, r.tx_bytes_per_sec, debug)),
        load: load.map(|r| LoadAverage {
            time: r.time.to_string(),
            load1: r.load1,
            load5: r.load5,
            load15: r.load15,
            human_friendly_time: debug.then(|| format_millis(r.time)),
        }),
        host: host.map(|r| HostInfo {
            time: r.time.to_string(),
            uptime_seconds: r.uptime_seconds,
            swap_total: r.swap_total,
            swap_used: r.swap_used,
            swap_free: r.swap_free,
            swap_used_percent: r.swap_used_percent,
            human_friendly_time: debug.then(|| format_millis(r.time)),
        }),
    };
    Json(body).into_response()
}

/// One row per container, each carrying its latest cpu/memory/disk sample.
async fn containers_current(State(state): State<Arc<AppState>>) -> Response {
    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || store.latest_container_metrics()).await;
    drop(permit);
    let rows = match result {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    let out: Vec<ContainerCurrent> = rows
        .into_iter()
        .map(|m| ContainerCurrent {
            id: m.container_id,
            // Container cpu reuses the history shape: percent as a string.
            cpu: m.cpu.map(|r| CpuUsage {
                time: r.time.to_string(),
                percent: format!("{:.2}", r.percent),
                human_friendly_time: debug.then(|| format_millis(r.time)),
            }),
            memory: m.memory.map(|r| MemUsage {
                time: r.time.to_string(),
                total: r.total,
                available: r.available,
                used: r.used,
                used_percent: r.used_percent,
                free: r.free,
                human_friendly_time: debug.then(|| format_millis(r.time)),
            }),
            disk: m.disk.map(|r| ContainerDiskUsage {
                time: r.time.to_string(),
                writable_layer: r.writable_layer,
                volumes_total: r.volumes_total,
                human_friendly_time: debug.then(|| format_millis(r.time)),
            }),
            network: m
                .network
                .map(|r| to_network_usage(r.time, r.rx_bytes_per_sec, r.tx_bytes_per_sec, debug)),
            status: m.status.map(|r| ContainerStatus {
                state: r.state,
                health: r.health_status,
                restart_count: r.restart_count,
            }),
            time: m.latest_time,
        })
        .collect();
    Json(out).into_response()
}

fn to_network_usage(time: i64, rx: f64, tx: f64, debug: bool) -> NetworkUsage {
    NetworkUsage {
        time: time.to_string(),
        rx_bytes_per_sec: rx,
        tx_bytes_per_sec: tx,
        human_friendly_time: debug.then(|| format_millis(time)),
    }
}

fn to_disk_usage(r: store::DiskRow, debug: bool) -> DiskUsage {
    DiskUsage {
        time: r.time.to_string(),
        mount: r.mount,
        total: r.total,
        used: r.used,
        available: r.available,
        used_percent: r.used_percent,
        human_friendly_time: debug.then(|| format_millis(r.time)),
    }
}

#[cfg(test)]
mod tests;
