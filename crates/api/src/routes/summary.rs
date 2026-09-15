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
    ContainerCurrent, ContainerDiskUsage, CpuCurrent, CpuUsage, DiskUsage, HostSummary, MemUsage,
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
    let store::HostSummaryRows { cpu, memory, disk } = match result {
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
        // Empty snapshot serializes as `null`, like the other two keys.
        disk: Some(disk)
            .filter(|rows| !rows.is_empty())
            .map(|rows| rows.into_iter().map(|r| to_disk_usage(r, debug)).collect()),
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
            time: m.latest_time,
        })
        .collect();
    Json(out).into_response()
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
