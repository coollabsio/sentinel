use serde::Serialize;

#[derive(Clone)]
pub struct EventReporter {
    client: reqwest::Client,
    endpoint: Option<String>,
    token: Option<String>,
}

pub struct ConnectedEvent<'a> {
    pub server_id: &'a str,
    pub connection_id: &'a str,
    pub sentinel_version: &'a str,
    pub protocol_version: u32,
    pub trust_bundle_version: u64,
    pub transport: &'a str,
    pub capabilities: &'a [String],
}

/// The generation and the hash of the desired set of a Sentinel with
/// `workload.reconcile.v1`.
#[derive(Clone, Copy)]
pub struct WorkloadSetState<'a> {
    pub generation: u64,
    pub set_hash: &'a str,
}

#[derive(Serialize, Default)]
struct Event<'a> {
    event: &'a str,
    server_id: &'a str,
    connection_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sentinel_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_at_unix_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust_bundle_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workload_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workload_set_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workload: Option<WorkloadStatusEvent<'a>>,
}

/// A `WorkloadStatus` of Sentinel for Coolify.
#[derive(Serialize)]
struct WorkloadStatusEvent<'a> {
    workload_id: &'a str,
    revision_id: &'a str,
    operation_id: &'a str,
    status: &'static str,
    reason: &'a str,
    generation: u64,
    container_name: &'a str,
    runtime_id: &'a str,
    autonomous: bool,
}

pub(crate) fn workload_status_name(status: i32) -> &'static str {
    use sentinel_protocol::control::v1::WorkloadStatusValue;
    match WorkloadStatusValue::try_from(status) {
        Ok(WorkloadStatusValue::Progressing) => "progressing",
        Ok(WorkloadStatusValue::Healthy) => "healthy",
        Ok(WorkloadStatusValue::Failed) => "failed",
        Ok(WorkloadStatusValue::Stopped) => "stopped",
        Ok(WorkloadStatusValue::Removed) => "removed",
        _ => "unknown",
    }
}

impl EventReporter {
    pub fn new(endpoint: Option<String>, token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("Flux event HTTP client configuration is valid"),
            endpoint,
            token,
        }
    }

    pub async fn connected(
        &self,
        connection: ConnectedEvent<'_>,
        workload_set: Option<WorkloadSetState<'_>>,
    ) {
        self.send(Event {
            event: "connected",
            server_id: connection.server_id,
            connection_id: connection.connection_id,
            sentinel_version: Some(connection.sentinel_version),
            protocol_version: Some(connection.protocol_version),
            trust_bundle_version: Some(connection.trust_bundle_version),
            transport: Some(connection.transport),
            capabilities: Some(connection.capabilities),
            workload_generation: workload_set.map(|set| set.generation),
            workload_set_hash: workload_set.map(|set| set.set_hash),
            ..Default::default()
        })
        .await;
    }

    pub async fn heartbeat(
        &self,
        server_id: &str,
        connection_id: &str,
        observed_at_unix_ms: i64,
        workload_set: Option<WorkloadSetState<'_>>,
    ) {
        self.send(Event {
            event: "heartbeat",
            server_id,
            connection_id,
            observed_at_unix_ms: Some(observed_at_unix_ms),
            workload_generation: workload_set.map(|set| set.generation),
            workload_set_hash: workload_set.map(|set| set.set_hash),
            ..Default::default()
        })
        .await;
    }

    pub async fn disconnected(&self, server_id: &str, connection_id: &str) {
        self.send(Event {
            event: "disconnected",
            server_id,
            connection_id,
            ..Default::default()
        })
        .await;
    }

    pub async fn runtime_changed(
        &self,
        server_id: &str,
        connection_id: &str,
        event_id: &str,
        observed_at_unix_ms: i64,
    ) {
        self.send(Event {
            event: "runtime_changed",
            server_id,
            connection_id,
            observed_at_unix_ms: Some(observed_at_unix_ms),
            event_id: Some(event_id),
            ..Default::default()
        })
        .await;
    }

    /// Reports a workload status. True when Coolify stored it, so Flux can
    /// acknowledge it to Sentinel; Sentinel sends it again otherwise.
    pub async fn workload_status(
        &self,
        server_id: &str,
        connection_id: &str,
        status: &sentinel_protocol::control::v1::WorkloadStatus,
    ) -> bool {
        self.send(workload_status_event(server_id, connection_id, status))
            .await
    }

    async fn send(&self, event: Event<'_>) -> bool {
        let (Some(endpoint), Some(token)) = (&self.endpoint, &self.token) else {
            return false;
        };
        match self
            .client
            .post(endpoint)
            .bearer_auth(token)
            .json(&event)
            .send()
            .await
            .and_then(|response| response.error_for_status())
        {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(%error, "Flux could not report connection event");
                false
            }
        }
    }
}

fn workload_status_event<'a>(
    server_id: &'a str,
    connection_id: &'a str,
    status: &'a sentinel_protocol::control::v1::WorkloadStatus,
) -> Event<'a> {
    Event {
        event: "workload_status",
        server_id,
        connection_id,
        observed_at_unix_ms: Some(status.observed_at_unix_ms),
        event_id: Some(&status.event_id),
        workload: Some(WorkloadStatusEvent {
            workload_id: &status.workload_id,
            revision_id: &status.revision_id,
            operation_id: &status.operation_id,
            status: workload_status_name(status.status),
            reason: &status.reason,
            generation: status.generation,
            container_name: &status.container_name,
            runtime_id: &status.runtime_id,
            autonomous: status.autonomous,
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, workload_status_event};
    use sentinel_protocol::control::v1::{WorkloadStatus, WorkloadStatusValue};

    #[test]
    fn serializes_workload_status_events_for_laravel() {
        let status = WorkloadStatus {
            event_id: "status-1".into(),
            workload_id: "workload-1".into(),
            revision_id: "revision-1".into(),
            operation_id: "operation-1".into(),
            status: WorkloadStatusValue::Failed as i32,
            reason: "The health check failed.".into(),
            generation: 7,
            observed_at_unix_ms: 1_700_000_000_000,
            container_name: "coolify-app".into(),
            runtime_id: "abc".into(),
            autonomous: false,
        };
        let value =
            serde_json::to_value(workload_status_event("node-1", "connection-1", &status)).unwrap();

        assert_eq!(value["event"], "workload_status");
        assert_eq!(value["event_id"], "status-1");
        assert_eq!(value["workload"]["status"], "failed");
        assert_eq!(value["workload"]["generation"], 7);
        assert_eq!(value["workload"]["operation_id"], "operation-1");
        assert_eq!(value["workload"]["reason"], "The health check failed.");
        assert!(value.get("workload_generation").is_none());
    }

    #[test]
    fn serializes_runtime_change_events_for_laravel() {
        let value = serde_json::to_value(Event {
            event: "runtime_changed",
            server_id: "node-1",
            connection_id: "connection-1",
            observed_at_unix_ms: Some(1_700_000_000_000),
            event_id: Some("runtime-1"),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(value["event"], "runtime_changed");
        assert_eq!(value["server_id"], "node-1");
        assert_eq!(value["connection_id"], "connection-1");
        assert_eq!(value["event_id"], "runtime-1");
        assert_eq!(value["observed_at_unix_ms"], 1_700_000_000_000_i64);
    }

    #[test]
    fn serializes_negotiated_capabilities_for_laravel() {
        let capabilities = vec![
            "container.list.v1".to_string(),
            "workload.deploy.v1".to_string(),
        ];
        let value = serde_json::to_value(Event {
            event: "connected",
            server_id: "node-1",
            connection_id: "connection-1",
            sentinel_version: Some("main"),
            protocol_version: Some(1),
            trust_bundle_version: Some(1),
            transport: Some("tls"),
            capabilities: Some(&capabilities),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(
            value["capabilities"],
            serde_json::json!(["container.list.v1", "workload.deploy.v1"])
        );
    }
}
