use serde::Serialize;

#[derive(Clone)]
pub struct EventReporter {
    client: reqwest::Client,
    endpoint: Option<String>,
    token: Option<String>,
}

#[derive(Serialize)]
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
        server_id: &str,
        connection_id: &str,
        sentinel_version: &str,
        protocol_version: u32,
        trust_bundle_version: u64,
        transport: &str,
    ) {
        self.send(Event {
            event: "connected",
            server_id,
            connection_id,
            sentinel_version: Some(sentinel_version),
            protocol_version: Some(protocol_version),
            observed_at_unix_ms: None,
            trust_bundle_version: Some(trust_bundle_version),
            transport: Some(transport),
            event_id: None,
        })
        .await;
    }

    pub async fn heartbeat(&self, server_id: &str, connection_id: &str, observed_at_unix_ms: i64) {
        self.send(Event {
            event: "heartbeat",
            server_id,
            connection_id,
            sentinel_version: None,
            protocol_version: None,
            observed_at_unix_ms: Some(observed_at_unix_ms),
            trust_bundle_version: None,
            transport: None,
            event_id: None,
        })
        .await;
    }

    pub async fn disconnected(&self, server_id: &str, connection_id: &str) {
        self.send(Event {
            event: "disconnected",
            server_id,
            connection_id,
            sentinel_version: None,
            protocol_version: None,
            observed_at_unix_ms: None,
            trust_bundle_version: None,
            transport: None,
            event_id: None,
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
            sentinel_version: None,
            protocol_version: None,
            observed_at_unix_ms: Some(observed_at_unix_ms),
            trust_bundle_version: None,
            transport: None,
            event_id: Some(event_id),
        })
        .await;
    }

    async fn send(&self, event: Event<'_>) {
        let (Some(endpoint), Some(token)) = (&self.endpoint, &self.token) else {
            return;
        };
        if let Err(error) = self
            .client
            .post(endpoint)
            .bearer_auth(token)
            .json(&event)
            .send()
            .await
            .and_then(|response| response.error_for_status())
        {
            tracing::warn!(%error, "Flux could not report connection event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Event;

    #[test]
    fn serializes_runtime_change_events_for_laravel() {
        let value = serde_json::to_value(Event {
            event: "runtime_changed",
            server_id: "node-1",
            connection_id: "connection-1",
            sentinel_version: None,
            protocol_version: None,
            observed_at_unix_ms: Some(1_700_000_000_000),
            trust_bundle_version: None,
            transport: None,
            event_id: Some("runtime-1"),
        })
        .unwrap();

        assert_eq!(value["event"], "runtime_changed");
        assert_eq!(value["server_id"], "node-1");
        assert_eq!(value["connection_id"], "connection-1");
        assert_eq!(value["event_id"], "runtime-1");
        assert_eq!(value["observed_at_unix_ms"], 1_700_000_000_000_i64);
    }
}
