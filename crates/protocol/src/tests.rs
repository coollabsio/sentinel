use std::any::type_name;

use prost::Message;

use super::*;

#[test]
fn network_capabilities_are_typed_and_versioned() {
    let capabilities = NETWORK_CAPABILITIES;
    assert_eq!(capabilities.len(), 9);
    assert!(capabilities.contains(&CAPABILITY_INGRESS_RECONCILE));
    assert_eq!(CAPABILITY_INGRESS_RECONCILE, "ingress.reconcile.v1");
    assert!(!capabilities.contains(&"discovery.corrosion.endpoints.reconcile.v1"));
    assert!(
        capabilities
            .iter()
            .all(|capability| capability.ends_with(".v1"))
    );

    let command = control::v1::Command {
        command_id: "network-1".into(),
        command_type: CAPABILITY_WIREGUARD_RECONCILE.into(),
        payload_version: 1,
        created_at_unix_ms: 1,
        payload: Some(control::v1::command::Payload::WireguardReconcile(
            control::v1::WireguardReconcileRequest {
                interface: "coolify0".into(),
                address: "10.240.0.2/32".into(),
                listen_port: 51820,
                revision: 2,
                peers: vec![control::v1::WireguardPeer {
                    public_key: "public".into(),
                    endpoint: "192.0.2.2:51820".into(),
                    allowed_ips: vec!["10.240.0.3/32".into()],
                    persistent_keepalive_seconds: 25,
                }],
                flux_probe_host: "10.240.0.1".into(),
            },
        )),
        expires_at_unix_ms: 2,
    };
    assert!(matches!(
        command.payload,
        Some(control::v1::command::Payload::WireguardReconcile(_))
    ));

    let firewall = control::v1::FirewallReconcileRequest {
        revision: 2,
        wireguard_port: 51820,
        cluster_cidr: "10.240.0.0/24".into(),
        local_node_ip: "10.240.0.2".into(),
        rules: vec![],
        wireguard_interface: "coolify0".into(),
        flux_probe_host: "10.240.0.1".into(),
        workload_cidrs: vec!["100.64.0.0/24".into()],
        ingress_rules: vec![],
    };
    assert_eq!(firewall.flux_probe_host, "10.240.0.1");

    let corrosion = control::v1::CorrosionReconcileRequest {
        version: "v1.0.0".into(),
        cluster_id: "cluster-one".into(),
        bind_address: "10.240.0.2".into(),
        peers: vec![],
        node_dns_name: "worker-1".into(),
    };
    let decoded =
        control::v1::CorrosionReconcileRequest::decode(corrosion.encode_to_vec().as_slice())
            .unwrap();
    assert_eq!(decoded.node_dns_name, "worker-1");
}

#[test]
fn publishes_version_one_and_initial_capabilities() {
    assert_eq!(PROTOCOL_MIN, 1);
    assert_eq!(PROTOCOL_MAX, 1);
    assert_eq!(CAPABILITY_SYSTEM_PING, "system.ping.v1");
    assert_eq!(CAPABILITY_SYSTEM_INFO, "system.info.v1");
    assert_eq!(CAPABILITY_CONTAINER_LIST, "container.list.v1");
    assert_eq!(CAPABILITY_WORKLOAD_DEPLOY, "workload.deploy.v1");
    assert_eq!(CAPABILITY_WORKLOAD_RESOURCES, "workload.resources.v1");
    assert_eq!(CAPABILITY_WORKLOAD_LIFECYCLE, "workload.lifecycle.v1");
    assert_eq!(CAPABILITY_LOGS_READ, "logs.read.v1");
}

#[test]
fn logs_read_command_and_result_round_trip() {
    let command = control::v1::Command {
        command_id: "logs-1".into(),
        command_type: CAPABILITY_LOGS_READ.into(),
        payload_version: 1,
        created_at_unix_ms: 1,
        payload: Some(control::v1::command::Payload::LogsRead(
            control::v1::LogsReadRequest {
                source: control::v1::LogSource::Corrosion.into(),
                limit: 200,
            },
        )),
        expires_at_unix_ms: 2,
    };
    assert_eq!(
        control::v1::Command::decode(command.encode_to_vec().as_slice()).unwrap(),
        command
    );

    let result = control::v1::CommandResult {
        event_id: "logs-1:result".into(),
        command_id: "logs-1".into(),
        status: control::v1::CommandStatus::Succeeded.into(),
        observed_at_unix_ms: 3,
        payload: Some(control::v1::command_result::Payload::LogsRead(
            control::v1::LogsReadResult {
                source: control::v1::LogSource::Sentinel.into(),
                events: vec![control::v1::LogEvent {
                    timestamp_unix_ms: 1_700_000_000_000,
                    level: "info".into(),
                    component: "control::connection".into(),
                    message: "Sentinel connected to Flux".into(),
                    fields: [("transport".to_string(), "Tls".to_string())].into(),
                }],
                truncated: true,
            },
        )),
    };
    assert_eq!(
        control::v1::CommandResult::decode(result.encode_to_vec().as_slice()).unwrap(),
        result
    );
}

#[test]
fn container_logs_command_and_result_round_trip() {
    assert_eq!(CAPABILITY_CONTAINER_LOGS, "container.logs.v1");
    let command = control::v1::Command {
        command_id: "container-logs-1".into(),
        command_type: CAPABILITY_CONTAINER_LOGS.into(),
        payload_version: 1,
        created_at_unix_ms: 1,
        payload: Some(control::v1::command::Payload::ContainerLogs(
            control::v1::ContainerLogsRequest {
                name: "coolify-app".into(),
                lines: 100,
                since_unix_seconds: Some(1_700_000_000),
            },
        )),
        expires_at_unix_ms: 2,
    };
    assert_eq!(
        control::v1::Command::decode(command.encode_to_vec().as_slice()).unwrap(),
        command
    );

    let result = control::v1::CommandResult {
        event_id: "container-logs-1:result".into(),
        command_id: "container-logs-1".into(),
        status: control::v1::CommandStatus::Succeeded.into(),
        observed_at_unix_ms: 3,
        payload: Some(control::v1::command_result::Payload::ContainerLogs(
            control::v1::ContainerLogsResult {
                name: "coolify-app".into(),
                logs: "2026-10-06T10:00:00.123456789Z ready\n".into(),
                truncated: true,
            },
        )),
    };
    assert_eq!(
        control::v1::CommandResult::decode(result.encode_to_vec().as_slice()).unwrap(),
        result
    );
}

#[test]
fn validates_container_names() {
    for name in ["a", "coolify-app_1.web", "0abc", &"a".repeat(128)] {
        assert!(valid_container_name(name), "{name}");
    }
    for name in [
        "",
        ".hidden",
        "..",
        "-flag",
        "_x",
        "has space",
        "semi;colon",
        "slash/name",
        "dollar$x",
        &"a".repeat(129),
    ] {
        assert!(!valid_container_name(name), "{name}");
    }
}

#[test]
fn selects_the_highest_overlapping_protocol() {
    assert_eq!(select_protocol(1, 3, 2, 4), Some(3));
    assert_eq!(select_protocol(1, 1, 1, 1), Some(1));
    assert_eq!(select_protocol(1, 1, 2, 2), None);
}

#[test]
fn rejects_invalid_protocol_ranges() {
    assert_eq!(select_protocol(0, 1, 1, 1), None);
    assert_eq!(select_protocol(1, 0, 1, 1), None);
    assert_eq!(select_protocol(2, 1, 1, 2), None);
    assert_eq!(select_protocol(1, 2, 2, 1), None);
}

#[test]
fn intersects_capabilities_in_supported_order_without_duplicates() {
    let granted = vec![
        CAPABILITY_SYSTEM_INFO.to_string(),
        CAPABILITY_CONTAINER_LIST.to_string(),
        CAPABILITY_WORKLOAD_DEPLOY.to_string(),
        CAPABILITY_SYSTEM_PING.to_string(),
        CAPABILITY_SYSTEM_PING.to_string(),
    ];
    let advertised = vec![
        CAPABILITY_SYSTEM_PING.to_string(),
        CAPABILITY_SYSTEM_INFO.to_string(),
        CAPABILITY_CONTAINER_LIST.to_string(),
        CAPABILITY_WORKLOAD_DEPLOY.to_string(),
    ];
    let supported = [
        CAPABILITY_SYSTEM_PING,
        CAPABILITY_SYSTEM_PING,
        CAPABILITY_SYSTEM_INFO,
        CAPABILITY_CONTAINER_LIST,
        CAPABILITY_WORKLOAD_DEPLOY,
        "future.unsupported.v1",
    ];

    assert_eq!(
        intersect_capabilities(&granted, &advertised, &supported),
        vec![
            CAPABILITY_SYSTEM_PING.to_string(),
            CAPABILITY_SYSTEM_INFO.to_string(),
            CAPABILITY_CONTAINER_LIST.to_string(),
            CAPABILITY_WORKLOAD_DEPLOY.to_string(),
        ]
    );
}

#[test]
fn hello_round_trips_and_ignores_unknown_fields() {
    let hello = control::v1::Hello {
        server_id: "server-uuid".to_string(),
        sentinel_version: "1.0.1".to_string(),
        protocol_min: 1,
        protocol_max: 1,
        capabilities: vec![CAPABILITY_SYSTEM_PING.to_string()],
        boot_id: "boot-id".to_string(),
        trust_bundle_version: 7,
    };
    let mut encoded = hello.encode_to_vec();

    // Unknown field 99, wire type 0, value 1.
    encoded.extend_from_slice(&[0x98, 0x06, 0x01]);

    let decoded = control::v1::Hello::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded, hello);
}

#[test]
fn generates_grpc_client_and_server_types() {
    assert!(
        type_name::<control::v1::agent_client::AgentClient<tonic::transport::Channel>>()
            .contains("AgentClient")
    );
    assert!(type_name::<control::v1::agent_server::AgentServer<()>>().contains("AgentServer"));
}

#[test]
fn trust_bundle_update_command_and_result_round_trip() {
    assert_eq!(CAPABILITY_TRUST_BUNDLE_UPDATE, "trust.bundle.update.v1");
    let command = control::v1::Command {
        command_id: "trust-1".into(),
        command_type: CAPABILITY_TRUST_BUNDLE_UPDATE.into(),
        payload_version: 1,
        created_at_unix_ms: 1,
        payload: Some(control::v1::command::Payload::TrustBundleUpdate(
            control::v1::TrustBundleUpdateRequest {
                version: 2,
                bundle_pem: "-----BEGIN CERTIFICATE-----\n".into(),
            },
        )),
        expires_at_unix_ms: 2,
    };
    assert_eq!(
        control::v1::Command::decode(command.encode_to_vec().as_slice()).unwrap(),
        command
    );
    let result = control::v1::CommandResult {
        event_id: "trust-1:result".into(),
        command_id: "trust-1".into(),
        status: control::v1::CommandStatus::Succeeded.into(),
        observed_at_unix_ms: 3,
        payload: Some(control::v1::command_result::Payload::TrustBundleUpdate(
            control::v1::TrustBundleUpdateResult {
                installed_version: 2,
                changed: true,
            },
        )),
    };
    assert_eq!(
        control::v1::CommandResult::decode(result.encode_to_vec().as_slice()).unwrap(),
        result
    );
}

#[test]
fn ingress_reconcile_command_and_result_round_trip() {
    let command = control::v1::Command {
        command_id: "ingress-1".into(),
        command_type: CAPABILITY_INGRESS_RECONCILE.into(),
        payload_version: 1,
        created_at_unix_ms: 1,
        payload: Some(control::v1::command::Payload::IngressReconcile(
            control::v1::IngressReconcileRequest {
                enabled: true,
                caddy_version: "v2.11.7".into(),
                revision: 4,
                routes: vec![control::v1::IngressRoute {
                    host: "app.example.com".into(),
                    workload_id: "web".into(),
                    namespace: "default".into(),
                    port: 3000,
                }],
                names: vec![control::v1::WorkloadName {
                    name: "web".into(),
                    workload_id: "uuid-web".into(),
                    namespace: "default".into(),
                }],
            },
        )),
        expires_at_unix_ms: 2,
    };
    assert_eq!(
        control::v1::Command::decode(command.encode_to_vec().as_slice()).unwrap(),
        command
    );
    let result = control::v1::CommandResult {
        event_id: "ingress-1:result".into(),
        command_id: "ingress-1".into(),
        status: control::v1::CommandStatus::Succeeded.into(),
        observed_at_unix_ms: 3,
        payload: Some(control::v1::command_result::Payload::IngressReconcile(
            control::v1::IngressReconcileResult {
                enabled: true,
                caddy_version: "v2.11.7".into(),
                active: true,
                revision: 4,
                route_count: 1,
                name_count: 1,
            },
        )),
    };
    assert_eq!(
        control::v1::CommandResult::decode(result.encode_to_vec().as_slice()).unwrap(),
        result
    );
}
