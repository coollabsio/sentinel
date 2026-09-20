use std::any::type_name;

use prost::Message;

use super::*;

#[test]
fn network_capabilities_are_typed_and_versioned() {
    let capabilities = NETWORK_CAPABILITIES;
    assert_eq!(capabilities.len(), 9);
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

    let endpoints = control::v1::CorrosionEndpointReconcileRequest {
        owner_node_ip: "10.240.0.2".into(),
        endpoints: vec![control::v1::WorkloadEndpoint {
            workload_id: "web".into(),
            namespace: "default".into(),
            owner_node_ip: "10.240.0.2".into(),
            container_ip: "10.240.0.2".into(),
            state: "running".into(),
            health: "healthy".into(),
            updated_at_unix_seconds: 1_700_000_000,
            expires_at_unix_seconds: 1_700_000_300,
        }],
    };
    assert_eq!(
        endpoints.endpoints[0].owner_node_ip,
        endpoints.owner_node_ip
    );
    assert_eq!(
        CAPABILITY_CORROSION_ENDPOINT_RECONCILE,
        "discovery.corrosion.endpoints.reconcile.v1"
    );
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
