use std::any::type_name;

use prost::Message;

use super::*;

#[test]
fn publishes_version_one_and_initial_capabilities() {
    assert_eq!(PROTOCOL_MIN, 1);
    assert_eq!(PROTOCOL_MAX, 1);
    assert_eq!(CAPABILITY_SYSTEM_PING, "system.ping.v1");
    assert_eq!(CAPABILITY_SYSTEM_INFO, "system.info.v1");
    assert_eq!(CAPABILITY_CONTAINER_LIST, "container.list.v1");
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
        CAPABILITY_SYSTEM_PING.to_string(),
        CAPABILITY_SYSTEM_PING.to_string(),
    ];
    let advertised = vec![
        CAPABILITY_SYSTEM_PING.to_string(),
        CAPABILITY_SYSTEM_INFO.to_string(),
        CAPABILITY_CONTAINER_LIST.to_string(),
    ];
    let supported = [
        CAPABILITY_SYSTEM_PING,
        CAPABILITY_SYSTEM_PING,
        CAPABILITY_SYSTEM_INFO,
        CAPABILITY_CONTAINER_LIST,
        "future.unsupported.v1",
    ];

    assert_eq!(
        intersect_capabilities(&granted, &advertised, &supported),
        vec![
            CAPABILITY_SYSTEM_PING.to_string(),
            CAPABILITY_SYSTEM_INFO.to_string(),
            CAPABILITY_CONTAINER_LIST.to_string(),
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
