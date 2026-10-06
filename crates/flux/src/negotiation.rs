use sentinel_protocol::control::v1::Hello;
use sentinel_protocol::{
    CAPABILITY_CONTAINER_LIST, CAPABILITY_CONTAINER_LOGS, CAPABILITY_LOGS_READ,
    CAPABILITY_SYSTEM_INFO, CAPABILITY_SYSTEM_PING, CAPABILITY_TRUST_BUNDLE_UPDATE,
    CAPABILITY_WORKLOAD_DEPLOY, CAPABILITY_WORKLOAD_LIFECYCLE, CAPABILITY_WORKLOAD_RESOURCES,
    NETWORK_CAPABILITIES, PROTOCOL_MAX, PROTOCOL_MIN, intersect_capabilities, select_protocol,
};

use crate::CredentialClaims;

pub struct Negotiated {
    pub protocol_version: u32,
    pub capabilities: Vec<String>,
}

pub fn negotiate(claims: &CredentialClaims, hello: &Hello) -> Result<Negotiated, &'static str> {
    if hello.server_id.is_empty()
        || hello.server_id != claims.subject
        || hello.sentinel_version.is_empty()
        || hello.boot_id.is_empty()
    {
        return Err("invalid identity");
    }
    let credential_protocol = select_protocol(
        claims.protocol_min,
        claims.protocol_max,
        hello.protocol_min,
        hello.protocol_max,
    )
    .ok_or("protocol mismatch")?;
    let protocol_version = select_protocol(
        PROTOCOL_MIN,
        PROTOCOL_MAX,
        credential_protocol,
        credential_protocol,
    )
    .ok_or("protocol mismatch")?;
    let supported = [
        CAPABILITY_SYSTEM_PING,
        CAPABILITY_SYSTEM_INFO,
        CAPABILITY_CONTAINER_LIST,
        CAPABILITY_WORKLOAD_DEPLOY,
        CAPABILITY_WORKLOAD_RESOURCES,
        CAPABILITY_WORKLOAD_LIFECYCLE,
        CAPABILITY_LOGS_READ,
        CAPABILITY_CONTAINER_LOGS,
        CAPABILITY_TRUST_BUNDLE_UPDATE,
    ]
    .into_iter()
    .chain(NETWORK_CAPABILITIES)
    .collect::<Vec<_>>();
    let capabilities =
        intersect_capabilities(&claims.capabilities, &hello.capabilities, &supported);
    // A newer Sentinel may advertise capabilities that this credential does not
    // grant or that this Flux does not know yet. They are left out of the
    // accepted set instead of refusing the connection.
    let ignored: Vec<&str> = hello
        .capabilities
        .iter()
        .map(String::as_str)
        .filter(|capability| !capabilities.iter().any(|accepted| accepted == capability))
        .collect();
    if !ignored.is_empty() {
        tracing::info!(
            server_id = %hello.server_id,
            ignored = ?ignored,
            "Flux ignored capabilities that are not granted or not supported"
        );
    }
    Ok(Negotiated {
        protocol_version,
        capabilities,
    })
}
