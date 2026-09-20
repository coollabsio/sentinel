use sentinel_protocol::control::v1::Hello;
use sentinel_protocol::{
    CAPABILITY_CONTAINER_LIST, CAPABILITY_SYSTEM_INFO, CAPABILITY_SYSTEM_PING,
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
    if hello
        .capabilities
        .iter()
        .any(|capability| !claims.capabilities.contains(capability))
    {
        return Err("capability was not granted");
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
    ]
    .into_iter()
    .chain(NETWORK_CAPABILITIES)
    .collect::<Vec<_>>();
    let capabilities =
        intersect_capabilities(&claims.capabilities, &hello.capabilities, &supported);
    Ok(Negotiated {
        protocol_version,
        capabilities,
    })
}
