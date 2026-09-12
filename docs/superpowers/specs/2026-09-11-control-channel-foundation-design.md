# Sentinel control-channel foundation design

**Date:** 2026-09-11  
**Status:** Proposed for implementation review  
**Scope:** The first Coolify v5 vertical slice through Coolify, Flux, and Sentinel

## 1. Goal

Add a dormant control-channel client to Sentinel and add Flux as a separate binary in the Sentinel Rust workspace. The same Sentinel product and executable supports the existing container deployment and the new host-native deployment.

The first vertical slice must let Coolify:

1. Assign an opted-in Sentinel to Flux.
2. Observe the Sentinel connection.
3. Store a durable read-only command.
4. Deliver `system.ping.v1` or `system.info.v1` through Flux.
5. Store the acknowledged result.

The change must not alter existing Sentinel behavior when the control channel is disabled. Normal Sentinel releases must continue while the v5 work is incomplete.

## 2. Non-goals

This slice does not include:

- Container mutations or deployments.
- Migration of the existing HTTP push service to gRPC.
- Corrosion or distributed service discovery.
- WireGuard installation or changes.
- Firewall management.
- Builder integration.
- Database lifecycle or backups.
- Log or terminal streaming.
- Multiple Flux instances or Cloud routing.
- Local durable command state in Sentinel.
- General v5 production activation.

## 3. Components and ownership

### Coolify

Coolify owns:

- User authorization and team isolation.
- Server ownership.
- The global and per-server rollout gates.
- Flux assignment.
- Short-lived Flux credential issuance.
- Durable command and event records.
- Command state transitions.
- Retry and reconciliation decisions.
- Audit data.

PostgreSQL is the durable source of truth. Redis can run Laravel queues, locks, cache, and dashboard events, but Redis does not own command truth.

### Flux

Flux owns:

- Long-lived Sentinel gRPC streams.
- Sentinel authentication.
- Protocol negotiation.
- The in-memory `server_id` to connection registry.
- Bounded per-connection delivery queues.
- Short-lived request and response correlation.
- Heartbeat expiry.
- Transport errors and timeouts.

Flux does not own deployments, product state, authorization, scheduling, or durable commands. It does not connect to PostgreSQL.

### Sentinel

Sentinel owns:

- The outbound Flux connection.
- Reconnect behavior.
- Host-local command validation and execution.
- Host fact collection.
- In-memory active-command and recent-result caches.
- Reporting acknowledgements and final results.

Sentinel does not own Coolify desired state or deployment workflows.

## 4. Repository and release layout

Flux lives in the existing Sentinel workspace. It is a separate binary with a separate runtime and release artifact.

```text
sentinel/
├── Cargo.toml
├── src/
│   └── main.rs                 Existing Sentinel binary
└── crates/
    ├── api/
    ├── collector/
    ├── config/
    ├── control/                Sentinel control-channel client
    ├── docker/
    ├── flux/                   Separate Flux binary
    ├── protocol/               Shared protobuf and protocol constants
    ├── push/
    ├── store/
    └── traffic/
```

The workspace produces at least:

```text
sentinel
flux
```

Sentinel and Flux can release at different times. The protocol crate is an internal workspace dependency. Compatibility is based on the wire protocol range and capabilities, not matching binary versions.

Sentinel keeps its current name in both deployment forms. The project does not introduce a second `coolify-agent` product or executable. GitHub Actions builds the container image and versioned host-native Linux artifacts from the same Sentinel source revision.

During migration, the current container Sentinel continues existing metrics and traffic work while the host-native Sentinel owns the v5 control connection and new host operations. Coolify assigns capability ownership explicitly. The two processes must not own the same capability at the same time. Capabilities move to the host process in stages, and Coolify retires the container only after parity and rollback validation.

The published Sentinel image contains the control client. A runtime environment gate keeps it disabled. There is no separate `sentinel-v5` image and no compile-time control-channel feature gate.

Flux uses its own image or binary artifact. It is not embedded in the Sentinel process.

## 5. Rollout gates and configuration

### Sentinel

The only new Sentinel environment variable is:

```text
CONTROL_PLANE_ENABLED=false
```

Sentinel reuses:

```text
TOKEN
PUSH_ENDPOINT
```

Rules:

- `CONTROL_PLANE_ENABLED` defaults to `false`.
- When false, Sentinel does not create the control service or make assignment and gRPC requests.
- When true, Sentinel uses `PUSH_ENDPOINT` as the Coolify base URL.
- When true, Sentinel uses `TOKEN` to authenticate its assignment request.
- No Flux URL or Flux credential is supplied through Sentinel environment variables.
- No new control-channel file or database table is created in Sentinel.

### Coolify

Coolify has two gates:

1. An instance gate that permits the experimental control channel.
2. A per-server opt-in setting.

Coolify sets `CONTROL_PLANE_ENABLED=true` only when both gates are enabled. The host-native Sentinel is the production owner of the v5 control connection. A containerized Sentinel can enable it only in an explicit development protocol test. Existing v4 Sentinel containers omit the variable or receive `false`.

The first implementation remains restricted to development or an equivalent explicit experimental rollout gate. It must not activate the archived v5 runtime in production.

### Remote kill switch

The assignment endpoint can return `enabled: false`. Sentinel then keeps its existing services active, does not connect to Flux, and retries assignment after the supplied delay.

## 6. Assignment contract

Sentinel requests an assignment at startup when the control channel is enabled.

```http
POST /api/v1/sentinel/control/assignment HTTP/1.1
Authorization: Bearer <existing TOKEN>
Content-Type: application/json
```

Request:

```json
{
  "sentinel_version": "1.0.1",
  "protocol_min": 1,
  "protocol_max": 1,
  "capabilities": [
    "system.ping.v1",
    "system.info.v1"
  ]
}
```

Enabled response:

```json
{
  "enabled": true,
  "server_id": "server-uuid",
  "flux_url": "https://agent.coolify.example.com",
  "credential": "short-lived-signed-token",
  "credential_expires_at": "2026-09-11T15:00:00Z",
  "protocol_min": 1,
  "protocol_max": 1,
  "heartbeat_interval_seconds": 30
}
```

Disabled response:

```json
{
  "enabled": false,
  "retry_after_seconds": 3600
}
```

Coolify derives the server from the existing Sentinel token. It does not accept a client-selected server ID.

Sentinel joins the assignment URL to the parsed `PUSH_ENDPOINT` base URL. It must not use raw string concatenation.

### Assignment errors

| Result | Behavior |
|---|---|
| `200`, enabled | Validate the response and connect to Flux. |
| `200`, disabled | Wait for `retry_after_seconds`, then request another assignment. |
| `401` or `403` | Log an authentication error and retry no faster than every 15 minutes. |
| `404` | Treat Coolify as not supporting the control channel and retry no faster than every hour. |
| `409` | Treat the protocol or server state as incompatible and retry no faster than every hour. |
| `429` | Honor `Retry-After`. |
| `5xx` | Retry with exponential backoff and jitter. |
| Network error | Retry with exponential backoff and jitter. |

Assignment failure never stops the existing Sentinel services.

## 7. Flux credential

The existing Sentinel `TOKEN` authenticates only to Coolify. Coolify issues a short-lived credential for the Flux stream.

The initial credential is a signed JWT with these required claims:

```text
iss     Coolify installation identity
aud     flux
purpose node-control-channel
sub     server UUID
jti     unique token ID
iat     issued-at time
nbf     not-before time
exp     expiry time
caps    explicit capability list
pmin    minimum protocol version
pmax    maximum protocol version
```

The `purpose` claim prevents use of the credential outside the v5 control channel. Contract tests require this exact claim and value.

Requirements:

- Use asymmetric signatures.
- Pin the accepted algorithms in Flux.
- Reject missing and unknown key IDs.
- Reject wildcard capabilities.
- Reject expired and not-yet-valid credentials.
- Reject credentials whose lifetime exceeds the configured maximum.
- Bind `sub` to the `server_id` in the first gRPC `Hello` message.
- Do not log the credential.

The first default lifetime is 15 minutes. Sentinel requests a new assignment before expiry and opens a replacement stream. Flux drops the old stream when the credential expires or when the new connection replaces it.

Sentinel keeps the Flux credential only in memory.

## 8. Transport

Sentinel opens one outbound TLS-protected bidirectional gRPC stream to Flux.

```protobuf
service Agent {
  rpc Stream(stream AgentMessage) returns (stream ControlMessage);
}
```

TLS is required outside explicit local test environments. Sentinel validates the Flux certificate with the normal system trust store. Private installations can use a certificate signed by a configured system-trusted CA. Certificate pinning is not part of the first slice.

Initial transport limits:

- Maximum inbound message size: 1 MiB.
- Maximum outbound message size: 1 MiB.
- Per-Sentinel outbound command queue: 32 messages.
- One active stream per server ID.
- Heartbeat interval supplied by assignment, clamped to 10 through 120 seconds.
- A connection expires after three missed heartbeat intervals.
- Initial connection timeout: 10 seconds.
- Initial command delivery timeout: 10 seconds.
- Read-only command completion timeout: 30 seconds.

All limits are server-side configurable. Sentinel treats invalid assignment limits as an assignment error.

## 9. Protocol negotiation

The first agent message must be `Hello`.

```text
Hello
- server_id
- sentinel_version
- protocol_min
- protocol_max
- capabilities
- boot_id
```

Flux selects the highest mutually supported protocol version and returns `Welcome`:

```text
Welcome
- connection_id
- protocol_version
- heartbeat_interval_seconds
- accepted_capabilities
- server_time
```

Flux rejects the stream when:

- `Hello` is not the first message.
- The JWT subject differs from `Hello.server_id`.
- The protocol ranges do not overlap.
- Sentinel advertises a capability not granted by its credential.
- Another required field is invalid.

Flux accepts only the intersection of credential capabilities, Sentinel capabilities, and Flux-supported capabilities.

Binary versions are diagnostic data. They do not control compatibility.

## 10. Message envelopes

`AgentMessage` contains one of:

```text
Hello
Heartbeat
CommandAccepted
CommandResult
```

`ControlMessage` contains one of:

```text
Welcome
Command
EventAck
ShutdownHint
```

### Command

```text
command_id       opaque Coolify-generated string, unique per installation
command_type     versioned capability name
payload_version  integer, initially 1
payload          typed protobuf payload
created_at       UTC timestamp
expires_at       UTC timestamp
```

### Command accepted

```text
command_id
accepted_at
```

Acceptance means Sentinel validated the envelope and scheduled local execution. It does not mean success.

### Command result

```text
event_id
command_id
status           succeeded or failed
payload          typed protobuf result
error_code       stable machine-readable code when failed
error_message    safe diagnostic text when failed
observed_at
```

The initial slice does not need a separate `running` or progress message because both commands are short. The database state model can reserve `running` for later operations.

### Event acknowledgement

```text
event_id
```

Flux sends `EventAck` only after Coolify has accepted or deduplicated the event. Sentinel retains unacknowledged results in its bounded in-memory cache and resends them after reconnect. A Sentinel restart can clear this cache because the first commands are read-only and Coolify can safely dispatch them again.

## 11. Initial commands

### `system.ping.v1`

Request:

```text
nonce
```

Result:

```text
nonce
sentinel_time
```

Sentinel must return the same nonce.

### `system.info.v1`

Request has no fields.

Result:

```text
hostname
operating_system
operating_system_version
kernel_version
architecture
cpu_count
memory_bytes
disk_total_bytes
disk_available_bytes
sentinel_version
boot_id
```

The handler uses existing Sentinel host collection functions where suitable. It must not invoke a shell command. Field failures return absent optional fields or a stable command error according to the final protobuf field requirements.

## 12. Sentinel runtime design

The `control` crate receives:

- A parsed control configuration.
- The existing token as a secret value.
- The parsed Coolify base URL.
- A shutdown receiver.
- A host-information provider interface.

It owns a state machine:

```text
Disabled
Assigning
WaitingToRetry
Connecting
Connected
RefreshingCredential
ShuttingDown
```

The control task stays alive during temporary errors. It exits only during Sentinel shutdown or an unrecoverable internal task failure. While the feature is experimental, an unrecoverable control failure logs an error and disables the control task without stopping the existing Sentinel API, collectors, store, push service, or traffic service.

Reconnect uses exponential backoff with full jitter:

```text
base: 1 second
maximum: 60 seconds
reset: after 5 minutes of a healthy connection
```

Sentinel keeps these items in memory:

- The current assignment.
- The current Flux credential.
- The selected protocol version.
- The active connection state.
- Active commands.
- A bounded recent-result cache.

The recent-result cache holds up to 1,000 command results for 30 minutes. Duplicate command IDs return the cached result. A duplicate with a different command type or payload is rejected as `command_id_conflict`.

A Sentinel restart clears the cache. This is safe because the initial commands are read-only.

## 13. Flux runtime design

Flux is a separate Tokio process.

It contains:

- A TLS gRPC listener for Sentinel streams.
- A JWT verifier and key set.
- A connection registry.
- A pending-request registry.
- A local Unix-domain HTTP listener for Coolify.
- An internal event client for Coolify command and connection events.
- Health and diagnostic endpoints on the Unix socket.

The in-memory connection registry maps:

```text
server_id -> connection_id, sender, capabilities, protocol_version, last_heartbeat
```

When a new authenticated stream connects for the same server, Flux installs the new connection and closes the old one with a replacement reason.

Flux applies global and per-connection bounds. Queue saturation returns a fast transport error to Coolify. It never waits without a timeout for room in a queue.

Flux has no database and no durable message queue.

## 14. Coolify-to-Flux local API

Coolify communicates with Flux through a Unix socket, default:

```text
/run/coolify/flux.sock
```

Initial endpoints:

```text
GET  /v1/health
GET  /v1/connections/{server_id}
POST /v1/commands
```

The socket uses file permissions to restrict access to Coolify and Flux. Flux does not expose these endpoints on its public gRPC listener.

Command request:

```json
{
  "server_id": "server-uuid",
  "command_id": "command-id",
  "command_type": "system.ping.v1",
  "payload": {},
  "created_at": "2026-09-11T14:00:00Z",
  "expires_at": "2026-09-11T14:00:30Z"
}
```

A `202 Accepted` response means Flux placed the command in the connected Sentinel's bounded queue. It does not mean Sentinel accepted or completed the command. Flux reports `CommandAccepted` and `CommandResult` through the internal event endpoint. Coolify stores all state transitions in PostgreSQL and treats its database as authoritative.

Initial transport errors include:

```text
host_disconnected
unsupported_command
queue_full
delivery_timeout
command_timeout
invalid_request
flux_unavailable
```

## 15. Durable Coolify command model

The first implementation adds durable command and event records only when the Coolify v5 gate is active.

Minimum command fields:

```text
id
server_id
team_id
command_type
payload
payload_version
status
attempts
available_at
expires_at
acknowledged_at
completed_at
result
error_code
error_message
created_at
updated_at
```

Initial states:

```text
pending
dispatched
acknowledged
succeeded
failed
expired
```

Valid transitions:

```text
pending -> dispatched
pending -> expired
dispatched -> acknowledged
dispatched -> failed
dispatched -> expired
acknowledged -> succeeded
acknowledged -> failed
acknowledged -> expired
```

Coolify writes the command and its outbox record in one database transaction. A queue worker dispatches committed outbox records. Failed delivery reschedules the command with bounded exponential backoff until expiry.

Coolify deduplicates results by `event_id`. It accepts only valid state transitions. A late result remains recorded for audit but does not replace a newer terminal decision without an explicit reconciliation rule.

Every command query and mutation is scoped to the current team and authorized against the server.

## 16. Connection observation

Flux reports these connection events to an authenticated internal Coolify endpoint:

```text
connected
disconnected
replaced
protocol_rejected
authentication_rejected
```

Each event contains:

```text
event_id
server_id
connection_id
sentinel_version
protocol_version
capabilities
observed_at
reason
```

Coolify orders observations by `observed_at` and event identity. It does not mark a newer connection offline because a delayed disconnect event from an older connection arrived later.

Connection observation is diagnostic state. It does not replace active host reconciliation.

Flux sends both connection events and command events to:

```text
POST /api/v1/internal/sentinel/control/events
```

Flux authenticates with a service credential that is separate from Sentinel credentials. Coolify persists or deduplicates the event before it returns success. Flux then sends `EventAck` to Sentinel. If Coolify is unavailable, Flux retries with a short bounded backoff while the connection remains active. If Flux or Sentinel restarts before acknowledgement, Coolify can retry the read-only command safely.

## 17. Compatibility with existing Sentinel behavior

When `CONTROL_PLANE_ENABLED` is absent or false:

- Configuration loading has the same required variables as Sentinel 1.0.1.
- No assignment request occurs.
- No gRPC connection occurs.
- No new file or SQLite table is created.
- The HTTP API behavior is unchanged.
- Metrics collection is unchanged.
- Storage collection is unchanged.
- The push service is unchanged.
- Traffic analytics is unchanged.
- Shutdown behavior is unchanged.

When enabled, failure of assignment or Flux does not change those existing services.

The current HTTP push service remains the production path for server and container metrics during this slice.

## 18. Security controls

The first slice requires:

- TLS for the public Sentinel-to-Flux connection.
- Existing Sentinel bearer-token authentication for assignment.
- Short-lived asymmetric signed Flux credentials.
- Explicit non-wildcard capabilities.
- Server identity binding.
- Protocol range checking.
- Message-size limits.
- Bounded queues and pending requests.
- Deadlines on every Coolify-to-Flux request.
- Safe error messages returned to Sentinel and users.
- Detailed server-side logs without credentials or sensitive payloads.
- Team-scoped Coolify queries and authorization tests.
- Rate limiting on the assignment endpoint.
- Event deduplication and stale-event protection.

The assignment endpoint returns no private signing key. Sentinel receives only its short-lived credential and normal public TLS trust data.

## 19. Observability

Sentinel logs state changes, not every heartbeat. Logs include server-safe identifiers, connection state, protocol version, and retry delay. They never include tokens.

Flux exposes through its protected local diagnostics:

- Process health.
- Number of active connections.
- Authentication rejection count.
- Protocol rejection count.
- Queue saturation count.
- Command timeout count.
- Reconnect and replacement count.

Coolify records command latency timestamps and connection status for the dashboard. Metrics export beyond these diagnostics is deferred.

## 20. Test strategy

### Sentinel compatibility tests

Start Sentinel without `CONTROL_PLANE_ENABLED` and prove:

- Existing configuration loads.
- Health and authenticated API routes work.
- Collection and push startup behavior remains unchanged.
- No assignment request occurs.
- No control state is written.
- Shutdown succeeds.

### Protocol tests

- Protobuf encode and decode round trips.
- Unknown fields remain forward compatible.
- Protocol range overlap selection.
- Capability intersection.
- Missing and invalid first messages.

### Sentinel control tests

Use a fake Coolify assignment server and fake Flux server:

- Successful assignment and connection.
- Disabled assignment.
- `404` from an older Coolify.
- Authentication error backoff.
- Network failure backoff and jitter bounds.
- Credential refresh.
- `system.ping.v1` result.
- `system.info.v1` result.
- Duplicate command result replay.
- Conflicting duplicate rejection.
- Graceful shutdown.

### Flux tests

- Valid and invalid JWTs.
- Algorithm and key-ID rejection.
- Expiry and maximum-lifetime enforcement.
- Server identity binding.
- Protocol rejection.
- Duplicate connection replacement.
- Heartbeat expiry.
- Queue saturation.
- Disconnection during dispatch.
- Command timeout.
- Unix-socket access and response mapping.

### Coolify tests

- Global and per-server gates.
- Existing server token assignment authentication.
- Cross-team token rejection.
- Assignment capability and credential claims.
- Durable command transitions.
- Transactional outbox behavior.
- Duplicate and stale result ingestion.
- Server authorization for command dispatch.
- Disabled v5 isolation.

### End-to-end test

Run real Coolify test endpoints, Flux, and Sentinel in a disposable environment:

1. Start Sentinel with the gate disabled and prove no control connection.
2. Enable the gate and request assignment.
3. Observe the authenticated Flux connection.
4. Dispatch `system.ping.v1`.
5. Dispatch `system.info.v1`.
6. Restart Flux and observe Sentinel reconnect.
7. Restart Sentinel and observe a fresh assignment with no local control state.
8. Disable assignment and observe that existing Sentinel services remain healthy.

## 21. Delivery sequence

### Change 1: dormant Sentinel configuration

- Add `CONTROL_PLANE_ENABLED=false` parsing.
- Add compatibility tests.
- Do not make network requests.

### Change 2: protocol crate

- Add the initial protobuf contract.
- Add generated types and contract tests.

### Change 3: dormant Sentinel control client

- Add assignment, connection, heartbeat, reconnect, and the two handlers.
- Test against fake servers.
- Keep the runtime gate off by default.

### Change 4: Flux binary

- Add TLS gRPC, authentication, registries, Unix-socket API, limits, and tests.

### Change 5: Coolify integration

- Add gated assignment, credential issuance, connection ingestion, durable commands, outbox dispatch, authorization, and tests.

### Change 6: end-to-end verification

- Add the disposable full-path test.
- Verify normal Sentinel behavior with the gate off.
- Verify reconnect and restart behavior with the gate on.

Each change must be independently releasable or remain inert until the required peer component exists.

## 22. Acceptance criteria

The foundation is complete when:

- The normal Sentinel image includes the dormant client and remains compatible when disabled.
- Coolify can opt in one server without enabling other servers.
- Sentinel discovers Flux through the existing Coolify URL and token.
- Flux authenticates the server and negotiates the protocol.
- Coolify records accurate connected and disconnected observations.
- Coolify durably records and dispatches `system.ping.v1` and `system.info.v1`.
- Duplicate delivery is safe.
- Flux and Sentinel restarts do not lose Coolify command truth.
- Assignment and Flux outages do not stop existing Sentinel services.
- Automated tests prove the disabled and enabled paths.

## 23. Deferred decisions

These decisions belong to later milestones and do not block this slice:

- Mutating-command idempotency and any need for local persistence.
- Container runtime command shapes.
- Corrosion record ownership and gossip authentication.
- WireGuard enrollment.
- Multi-Flux routing and regional assignment.
- Build scheduling and artifact storage.
- Log, terminal, and metrics streaming.
- Replacement of the existing HTTP push path.

## 24. Protocol references

The implementation must verify behavior against current upstream documentation before selecting Rust APIs or dependency versions:

- [gRPC authentication](https://grpc.io/docs/guides/auth/)
- [gRPC deadlines](https://grpc.io/docs/guides/deadlines/)
- [gRPC flow control](https://grpc.io/docs/guides/flow-control/)
- [gRPC keepalive](https://grpc.io/docs/guides/keepalive/)
- [Protocol Buffers versioning guidance](https://protobuf.dev/programming-guides/dos-donts/)
