use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use sentinel_protocol::{CAPABILITY_SYSTEM_PING, PROTOCOL_MAX, PROTOCOL_MIN};

use super::*;

fn token(
    signing_key: &SigningKey,
    kid: &str,
    subject: &str,
    expires_delta: i64,
    not_before_delta: i64,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "alg": "EdDSA", "typ": "JWT", "kid": kid
        }))
        .unwrap(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": "coolify-dev", "aud": "flux", "purpose": "v5-control-channel",
            "sub": subject, "jti": "token-id", "iat": now, "nbf": now + not_before_delta,
            "exp": now + expires_delta, "caps": [CAPABILITY_SYSTEM_PING],
            "pmin": PROTOCOL_MIN, "pmax": PROTOCOL_MAX
        }))
        .unwrap(),
    );
    let input = format!("{header}.{claims}");
    let signature = signing_key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[test]
fn verifies_bound_short_lived_eddsa_credentials() {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let verifier = CredentialVerifier::new(
        "dev-key",
        signing_key.verifying_key().to_bytes(),
        "coolify-dev",
        Duration::from_secs(15 * 60),
    );
    let credential = token(&signing_key, "dev-key", "server-1", 15 * 60, -1);

    let claims = verifier.verify(&credential).unwrap();

    assert_eq!(claims.subject, "server-1");
    assert_eq!(claims.capabilities, vec![CAPABILITY_SYSTEM_PING]);
}

#[test]
fn rejects_wrong_key_id_subject_and_excessive_lifetime() {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let verifier = CredentialVerifier::new(
        "dev-key",
        signing_key.verifying_key().to_bytes(),
        "coolify-dev",
        Duration::from_secs(15 * 60),
    );

    assert_eq!(
        verifier
            .verify(&token(&signing_key, "other", "server-1", 60, -1))
            .unwrap_err()
            .kind(),
        CredentialErrorKind::KeyId
    );
    assert_eq!(
        verifier
            .verify(&token(&signing_key, "dev-key", "server-1", 16 * 60, -1))
            .unwrap_err()
            .kind(),
        CredentialErrorKind::Lifetime
    );
    assert_eq!(
        verifier
            .verify(&token(&signing_key, "dev-key", "server-1", 60, 30))
            .unwrap_err()
            .kind(),
        CredentialErrorKind::Claims
    );
}

#[test]
fn selects_protocol_and_capabilities_for_valid_hello() {
    let claims = CredentialClaims {
        subject: "server-1".into(),
        capabilities: vec![CAPABILITY_SYSTEM_PING.into()],
        protocol_min: 1,
        protocol_max: 1,
        expires_at: i64::MAX,
    };
    let hello = sentinel_protocol::control::v1::Hello {
        server_id: "server-1".into(),
        sentinel_version: "main".into(),
        protocol_min: 1,
        protocol_max: 1,
        capabilities: vec![CAPABILITY_SYSTEM_PING.into()],
        boot_id: "boot-1".into(),
    };

    let negotiated = negotiate(&claims, &hello).unwrap();

    assert_eq!(negotiated.protocol_version, 1);
    assert_eq!(negotiated.capabilities, vec![CAPABILITY_SYSTEM_PING]);
}

#[tokio::test]
async fn registry_replaces_the_previous_connection() {
    let registry = ConnectionRegistry::default();
    let (first_tx, mut first_rx) = tokio::sync::mpsc::channel(1);
    let (second_tx, _) = tokio::sync::mpsc::channel(1);
    registry
        .insert("server-1", "connection-1", first_tx, 1, vec![])
        .await;
    registry
        .insert("server-1", "connection-2", second_tx, 1, vec![])
        .await;

    let message = first_rx.recv().await.unwrap();
    assert!(matches!(
        message.message,
        Some(sentinel_protocol::control::v1::control_message::Message::ShutdownHint(_))
    ));
    assert_eq!(
        registry.get("server-1").await.unwrap().connection_id,
        "connection-2"
    );
}

#[tokio::test]
async fn registry_routes_a_ping_result_to_the_waiting_request() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_SYSTEM_PING.into()],
        )
        .await;
    let command = sentinel_protocol::control::v1::Command {
        command_id: "command-1".into(),
        command_type: CAPABILITY_SYSTEM_PING.into(),
        payload_version: 1,
        created_at_unix_ms: now_millis(),
        payload: Some(
            sentinel_protocol::control::v1::command::Payload::SystemPing(
                sentinel_protocol::control::v1::SystemPingRequest {
                    nonce: "nonce-1".into(),
                },
            ),
        ),
        expires_at_unix_ms: now_millis() + 10_000,
    };
    let pending_registry = registry.clone();
    let waiter = tokio::spawn(async move {
        pending_registry
            .dispatch("server-1", command, Duration::from_secs(1))
            .await
    });
    receiver.recv().await.unwrap();
    registry
        .complete(
            "server-1",
            sentinel_protocol::control::v1::CommandResult {
                event_id: "event-1".into(),
                command_id: "command-1".into(),
                status: sentinel_protocol::control::v1::CommandStatus::Succeeded.into(),
                observed_at_unix_ms: now_millis(),
                payload: None,
            },
        )
        .await;

    assert_eq!(waiter.await.unwrap().unwrap().command_id, "command-1");
}

#[tokio::test]
async fn registry_reports_an_offline_server_without_waiting() {
    let result = ConnectionRegistry::default()
        .dispatch(
            "offline",
            sentinel_protocol::control::v1::Command::default(),
            Duration::from_secs(1),
        )
        .await;

    assert_eq!(result.unwrap_err(), CommandDispatchError::Offline);
}

#[tokio::test]
async fn registry_times_out_when_sentinel_does_not_return_a_result() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_SYSTEM_PING.into()],
        )
        .await;
    let command = sentinel_protocol::control::v1::Command {
        command_id: "command-timeout".into(),
        command_type: CAPABILITY_SYSTEM_PING.into(),
        ..Default::default()
    };

    let result = registry
        .dispatch("server-1", command, Duration::from_millis(1))
        .await;
    assert!(receiver.recv().await.is_some());
    assert_eq!(result.unwrap_err(), CommandDispatchError::Timeout);
}
