use std::path::PathBuf;

use super::{assignment_client, unexpected_service_exit};

fn control_tls_config() -> config::ControlTlsConfig {
    config::ControlTlsConfig {
        ca_path: PathBuf::from("/etc/coolify/sentinel-flux-ca.pem"),
        trust_bundle_version: 1,
        allow_plaintext: false,
    }
}

#[test]
fn a_clean_service_exit_is_still_unexpected_before_shutdown() {
    let result = unexpected_service_exit(Some(Ok(Ok(()))));
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("stopped unexpectedly")
    );
}

#[test]
fn a_service_error_is_propagated() {
    let result = unexpected_service_exit(Some(Ok(Err("api failed".into()))));
    assert_eq!(result.unwrap_err().to_string(), "api failed");
}

#[test]
fn control_assignment_stays_dormant_when_disabled() {
    let client = assignment_client(false, "", "", "", None);

    assert!(client.is_none());
}

#[test]
fn control_assignment_client_is_created_when_enabled() {
    let client = assignment_client(
        true,
        "https://coolify.example.com",
        "token",
        "main",
        Some(&control_tls_config()),
    );

    assert!(client.is_some());
}

#[test]
fn invalid_control_assignment_configuration_does_not_fail_startup() {
    let client = assignment_client(
        true,
        "not-a-url",
        "token",
        "main",
        Some(&control_tls_config()),
    );

    assert!(client.is_none());
}
