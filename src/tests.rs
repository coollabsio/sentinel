use std::path::PathBuf;

use clap::Parser;

use super::{Cli, CliCommand, assignment_client, unexpected_service_exit};

fn control_tls_config() -> config::ControlTlsConfig {
    config::ControlTlsConfig {
        ca_path: PathBuf::from("/etc/coolify/sentinel-flux-ca.pem"),
        trust_bundle_version: 1,
        allow_plaintext: false,
    }
}

fn command_journal() -> store::CommandJournal {
    store::CommandJournal::open_in_memory(7, 100_000).unwrap()
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
    let client = assignment_client(false, "", "", "", None, command_journal());

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
        command_journal(),
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
        command_journal(),
    );

    assert!(client.is_none());
}

#[test]
fn parses_the_private_discovery_dns_process_mode() {
    let cli = Cli::try_parse_from([
        "sentinel",
        "discovery-dns",
        "--bind",
        "10.240.0.2:53",
        "--zone",
        "coolify.internal",
        "--corrosion-config",
        "/etc/corrosion/config.toml",
    ])
    .unwrap();

    assert!(matches!(
        cli.command,
        Some(CliCommand::DiscoveryDns { bind, .. }) if bind.to_string() == "10.240.0.2:53"
    ));
}
