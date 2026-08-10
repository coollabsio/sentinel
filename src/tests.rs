use super::unexpected_service_exit;

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
