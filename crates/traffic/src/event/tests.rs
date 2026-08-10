use super::*;

#[test]
fn classifies_status() {
    assert_eq!(status_class(204), StatusClass::S2xx);
    assert_eq!(status_class(301), StatusClass::S3xx);
    assert_eq!(status_class(404), StatusClass::S4xx);
    assert_eq!(status_class(503), StatusClass::S5xx);
    assert_eq!(status_class(101), StatusClass::Other);
}
