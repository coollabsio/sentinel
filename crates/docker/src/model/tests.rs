use super::*;

fn summary() -> ContainerSummary {
    ContainerSummary {
        id: "abcdef0123456789".into(),
        ..Default::default()
    }
}

#[test]
fn prefers_coolify_name_label() {
    let mut c = summary();
    c.names = vec!["/docker-name".into()];
    c.labels.insert("coolify.name".into(), "my-app".into());
    assert_eq!(c.display_name(), "my-app");
}

#[test]
fn falls_back_to_docker_name_without_leading_slash() {
    let mut c = summary();
    c.names = vec!["/docker-name".into()];
    assert_eq!(c.display_name(), "docker-name");
}

#[test]
fn falls_back_to_truncated_id() {
    assert_eq!(summary().display_name(), "abcdef012345");
}

#[test]
fn ignores_empty_label_and_empty_name() {
    let mut c = summary();
    c.labels.insert("coolify.name".into(), String::new());
    c.names = vec![String::new()];
    assert_eq!(c.display_name(), "abcdef012345");
}
