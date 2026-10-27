use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Owner labels in precedence order: the first one present names the owner.
const OWNER_LABELS: [&str; 3] = [
    "coolify.applicationUuid",
    "coolify.serviceUuid",
    "coolify.databaseUuid",
];

/// A Coolify-managed container whose logs are archived. Built only through
/// [`Target::from_container`], so every field is a safe path segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub id: String,
    pub owner: String,
    pub name: String,
}

impl Target {
    /// `None` for containers that are not managed by Coolify, have no owner
    /// label, or whose owner, name, or id is not a safe path segment.
    pub fn from_container(id: &str, name: &str, labels: &HashMap<String, String>) -> Option<Self> {
        if labels.get("coolify.managed").map(String::as_str) != Some("true") {
            return None;
        }
        let owner = OWNER_LABELS.iter().find_map(|key| labels.get(*key))?;
        let name = name.strip_prefix('/').unwrap_or(name);
        if !is_safe_segment(owner) || !is_safe_segment(name) || !is_safe_segment(id) {
            return None;
        }
        Some(Self {
            id: id.to_string(),
            owner: owner.clone(),
            name: name.to_string(),
        })
    }

    /// `<root>/<owner>/<name>.<first 12 chars of id>.log`
    pub fn path(&self, root: &Path) -> PathBuf {
        let short_id: String = self.id.chars().take(12).collect();
        root.join(&self.owner)
            .join(format!("{}.{short_id}.log", self.name))
    }
}

/// `[A-Za-z0-9][A-Za-z0-9_.-]*` without `..`.
pub fn is_safe_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && !segment.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    const ID: &str = "0123456789abcdef0123";

    #[test]
    fn builds_the_archive_path() {
        let target = Target::from_container(
            ID,
            "/web-abc",
            &labels(&[
                ("coolify.managed", "true"),
                ("coolify.applicationUuid", "app1"),
            ]),
        )
        .unwrap();
        assert_eq!(
            target.path(Path::new("/app/db/container-logs")),
            PathBuf::from("/app/db/container-logs/app1/web-abc.0123456789ab.log")
        );
    }

    #[test]
    fn owner_labels_follow_precedence() {
        let all = labels(&[
            ("coolify.managed", "true"),
            ("coolify.databaseUuid", "db1"),
            ("coolify.serviceUuid", "svc1"),
            ("coolify.applicationUuid", "app1"),
        ]);
        assert_eq!(Target::from_container(ID, "c", &all).unwrap().owner, "app1");

        let service_and_db = labels(&[
            ("coolify.managed", "true"),
            ("coolify.databaseUuid", "db1"),
            ("coolify.serviceUuid", "svc1"),
        ]);
        assert_eq!(
            Target::from_container(ID, "c", &service_and_db)
                .unwrap()
                .owner,
            "svc1"
        );

        let db = labels(&[("coolify.managed", "true"), ("coolify.databaseUuid", "db1")]);
        assert_eq!(Target::from_container(ID, "c", &db).unwrap().owner, "db1");
    }

    #[test]
    fn skips_unmanaged_and_ownerless_containers() {
        let unmanaged = labels(&[("coolify.applicationUuid", "app1")]);
        assert_eq!(Target::from_container(ID, "c", &unmanaged), None);
        let not_true = labels(&[
            ("coolify.managed", "false"),
            ("coolify.applicationUuid", "app1"),
        ]);
        assert_eq!(Target::from_container(ID, "c", &not_true), None);
        let ownerless = labels(&[("coolify.managed", "true")]);
        assert_eq!(Target::from_container(ID, "c", &ownerless), None);
    }

    #[test]
    fn skips_unsafe_owner_or_name() {
        for (owner, name) in [
            ("..", "c"),
            ("a/b", "c"),
            ("", "c"),
            ("app1", "../etc"),
            ("app1", "a/b"),
        ] {
            let l = labels(&[("coolify.managed", "true"), ("coolify.serviceUuid", owner)]);
            assert_eq!(Target::from_container(ID, name, &l), None, "{owner} {name}");
        }
    }

    #[test]
    fn validates_segments() {
        for ok in ["a", "app-1", "x_y.z", "A9.log"] {
            assert!(is_safe_segment(ok), "{ok}");
        }
        for bad in [
            "", ".", "..", "a..b", "-a", ".hidden", "_a", "a/b", "/a", "a b", "a\\b",
        ] {
            assert!(!is_safe_segment(bad), "{bad}");
        }
    }
}
