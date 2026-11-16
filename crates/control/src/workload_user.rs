//! The user of a workload process (`workload.user.v1`), the Compose `user:`.

use sentinel_protocol::control::v1::WorkloadDeployRequest;

const MAX_PART: usize = 32;

/// Validates `user` of the request and returns its `--user` arguments. An
/// empty value runs the user of the image.
pub(crate) fn user_args(request: &WorkloadDeployRequest) -> Result<Vec<String>, String> {
    let user = &request.user;
    if user.is_empty() {
        return Ok(Vec::new());
    }
    let mut parts = user.splitn(2, ':');
    let valid = parts.next().is_some_and(valid_part) && parts.next().is_none_or(valid_part);
    if !valid {
        return Err("The workload user is invalid.".into());
    }
    Ok(vec!["--user".into(), user.clone()])
}

/// `[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}`.
fn valid_part(part: &str) -> bool {
    let mut characters = part.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric() || first == '_')
        && part.len() <= MAX_PART
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(user: &str) -> WorkloadDeployRequest {
        WorkloadDeployRequest {
            name: "coolify-p1test-main".into(),
            user: user.into(),
            ..Default::default()
        }
    }

    #[test]
    fn runs_the_image_user_without_a_value() {
        assert!(user_args(&request("")).unwrap().is_empty());
    }

    #[test]
    fn passes_a_valid_user_to_podman() {
        for user in [
            "root",
            "0",
            "1000:1000",
            "www-data",
            "_apt",
            "node:node",
            "user.name:group-1",
            &"a".repeat(32),
        ] {
            assert_eq!(user_args(&request(user)).unwrap(), ["--user", user]);
        }
    }

    #[test]
    fn rejects_an_invalid_user() {
        for user in [
            ":",
            ":1000",
            "1000:",
            "-1",
            ".hidden",
            "1000:1000:1000",
            "user name",
            "user;id",
            "$(id)",
            "user\n",
            "ro\0ot",
            "über",
            &"a".repeat(33),
        ] {
            assert_eq!(
                user_args(&request(user)).unwrap_err(),
                "The workload user is invalid.",
                "{user:?}"
            );
        }
    }
}
