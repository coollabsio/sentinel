//! Workload files (decision 0023): files and empty directories that Coolify
//! sends with `workload.deploy` and that Sentinel bind-mounts into the
//! container, like the `content:` mounts of Compose in v4. Each container name
//! has its own host directory, rewritten on every deploy and deleted with the
//! container. Contents are never logged.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sentinel_protocol::control::v1::{WorkloadDeployRequest, WorkloadFile};

const FILES_DIR: &str = "var/lib/coolify/workload-files";
const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_FILE_MODE: u32 = 0o644;
const DEFAULT_DIRECTORY_MODE: u32 = 0o755;
const FORBIDDEN_PREFIXES: [&str; 4] = ["/proc", "/sys", "/dev", "/run/secrets"];

/// The host directory of one container name.
pub(crate) fn container_dir(root: &Path, container: &str) -> PathBuf {
    root.join(FILES_DIR).join(container)
}

/// The host path of one entry, under [`container_dir`].
fn host_path(root: &Path, container: &str, path: &str) -> PathBuf {
    container_dir(root, container).join(path.trim_start_matches('/'))
}

fn valid_path(path: &str) -> bool {
    path.len() <= 4_096
        && path.starts_with('/')
        && path != "/"
        && !path.ends_with('/')
        && !path.contains("//")
        && !path
            .chars()
            .any(|character| character == ',' || character.is_control())
        && path
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
        && !FORBIDDEN_PREFIXES.iter().any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

fn mode(file: &WorkloadFile) -> Result<u32, String> {
    if file.mode.is_empty() {
        return Ok(if file.directory {
            DEFAULT_DIRECTORY_MODE
        } else {
            DEFAULT_FILE_MODE
        });
    }
    if !(3..=4).contains(&file.mode.len()) || !file.mode.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err(format!("The mode of the file {} is invalid.", file.path));
    }
    let mode = u32::from_str_radix(&file.mode, 8)
        .map_err(|_| format!("The mode of the file {} is invalid.", file.path))?;
    if mode > 0o777 {
        return Err(format!("The mode of the file {} is invalid.", file.path));
    }
    Ok(mode)
}

/// Validates the files of the request and returns their `--mount` arguments.
pub(crate) fn mount_args(
    root: &Path,
    request: &WorkloadDeployRequest,
) -> Result<Vec<String>, String> {
    if request.files.is_empty() {
        return Ok(Vec::new());
    }
    if request.files.len() > MAX_FILES {
        return Err("The workload has too many files.".into());
    }
    let volume_paths: HashSet<&str> = request
        .mounts
        .iter()
        .map(|mount| mount.container_path.as_str())
        .collect();
    let mut paths = HashSet::with_capacity(request.files.len());
    let mut total = 0usize;
    for file in &request.files {
        if !valid_path(&file.path) {
            return Err("A file path is invalid.".into());
        }
        if !paths.insert(file.path.as_str()) || volume_paths.contains(file.path.as_str()) {
            return Err(format!("The path {} is used twice.", file.path));
        }
        if file.directory && !file.content.is_empty() {
            return Err(format!("The directory {} cannot have content.", file.path));
        }
        if file.content.len() > MAX_FILE_BYTES {
            return Err(format!("The file {} is larger than 1 MiB.", file.path));
        }
        total += file.content.len();
        mode(file)?;
    }
    if total > MAX_TOTAL_BYTES {
        return Err("The files of the workload are larger than 4 MiB together.".into());
    }
    // A file cannot hold another entry below it.
    for file in request.files.iter().filter(|file| !file.directory) {
        let prefix = format!("{}/", file.path);
        if request
            .files
            .iter()
            .any(|other| other.path.starts_with(&prefix))
        {
            return Err(format!(
                "The file {} cannot contain other files.",
                file.path
            ));
        }
    }
    let mut args = Vec::with_capacity(request.files.len() * 2);
    for file in &request.files {
        args.push("--mount".into());
        args.push(format!(
            "type=bind,source={},target={}",
            host_path(root, &request.name, &file.path).display(),
            file.path
        ));
    }
    Ok(args)
}

/// Replaces the host directory of the container with the files of the
/// request. Without files, the directory is deleted. Call [`mount_args`]
/// first: it validates the request.
pub(crate) fn write(root: &Path, request: &WorkloadDeployRequest) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    remove(root, &request.name)?;
    if request.files.is_empty() {
        return Ok(());
    }
    let error = |path: &str| format!("The file {path} could not be written.");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root.join(FILES_DIR))
        .map_err(|_| "The workload file directory could not be created.".to_string())?;
    let base = container_dir(root, &request.name);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&base)
        .map_err(|_| "The workload file directory could not be created.".to_string())?;
    // Directories first, so a file below a directory entry keeps its mode.
    let mut files: Vec<&WorkloadFile> = request.files.iter().collect();
    files.sort_by_key(|file| (!file.directory, file.path.len()));
    for file in files {
        let path = host_path(root, &request.name, &file.path);
        // Parents inside the container directory are visible in a mounted
        // directory, so the container user must be able to pass them.
        if let Some(parent) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(parent)
                .map_err(|_| error(&file.path))?;
        }
        let mode = mode(file)?;
        if file.directory {
            match std::fs::DirBuilder::new().mode(mode).create(&path) {
                Ok(()) => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {}
                Err(_) => return Err(error(&file.path)),
            }
        } else {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&path)
                .and_then(|mut handle| handle.write_all(&file.content))
                .map_err(|_| error(&file.path))?;
        }
        // The process umask must not change the requested mode.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .map_err(|_| error(&file.path))?;
    }
    Ok(())
}

/// Deletes the host directory of the container. Succeeds when there is none.
pub(crate) fn remove(root: &Path, container: &str) -> Result<(), String> {
    match std::fs::remove_dir_all(container_dir(root, container)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("The workload files could not be deleted.".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use sentinel_protocol::control::v1::{
        WorkloadDeployRequest, WorkloadFile, WorkloadVolumeMount,
    };

    use super::*;

    fn file(path: &str, content: &[u8]) -> WorkloadFile {
        WorkloadFile {
            path: path.into(),
            content: content.to_vec(),
            ..Default::default()
        }
    }

    fn directory(path: &str) -> WorkloadFile {
        WorkloadFile {
            path: path.into(),
            directory: true,
            ..Default::default()
        }
    }

    fn request(files: Vec<WorkloadFile>) -> WorkloadDeployRequest {
        WorkloadDeployRequest {
            name: "coolify-p1test-main".into(),
            files,
            ..Default::default()
        }
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn accepts_files_and_directories_and_mounts_each_one() {
        let root = Path::new("/");
        let args = mount_args(
            root,
            &request(vec![
                file("/etc/app/config.yml", b"a: 1"),
                directory("/data"),
            ]),
        )
        .unwrap();
        assert_eq!(
            args,
            [
                "--mount",
                "type=bind,source=/var/lib/coolify/workload-files/coolify-p1test-main/etc/app/config.yml,target=/etc/app/config.yml",
                "--mount",
                "type=bind,source=/var/lib/coolify/workload-files/coolify-p1test-main/data,target=/data",
            ]
        );
        assert!(mount_args(root, &request(Vec::new())).unwrap().is_empty());
    }

    #[test]
    fn rejects_invalid_paths() {
        for path in [
            "",
            "relative",
            "/",
            "/etc/",
            "/etc//app",
            "/etc/../shadow",
            "/etc/./app",
            "/a,b",
            "/a\0b",
            "/a\nb",
            "/proc",
            "/proc/self",
            "/sys/kernel",
            "/dev/null",
            "/run/secrets",
            "/run/secrets/key",
        ] {
            assert!(
                mount_args(Path::new("/"), &request(vec![file(path, b"x")])).is_err(),
                "{path:?} must be rejected"
            );
        }
        for path in [
            "/a:b",
            "/process",
            "/devices/x",
            "/run/secretsx",
            "/run/app.sock",
        ] {
            assert!(
                mount_args(Path::new("/"), &request(vec![file(path, b"x")])).is_ok(),
                "{path:?} must be accepted"
            );
        }
    }

    #[test]
    fn rejects_duplicates_limits_and_invalid_modes() {
        let root = Path::new("/");
        assert!(mount_args(root, &request(vec![file("/a", b""), directory("/a")])).is_err());
        let mut with_volume = request(vec![file("/data", b"")]);
        with_volume.mounts.push(WorkloadVolumeMount {
            volume_name: "coolify-vol-x".into(),
            container_path: "/data".into(),
            read_only: false,
        });
        assert!(mount_args(root, &with_volume).is_err());
        assert!(mount_args(root, &request(vec![file("/a", b""), file("/a/b", b"")])).is_err());
        assert!(mount_args(root, &request(vec![directory("/a"), file("/a/b", b"")])).is_ok());

        let mut with_content = directory("/a");
        with_content.content = b"x".to_vec();
        assert!(mount_args(root, &request(vec![with_content])).is_err());

        let many = (0..=MAX_FILES)
            .map(|i| file(&format!("/f{i}"), b""))
            .collect();
        assert!(mount_args(root, &request(many)).is_err());
        let limit = (0..MAX_FILES)
            .map(|i| file(&format!("/f{i}"), b""))
            .collect();
        assert!(mount_args(root, &request(limit)).is_ok());

        let mib = vec![0u8; MAX_FILE_BYTES];
        assert!(mount_args(root, &request(vec![file("/big", &mib)])).is_ok());
        let over = vec![0u8; MAX_FILE_BYTES + 1];
        assert!(mount_args(root, &request(vec![file("/big", &over)])).is_err());
        let four = (0..4).map(|i| file(&format!("/f{i}"), &mib)).collect();
        assert!(mount_args(root, &request(four)).is_ok());
        let five = (0..5).map(|i| file(&format!("/f{i}"), &mib)).collect();
        assert!(mount_args(root, &request(five)).is_err());

        for (mode, accepted) in [
            ("0644", true),
            ("600", true),
            ("0777", true),
            ("4755", false),
            ("0888", false),
            ("644 ", false),
            ("12", false),
            ("00644", false),
        ] {
            let mut entry = file("/a", b"");
            entry.mode = mode.into();
            assert_eq!(
                mount_args(root, &request(vec![entry])).is_ok(),
                accepted,
                "{mode}"
            );
        }
    }

    #[test]
    fn writes_rewrites_and_removes_the_files_of_a_container() {
        let root = tempfile::tempdir().unwrap();
        let mut script = file("/usr/local/bin/init.sh", b"#!/bin/sh\necho hi\n");
        script.mode = "0755".into();
        let first = request(vec![
            file("/etc/app/config.yml", b"a: 1"),
            script,
            directory("/data"),
            file("/data/seed.txt", b"seed"),
        ]);
        mount_args(root.path(), &first).unwrap();
        write(root.path(), &first).unwrap();

        let base = container_dir(root.path(), "coolify-p1test-main");
        assert_eq!(mode_of(&root.path().join(FILES_DIR)), 0o700);
        assert_eq!(mode_of(&base), 0o700);
        assert_eq!(
            std::fs::read(base.join("etc/app/config.yml")).unwrap(),
            b"a: 1"
        );
        assert_eq!(mode_of(&base.join("etc/app/config.yml")), 0o644);
        assert_eq!(mode_of(&base.join("etc/app")), 0o755);
        assert_eq!(mode_of(&base.join("usr/local/bin/init.sh")), 0o755);
        assert!(base.join("data").is_dir());
        assert_eq!(mode_of(&base.join("data")), 0o755);
        assert_eq!(std::fs::read(base.join("data/seed.txt")).unwrap(), b"seed");

        // A second deploy of the same name replaces every file.
        std::fs::write(base.join("data/written-by-app"), b"x").unwrap();
        let second = request(vec![file("/etc/app/config.yml", b"a: 2")]);
        write(root.path(), &second).unwrap();
        assert_eq!(
            std::fs::read(base.join("etc/app/config.yml")).unwrap(),
            b"a: 2"
        );
        assert!(!base.join("data").exists());
        assert!(!base.join("usr").exists());

        // The other slot of the workload keeps its own files.
        let mut other = request(vec![file("/etc/app/config.yml", b"a: 3")]);
        other.name = "coolify-p1test-next".into();
        write(root.path(), &other).unwrap();
        assert_eq!(
            std::fs::read(base.join("etc/app/config.yml")).unwrap(),
            b"a: 2"
        );

        // A deploy without files deletes the directory, and so does remove.
        write(root.path(), &request(Vec::new())).unwrap();
        assert!(!base.exists());
        remove(root.path(), "coolify-p1test-next").unwrap();
        assert!(!container_dir(root.path(), "coolify-p1test-next").exists());
        remove(root.path(), "coolify-p1test-next").unwrap();
    }
}
