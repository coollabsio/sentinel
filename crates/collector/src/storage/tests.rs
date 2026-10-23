use super::*;

#[test]
fn resolves_host_path_with_and_without_prefix() {
    assert_eq!(
        resolve_host_path("", "/var/lib/docker/volumes/x/_data"),
        PathBuf::from("/var/lib/docker/volumes/x/_data")
    );
    assert_eq!(
        resolve_host_path("/host", "/var/lib/docker/volumes/x/_data"),
        PathBuf::from("/host/var/lib/docker/volumes/x/_data")
    );
}

#[test]
fn pseudo_filesystems_are_skipped() {
    assert!(is_pseudo_fs("tmpfs"));
    assert!(is_pseudo_fs("overlay"));
    assert!(is_pseudo_fs("cgroup2"));
    assert!(is_pseudo_fs(""));
    assert!(!is_pseudo_fs("ext4"));
    assert!(!is_pseudo_fs("xfs"));
    assert!(!is_pseudo_fs("btrfs"));
}

/// Host mount table as Sentinel reads it through `--pid host` (`/proc/1/mountinfo`).
const HOST_MOUNTINFO: &str = "\
29 1 253:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw
30 29 253:2 / /data rw,relatime shared:2 - xfs /dev/vdb1 rw
31 29 0:25 / /run rw,nosuid shared:3 - tmpfs tmpfs rw
90 29 0:42 / /var/lib/docker/rootfs/overlayfs/abc rw shared:40 - overlay overlay rw
91 29 253:1 /var/lib/docker /mnt/docker\\040copy rw shared:1 - ext4 /dev/vda1 rw
";

/// The Sentinel container's own mount table (`/proc/self/mountinfo`).
const CONTAINER_MOUNTINFO: &str = "\
600 500 0:42 / / rw,relatime - overlay overlay rw,lowerdir=/x
601 600 253:1 /data/coolify/sentinel /app/db rw,relatime - ext4 /dev/vda1 rw
602 600 253:1 /var/lib/docker/containers/x/hosts /etc/hosts rw,relatime - ext4 /dev/vda1 rw
603 600 253:2 /coolify/proxy /data/coolify/proxy ro,relatime - xfs /dev/vdb1 rw
604 600 0:25 /docker.sock /run/docker.sock rw - tmpfs tmpfs rw
";

#[test]
fn container_mounts_are_named_by_their_host_filesystem() {
    let labels = host_mount_labels(CONTAINER_MOUNTINFO, HOST_MOUNTINFO).unwrap();

    // /app/db is on the host root device, so it measures the host `/` exactly.
    assert_eq!(labels.get("/app/db").map(String::as_str), Some("/"));
    assert_eq!(labels.get("/etc/hosts").map(String::as_str), Some("/"));
    assert_eq!(
        labels.get("/data/coolify/proxy").map(String::as_str),
        Some("/data")
    );
    // The container's own overlay root and tmpfs binds are no host disk.
    assert_eq!(labels.get("/"), None);
    assert_eq!(labels.get("/run/docker.sock"), None);
}

#[test]
fn no_labels_when_sentinel_shares_the_host_mount_table() {
    // Running on the host, or in a container without `--pid host`.
    assert!(host_mount_labels(HOST_MOUNTINFO, HOST_MOUNTINFO).is_none());
}

#[test]
fn mountinfo_paths_are_unescaped() {
    let labels = host_mount_labels(
        "1 0 253:1 / /mnt/a\\040b rw - ext4 /dev/vda1 rw\n",
        HOST_MOUNTINFO,
    )
    .unwrap();
    assert_eq!(labels.get("/mnt/a b").map(String::as_str), Some("/"));
}

#[test]
fn dir_size_missing_path_is_zero() {
    assert_eq!(dir_size(Path::new("/nonexistent/sentinel/storage/path")), 0);
}

#[test]
fn dir_size_sums_file_blocks() {
    let dir = std::env::temp_dir().join(format!("sentinel-storage-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("a.bin"), vec![0u8; 8192]).unwrap();
    std::fs::write(dir.join("sub/b.bin"), vec![0u8; 4096]).unwrap();
    // At least the two files' worth of blocks (12 KiB) must be counted.
    assert!(dir_size(&dir) >= 12 * 1024);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn dir_size_bounded_stops_at_entry_cap() {
    let dir = std::env::temp_dir().join(format!("sentinel-storage-cap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A flat directory of ten one-block files. Each contributes >0 blocks
    // regardless of read_dir ordering, so a walk that stops after 3 entries
    // is strictly smaller than the full walk — order-independent proof the
    // cap short-circuits.
    for i in 0..10 {
        std::fs::write(dir.join(format!("f{i}.bin")), vec![0u8; 4096]).unwrap();
    }
    let full = dir_size_bounded(&dir, u64::MAX);
    let capped = dir_size_bounded(&dir, 3);
    assert!(capped < full, "capped={capped} full={full}");
    std::fs::remove_dir_all(&dir).unwrap();
}
