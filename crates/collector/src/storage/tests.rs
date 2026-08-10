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
