use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct ArchivedFile {
    pub path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_age: Duration,
    pub max_total_bytes: u64,
}

/// The files a sweep deletes, in order. First every file older than
/// `max_age`, then the oldest files until the rest fit in `max_total_bytes`.
/// Followed files are spared both passes, unless the cap still overflows
/// after every other file is gone.
pub fn select_for_deletion(
    files: &[ArchivedFile],
    followed: &HashSet<PathBuf>,
    now: SystemTime,
    limits: Limits,
) -> Vec<PathBuf> {
    let mut order: Vec<&ArchivedFile> = files.iter().collect();
    order.sort_by_key(|f| (followed.contains(&f.path), f.modified));

    let mut total: u64 = files.iter().map(|f| f.size).sum();
    let mut deleted = Vec::new();
    let mut kept = Vec::new();
    for file in order {
        let expired = now
            .duration_since(file.modified)
            .is_ok_and(|age| age > limits.max_age);
        if expired && !followed.contains(&file.path) {
            total -= file.size;
            deleted.push(file.path.clone());
        } else {
            kept.push(file);
        }
    }
    for file in kept {
        if total <= limits.max_total_bytes {
            break;
        }
        total -= file.size;
        deleted.push(file.path.clone());
    }
    deleted
}

/// Applies retention under `root` (`<root>/<owner>/<file>.log[.1]`), then
/// removes owner directories that are left empty and hold no followed file.
/// Returns the number of deleted files.
pub fn sweep(root: &Path, followed: &HashSet<PathBuf>, limits: Limits) -> io::Result<usize> {
    let mut files = Vec::new();
    let mut owner_dirs = Vec::new();
    for owner in std::fs::read_dir(root)? {
        let owner = owner?;
        if !owner.file_type()?.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(owner.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !(name.ends_with(".log") || name.ends_with(".log.1")) {
                continue;
            }
            let meta = entry.metadata()?;
            if meta.is_file() {
                files.push(ArchivedFile {
                    path: entry.path(),
                    size: meta.len(),
                    modified: meta.modified()?,
                });
            }
        }
        owner_dirs.push(owner.path());
    }

    let doomed = select_for_deletion(&files, followed, SystemTime::now(), limits);
    for path in &doomed {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }

    let followed_dirs: HashSet<&Path> = followed.iter().filter_map(|p| p.parent()).collect();
    for dir in owner_dirs {
        if !followed_dirs.contains(dir.as_path()) {
            // Fails, as intended, while the directory still holds files.
            let _ = std::fs::remove_dir(&dir);
        }
    }
    Ok(doomed.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    fn file(name: &str, size: u64, age_days: u64, now: SystemTime) -> ArchivedFile {
        ArchivedFile {
            path: PathBuf::from(name),
            size,
            modified: now - DAY * age_days as u32,
        }
    }

    fn names(paths: Vec<PathBuf>) -> Vec<String> {
        paths
            .into_iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }

    fn limits(max_total_bytes: u64) -> Limits {
        Limits {
            max_age: 7 * DAY,
            max_total_bytes,
        }
    }

    #[test]
    fn deletes_expired_files() {
        let now = SystemTime::now();
        let files = [file("old", 1, 8, now), file("new", 1, 1, now)];
        assert_eq!(
            names(select_for_deletion(
                &files,
                &HashSet::new(),
                now,
                limits(100)
            )),
            ["old"]
        );
    }

    #[test]
    fn caps_the_total_oldest_first() {
        let now = SystemTime::now();
        let files = [
            file("c", 10, 1, now),
            file("a", 10, 3, now),
            file("b", 10, 2, now),
        ];
        assert_eq!(
            names(select_for_deletion(
                &files,
                &HashSet::new(),
                now,
                limits(15)
            )),
            ["a", "b"]
        );
    }

    #[test]
    fn spares_followed_files_until_nothing_else_is_left() {
        let now = SystemTime::now();
        let followed: HashSet<PathBuf> = [PathBuf::from("live")].into();
        let files = [file("live", 10, 9, now), file("other", 10, 1, now)];
        assert_eq!(
            names(select_for_deletion(&files, &followed, now, limits(10))),
            ["other"]
        );
        assert_eq!(
            names(select_for_deletion(&files, &followed, now, limits(5))),
            ["other", "live"]
        );
        assert!(select_for_deletion(&files, &followed, now, limits(100)).is_empty());
    }

    #[test]
    fn sweep_deletes_files_and_empty_owner_dirs() {
        let root = tempfile::tempdir().unwrap();
        let gone = root.path().join("gone");
        let live = root.path().join("live");
        std::fs::create_dir_all(&gone).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(gone.join("a.0123456789ab.log"), vec![b'x'; 10]).unwrap();
        std::fs::write(gone.join("a.0123456789ab.log.1"), vec![b'x'; 10]).unwrap();
        std::fs::write(gone.join("notes.txt"), b"keep").unwrap();
        let followed: HashSet<PathBuf> = [live.join("b.0123456789ab.log")].into();
        std::fs::write(live.join("b.0123456789ab.log"), vec![b'x'; 10]).unwrap();

        let deleted = sweep(root.path(), &followed, limits(10)).unwrap();

        assert_eq!(deleted, 2);
        assert!(!gone.join("a.0123456789ab.log").exists());
        assert!(
            gone.join("notes.txt").exists(),
            "only archive files are touched"
        );
        assert!(live.join("b.0123456789ab.log").exists());

        std::fs::remove_file(gone.join("notes.txt")).unwrap();
        sweep(root.path(), &HashSet::new(), limits(100)).unwrap();
        assert!(!gone.exists(), "empty owner dir removed");
        assert!(live.exists(), "non-empty owner dir kept");
    }
}
