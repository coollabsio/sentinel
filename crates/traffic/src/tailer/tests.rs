use super::*;
use std::fs::OpenOptions;
use std::io::Write;

fn append(path: &Path, data: &[u8]) {
    let mut f = OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
}

/// Fresh temp dir with an empty `access.log` and a `Tailer` opened on it.
/// The `TempDir` is returned so the caller keeps it alive.
fn open_tailer() -> (tempfile::TempDir, PathBuf, Tailer) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("access.log");
    File::create(&path).unwrap();
    let tailer = Tailer::open(&path).unwrap();
    (dir, path, tailer)
}

#[test]
fn yields_complete_lines_appended_after_open() {
    let (_dir, path, mut tailer) = open_tailer();

    append(&path, b"line one\nline two\n");

    let mut out = Vec::new();
    tailer.poll_lines(&mut out).unwrap();

    assert_eq!(out, vec![b"line one".to_vec(), b"line two".to_vec()]);
}

#[test]
fn buffers_partial_line_until_newline_arrives() {
    let (_dir, path, mut tailer) = open_tailer();

    append(&path, b"incomplete line without newline yet");

    let mut out = Vec::new();
    tailer.poll_lines(&mut out).unwrap();
    assert_eq!(out.len(), 0, "no complete line yet");

    append(&path, b"\n");

    tailer.poll_lines(&mut out).unwrap();
    assert_eq!(out, vec![b"incomplete line without newline yet".to_vec()]);
}

#[test]
fn survives_rotation_and_reads_new_file_from_start() {
    let (dir, path, mut tailer) = open_tailer();

    append(&path, b"old file line\n");
    let mut out = Vec::new();
    tailer.poll_lines(&mut out).unwrap();
    assert_eq!(out, vec![b"old file line".to_vec()]);

    // Simulate rotation: rename old file away, create a fresh one at
    // the original path (as `mv access.log access.log.1` followed by
    // the proxy creating a new `access.log` would do).
    let rotated = dir.path().join("access.log.1");
    std::fs::rename(&path, &rotated).unwrap();
    let mut new_file = File::create(&path).unwrap();
    new_file.write_all(b"new file line\n").unwrap();
    new_file.flush().unwrap();
    drop(new_file);

    out.clear();
    tailer.poll_lines(&mut out).unwrap();
    assert_eq!(
        out,
        vec![b"new file line".to_vec()],
        "should read only the new file's content, not re-read the old file"
    );
}

#[test]
fn survives_truncation_and_reads_from_start() {
    let (_dir, path, mut tailer) = open_tailer();

    append(&path, b"a long line that will be truncated away\n");
    let mut out = Vec::new();
    tailer.poll_lines(&mut out).unwrap();
    assert_eq!(
        out,
        vec![b"a long line that will be truncated away".to_vec()]
    );

    // Simulate copytruncate: truncate the same file in place (same
    // inode) and write new, shorter content.
    let mut truncated = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    truncated.write_all(b"short\n").unwrap();
    truncated.flush().unwrap();
    drop(truncated);

    out.clear();
    tailer.poll_lines(&mut out).unwrap();
    assert_eq!(
        out,
        vec![b"short".to_vec()],
        "should read from position 0 after truncation, not from the stale offset"
    );
}
