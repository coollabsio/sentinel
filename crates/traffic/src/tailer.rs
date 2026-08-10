#![forbid(unsafe_code)]

//! Rotation-aware access-log tailer. It yields complete raw-byte lines,
//! handles rename/recreate and copytruncate rotation, and starts at EOF.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Follows a single file at a fixed path across rotation and truncation.
pub struct Tailer {
    path: PathBuf,
    file: File,
    /// Inode of the currently-open file, used to detect rotation (the path
    /// now resolves to a different file than the one we have open).
    inode: u64,
    /// Byte offset into the currently-open file that we've already
    /// consumed (yielded as complete lines, or held in `partial`).
    pos: u64,
    /// Bytes read since `pos` that don't yet form a complete line (no
    /// trailing `\n`). Prepended to the next read.
    partial: Vec<u8>,
}

impl Tailer {
    /// Opens `path` and seeks to the end, so only lines appended after
    /// this call will be yielded by `poll_lines`.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let meta = file.metadata()?;
        let inode = meta.ino();
        let pos = file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            inode,
            pos,
            partial: Vec::new(),
        })
    }

    /// Reads whatever new, complete lines are available and appends them
    /// (without their trailing `\n`) to `out`. Handles rotation (path now
    /// points at a different inode) and truncation (file shrank below our
    /// read position) transparently. Never panics; genuine I/O errors are
    /// propagated via `?`. Transient races (file momentarily missing
    /// during rotation) are treated as "nothing to read this poll".
    pub fn poll_lines(&mut self, out: &mut Vec<Vec<u8>>) -> std::io::Result<()> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(meta) => meta,
            Err(_) => return Ok(()),
        };

        if meta.ino() != self.inode {
            // Rotation: the path now resolves to a new file. Reopen from
            // the start -- it's brand new, we haven't read any of it.
            let mut file = File::open(&self.path)?;
            file.seek(SeekFrom::Start(0))?;
            self.file = file;
            self.inode = meta.ino();
            self.pos = 0;
            self.partial.clear();
        } else if meta.len() < self.pos {
            // Truncation in place (e.g. copytruncate): seek back to 0.
            self.file.seek(SeekFrom::Start(0))?;
            self.pos = 0;
            self.partial.clear();
        }

        self.file.seek(SeekFrom::Start(self.pos))?;
        let mut reader = BufReader::new(&mut self.file);
        let mut chunk = Vec::new();
        reader.read_to_end(&mut chunk)?;

        if chunk.is_empty() {
            return Ok(());
        }

        self.partial.extend_from_slice(&chunk);
        self.pos += chunk.len() as u64;

        let mut consumed_up_to = 0usize;
        let mut start = 0usize;
        for (i, &b) in self.partial.iter().enumerate() {
            if b == b'\n' {
                out.push(self.partial[start..i].to_vec());
                start = i + 1;
                consumed_up_to = start;
            }
        }
        self.partial.drain(0..consumed_up_to);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
}
