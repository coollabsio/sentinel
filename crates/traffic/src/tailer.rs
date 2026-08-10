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
mod tests;
