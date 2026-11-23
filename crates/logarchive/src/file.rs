use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};

use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter};

use crate::line::{Timestamp, resume_point};

/// Bytes read from the end of an archive to find its resume point.
const TAIL_BYTES: u64 = 64 * 1024;

/// An archive file opened for buffered appends, rotated to `<path>.1` once
/// it grows past `max_bytes`.
pub struct ArchiveWriter {
    path: PathBuf,
    out: BufWriter<File>,
    size: u64,
    max_bytes: u64,
}

impl ArchiveWriter {
    pub async fn open(path: PathBuf, max_bytes: u64) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            create_private_dir(dir).await?;
        }
        let file = open_append(&path).await?;
        let size = file.metadata().await?.len();
        Ok(Self {
            path,
            out: BufWriter::new(file),
            size,
            max_bytes,
        })
    }

    pub async fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        if needs_rotation(self.size, self.max_bytes) {
            self.rotate().await?;
        }
        self.out.write_all(line).await?;
        self.size += line.len() as u64;
        Ok(())
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.out.flush().await
    }

    async fn rotate(&mut self) -> io::Result<()> {
        self.out.flush().await?;
        tokio::fs::rename(&self.path, rotated_path(&self.path)).await?;
        self.out = BufWriter::new(open_append(&self.path).await?);
        self.size = 0;
        Ok(())
    }
}

pub fn needs_rotation(size: u64, max_bytes: u64) -> bool {
    size > max_bytes
}

pub fn rotated_path(path: &Path) -> PathBuf {
    let mut rotated = path.as_os_str().to_owned();
    rotated.push(".1");
    PathBuf::from(rotated)
}

/// The timestamp of the last line already archived for `path`, looking at
/// the rotated file when the current one has none (missing, or just rotated).
pub async fn read_resume_point(path: &Path) -> Option<Timestamp> {
    for candidate in [path.to_path_buf(), rotated_path(path)] {
        if let Ok(tail) = read_tail(&candidate).await
            && let Some(at) = resume_point(&tail)
        {
            return Some(at);
        }
    }
    None
}

async fn read_tail(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path).await?;
    let len = file.metadata().await?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(TAIL_BYTES)))
        .await?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).await?;
    Ok(tail)
}

/// Archived logs can hold secrets, so new directories are `0700` and new
/// files `0600`, like the json logs Docker keeps for root only.
pub async fn create_private_dir(dir: &Path) -> io::Result<()> {
    tokio::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .await
}

async fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rotates_past_the_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner/c.0123456789ab.log");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(rotated_path(&path), b"stale\n").unwrap();

        let mut writer = ArchiveWriter::open(path.clone(), 10).await.unwrap();
        writer.write_line(b"0123456789\n").await.unwrap();
        writer.write_line(b"second\n").await.unwrap();
        writer.write_line(b"third\n").await.unwrap();
        writer.flush().await.unwrap();

        assert_eq!(std::fs::read(rotated_path(&path)).unwrap(), b"0123456789\n");
        assert_eq!(std::fs::read(&path).unwrap(), b"second\nthird\n");
    }

    #[tokio::test]
    async fn creates_files_and_directories_readable_by_the_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root/owner/c.0123456789ab.log");
        let mut writer = ArchiveWriter::open(path.clone(), 1).await.unwrap();
        writer.write_line(b"one\n").await.unwrap();
        writer.write_line(b"two\n").await.unwrap();
        writer.flush().await.unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join("root")), 0o700);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&rotated_path(&path)), 0o600);
    }

    #[tokio::test]
    async fn appends_to_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.log");
        std::fs::write(&path, b"one\n").unwrap();
        let mut writer = ArchiveWriter::open(path.clone(), 1024).await.unwrap();
        writer.write_line(b"two\n").await.unwrap();
        writer.flush().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one\ntwo\n");
    }

    #[tokio::test]
    async fn resumes_from_the_rotated_file_when_the_current_one_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.log");
        assert_eq!(read_resume_point(&path).await, None);
        std::fs::write(rotated_path(&path), b"2026-10-27T10:15:30.5Z old\n").unwrap();
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            read_resume_point(&path).await,
            Timestamp::parse("2026-10-27T10:15:30.5Z")
        );
        std::fs::write(&path, b"2026-10-27T10:15:31Z new\n").unwrap();
        assert_eq!(
            read_resume_point(&path).await,
            Timestamp::parse("2026-10-27T10:15:31Z")
        );
    }
}
