use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};

use crate::StoreError;

const DAY_MS: i64 = 86_400_000;
const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS command_executions (
    command_id  TEXT PRIMARY KEY,
    request     BLOB NOT NULL,
    result      BLOB,
    status      TEXT NOT NULL CHECK (status IN ('running', 'completed')),
    started_at  INTEGER NOT NULL,
    completed_at INTEGER
) STRICT;
CREATE INDEX IF NOT EXISTS idx_command_executions_cleanup
    ON command_executions (status, completed_at);
"#;

#[derive(Debug, PartialEq, Eq)]
pub enum CommandStart {
    Started,
    Completed(Vec<u8>),
    Interrupted,
    Conflict,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CommandLookup {
    Missing,
    Completed(Vec<u8>),
    Interrupted,
    Conflict,
}

#[derive(Clone)]
pub struct CommandJournal {
    connection: Arc<Mutex<Connection>>,
    retention_days: u32,
    max_records: u32,
}

impl CommandJournal {
    pub fn open(path: &Path, retention_days: u32, max_records: u32) -> Result<Self, StoreError> {
        if let Some(directory) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            std::fs::create_dir_all(directory)?;
        }
        Self::from_connection(Connection::open(path)?, retention_days, max_records)
    }

    pub fn open_in_memory(retention_days: u32, max_records: u32) -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?, retention_days, max_records)
    }

    fn from_connection(
        connection: Connection,
        retention_days: u32,
        max_records: u32,
    ) -> Result<Self, StoreError> {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(DDL)?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            retention_days,
            max_records,
        })
    }

    pub fn start(
        &self,
        command_id: &str,
        request: &[u8],
        now_ms: i64,
    ) -> Result<CommandStart, StoreError> {
        match self.lookup(command_id, request)? {
            CommandLookup::Completed(result) => return Ok(CommandStart::Completed(result)),
            CommandLookup::Interrupted => return Ok(CommandStart::Interrupted),
            CommandLookup::Conflict => return Ok(CommandStart::Conflict),
            CommandLookup::Missing => {}
        }
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        connection.execute(
            "INSERT INTO command_executions (command_id, request, status, started_at) VALUES (?1, ?2, 'running', ?3)",
            params![command_id, request, now_ms],
        )?;
        Ok(CommandStart::Started)
    }

    pub fn lookup(&self, command_id: &str, request: &[u8]) -> Result<CommandLookup, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let existing = connection
            .query_row(
                "SELECT request, result, status FROM command_executions WHERE command_id = ?1",
                [command_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;

        if let Some((stored_request, result, status)) = existing {
            if stored_request != request {
                return Ok(CommandLookup::Conflict);
            }
            return if status == "completed" {
                Ok(CommandLookup::Completed(result.unwrap_or_default()))
            } else {
                Ok(CommandLookup::Interrupted)
            };
        }
        Ok(CommandLookup::Missing)
    }

    pub fn finish(&self, command_id: &str, result: &[u8], now_ms: i64) -> Result<(), StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        connection.execute(
            "UPDATE command_executions SET result = ?2, status = 'completed', completed_at = ?3 WHERE command_id = ?1 AND status = 'running'",
            params![command_id, result, now_ms],
        )?;
        Ok(())
    }

    pub fn cleanup(&self, now_ms: i64) -> Result<u64, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let cutoff = now_ms.saturating_sub(i64::from(self.retention_days).saturating_mul(DAY_MS));
        let mut deleted = connection.execute(
            "DELETE FROM command_executions WHERE status = 'completed' AND completed_at < ?1",
            [cutoff],
        )? as u64;
        let completed: i64 = connection.query_row(
            "SELECT COUNT(*) FROM command_executions WHERE status = 'completed'",
            [],
            |row| row.get(0),
        )?;
        let excess = completed.saturating_sub(i64::from(self.max_records));
        if excess > 0 {
            deleted += connection.execute(
                "DELETE FROM command_executions WHERE command_id IN (
                    SELECT command_id FROM command_executions
                    WHERE status = 'completed' ORDER BY completed_at ASC LIMIT ?1
                )",
                [excess],
            )? as u64;
        }
        Ok(deleted)
    }
}
