//! Database dumps to S3 and restores from S3 (decision 0010).
//!
//! `database.dump.v1` runs the fixed dump command of an engine in a workload
//! container and uploads its output like a volume backup. `database.restore.v1`
//! downloads a dump, checks it, and streams it into the fixed restore command
//! of the engine. A request names the engine and the database, never a
//! command; the commands read the credentials from the environment and the
//! secret files of the container, so no credential passes through Sentinel.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use sentinel_protocol::control::v1::{
    DatabaseDumpRequest, DatabaseRestoreRequest, VolumeBackupResult, VolumeRestoreResult,
};
use sha2::{Digest, Sha256};

use crate::commands::valid_container_name;
use crate::network::output_with_timeout;
use crate::volume_backup::{
    PART_SIZE_MAX, PART_SIZE_MIN, SharedBackup, SharedRestore, drain, hex, http_client, http_error,
    kill, rejected, spawn, start_or_poll_backup, start_or_poll_restore, upload_compressed,
    valid_id, valid_part_urls, valid_sha256, valid_url,
};

/// Dumps wait in this directory until their checksum is verified.
const RESTORE_DIRECTORY: &str = "/var/lib/coolify/database-restores";
const INSPECT_TIMEOUT: Duration = Duration::from_secs(20);
/// The part size doubles every this many parts, so a small dump uses small
/// parts and the S3 limit of 10000 parts still holds about 970 GiB.
const PARTS_PER_SIZE: u32 = 2_000;

/// Reads the password of `$1` (a variable name) from `$1_FILE` or `$1`.
const SECRET: &str = r#"secret() { eval "file=\${${1}_FILE:-}"; if [ -n "$file" ]; then cat "$file"; else eval "printf '%s' \"\${${1}:-}\""; fi; }
"#;

const POSTGRES: &str = r#"set -e
user="${POSTGRES_USER:-postgres}"
PGPASSWORD="$(secret POSTGRES_PASSWORD)"
export PGPASSWORD
"#;
const POSTGRES_DUMP: &str =
    r#"exec pg_dump --format=custom --no-acl --no-owner --username="$user" --dbname="$1""#;
const POSTGRES_DUMP_ALL: &str = r#"exec pg_dumpall --clean --if-exists --username="$user""#;
const POSTGRES_RESTORE: &str = r#"createdb --username="$user" "$1" 2>/dev/null || true
exec pg_restore --clean --if-exists --no-acl --no-owner --username="$user" --dbname="$1""#;
const POSTGRES_RESTORE_ALL: &str = r#"exec psql --quiet --username="$user" --dbname=postgres"#;

const MYSQL: &str = r#"set -e
MYSQL_PWD="$(secret MYSQL_ROOT_PASSWORD)"
export MYSQL_PWD
"#;
const MARIADB: &str = r#"set -e
MYSQL_PWD="$(secret MARIADB_ROOT_PASSWORD)"
export MYSQL_PWD
"#;
const MYSQL_DUMP_FLAGS: &str = "--user=root --single-transaction --routines --events --triggers";

const MONGODB: &str = r#"set -e
user="${MONGO_INITDB_ROOT_USERNAME:-}"
config="password: \"$(secret MONGO_INITDB_ROOT_PASSWORD | sed 's/[\\"]/\\&/g')\""
if [ $# -gt 0 ]; then database="$1"; set -- --db="$database"; fi
"#;
const MONGODB_DUMP: &str = r#"exec mongodump --quiet --archive --authenticationDatabase=admin --username="$user" --config=/dev/fd/3 "$@" 3<<CONFIG
$config
CONFIG"#;
const MONGODB_RESTORE: &str = r#"if [ -n "${database:-}" ]; then set -- --nsInclude="$database.*"; fi
exec mongorestore --quiet --archive --drop --authenticationDatabase=admin --username="$user" --config=/dev/fd/3 "$@" 3<<CONFIG
$config
CONFIG"#;

/// `$1` is the client of the engine: `redis-cli` or `keydb-cli`.
const REDIS: &str = r#"set -e
REDISCLI_AUTH="${REDIS_PASSWORD:-}"
export REDISCLI_AUTH
client="$1"
cli() { "$client" --no-auth-warning "$@"; }
check() { if [ "$1" != OK ]; then echo "$1" >&2; exit 1; fi; }
"#;
const REDIS_DUMP: &str = r#"exec "$client" --no-auth-warning --rdb -"#;
/// Loads the dump without a restart. Redis 7 needs `enable-debug-command
/// local`. With AOF, a rewrite makes the restored data durable.
const REDIS_RESTORE: &str = r#"dir="$(cli CONFIG GET dir | sed -n 2p)"
file="$(cli CONFIG GET dbfilename | sed -n 2p)"
cat > "$dir/$file.coolify-restore"
mv "$dir/$file.coolify-restore" "$dir/$file"
check "$(cli DEBUG RELOAD NOSAVE)"
if [ "$(cli CONFIG GET appendonly | sed -n 2p)" = yes ]; then
  cli BGREWRITEAOF >/dev/null
  while cli INFO persistence | grep -Eq '^aof_rewrite_(in_progress|scheduled):1'; do sleep 1; done
  if ! cli INFO persistence | grep -q '^aof_last_bgrewrite_status:ok'; then echo "The AOF rewrite failed." >&2; exit 1; fi
fi"#;
const DRAGONFLY: &str = r#"set -e
REDISCLI_AUTH="${REDIS_PASSWORD:-}"
export REDISCLI_AUTH
cli() { redis-cli --no-auth-warning "$@"; }
check() { if [ "$1" != OK ]; then echo "$1" >&2; exit 1; fi; }
dir="$(cli CONFIG GET dir | sed -n 2p)"
dir="${dir:-.}"
"#;
const DRAGONFLY_DUMP: &str = r#"name="coolify-dump-$$"
trap 'rm -f "$dir/$name.rdb"' EXIT
check "$(cli SAVE RDB "$name")"
cat "$dir/$name.rdb""#;
const DRAGONFLY_RESTORE: &str = r#"name="coolify-restore-$$.rdb"
trap 'rm -f "$dir/$name"' EXIT
cat > "$dir/$name"
check "$(cli DFLY LOAD "$name")""#;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Engine {
    Postgresql,
    Mysql,
    Mariadb,
    Mongodb,
    Redis,
    Keydb,
    Dragonfly,
}

impl Engine {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "postgresql" => Self::Postgresql,
            "mysql" => Self::Mysql,
            "mariadb" => Self::Mariadb,
            "mongodb" => Self::Mongodb,
            "redis" => Self::Redis,
            "keydb" => Self::Keydb,
            "dragonfly" => Self::Dragonfly,
            _ => return None,
        })
    }

    /// Whether a dump can name one database.
    fn has_databases(self) -> bool {
        !matches!(self, Self::Redis | Self::Keydb | Self::Dragonfly)
    }

    /// The `sh -c` script and its arguments. `database` is empty or valid.
    fn script(self, restore: bool, database: &str) -> (String, Vec<String>) {
        let all = database.is_empty();
        let mysql = |prefix: &str, dump: &str, client: &str| {
            if restore {
                format!("{SECRET}{prefix}exec {client} --user=root")
            } else if all {
                format!("{SECRET}{prefix}exec {dump} {MYSQL_DUMP_FLAGS} --all-databases")
            } else {
                format!("{SECRET}{prefix}exec {dump} {MYSQL_DUMP_FLAGS} --databases \"$1\"")
            }
        };
        let script = match (self, restore) {
            (Self::Postgresql, false) => format!(
                "{SECRET}{POSTGRES}{}",
                if all {
                    POSTGRES_DUMP_ALL
                } else {
                    POSTGRES_DUMP
                }
            ),
            (Self::Postgresql, true) => format!(
                "{SECRET}{POSTGRES}{}",
                if all {
                    POSTGRES_RESTORE_ALL
                } else {
                    POSTGRES_RESTORE
                }
            ),
            (Self::Mysql, _) => mysql(MYSQL, "mysqldump", "mysql"),
            (Self::Mariadb, _) => mysql(MARIADB, "mariadb-dump", "mariadb"),
            (Self::Mongodb, false) => format!("{SECRET}{MONGODB}{MONGODB_DUMP}"),
            (Self::Mongodb, true) => format!("{SECRET}{MONGODB}{MONGODB_RESTORE}"),
            (Self::Redis | Self::Keydb, false) => format!("{REDIS}{REDIS_DUMP}"),
            (Self::Redis | Self::Keydb, true) => format!("{REDIS}{REDIS_RESTORE}"),
            (Self::Dragonfly, false) => format!("{DRAGONFLY}{DRAGONFLY_DUMP}"),
            (Self::Dragonfly, true) => format!("{DRAGONFLY}{DRAGONFLY_RESTORE}"),
        };
        let arguments = match self {
            Self::Redis => vec!["redis-cli".to_string()],
            Self::Keydb => vec!["keydb-cli".to_string()],
            Self::Dragonfly => Vec::new(),
            _ if all => Vec::new(),
            _ => vec![database.to_string()],
        };
        (script, arguments)
    }
}

fn valid_database(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn validate_target(container: &str, engine: &str, database: &str) -> Result<Engine, String> {
    if !valid_container_name(container) {
        return Err("The container name is invalid.".into());
    }
    let engine = Engine::parse(engine).ok_or("The database engine is not supported.")?;
    if !database.is_empty() && (!engine.has_databases() || !valid_database(database)) {
        return Err("The database name is invalid.".into());
    }
    Ok(engine)
}

pub(crate) fn validate_dump(request: &DatabaseDumpRequest) -> Result<(), String> {
    if !valid_id(&request.dump_id) {
        return Err("The dump ID is invalid.".into());
    }
    validate_target(&request.container_name, &request.engine, &request.database)?;
    if !valid_part_urls(&request.part_urls) {
        return Err("A part URL is invalid.".into());
    }
    Ok(())
}

pub(crate) fn validate_restore(request: &DatabaseRestoreRequest) -> Result<(), String> {
    if !valid_id(&request.restore_id) {
        return Err("The restore ID is invalid.".into());
    }
    validate_target(&request.container_name, &request.engine, &request.database)?;
    if !valid_url(&request.url) {
        return Err("The download URL is invalid.".into());
    }
    if !valid_sha256(&request.sha256) {
        return Err("The checksum is invalid.".into());
    }
    Ok(())
}

/// The ID of a running workload container: it carries `coolify.managed=true`
/// and `coolify.workload`, and is not one of Sentinel's own containers. The
/// dump and the restore use the ID, so a container that is replaced under the
/// same name is never used.
fn running_workload(podman: &Path, name: &str) -> Result<String, String> {
    let output = output_with_timeout(
        Command::new(podman).args(["container", "inspect", name]),
        INSPECT_TIMEOUT,
    )
    .map_err(|_| "Podman could not inspect the container.".to_string())?;
    if !output.status.success() {
        return Err("The database container does not exist.".into());
    }
    let containers: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .map_err(|_| "Podman returned invalid container data.".to_string())?;
    let container = containers
        .first()
        .ok_or("The database container does not exist.")?;
    let label = |key: &str| {
        container
            .pointer("/Config/Labels")
            .and_then(|labels| labels.get(key))
            .and_then(serde_json::Value::as_str)
    };
    if label("coolify.managed") != Some("true")
        || label("coolify.workload").is_none_or(str::is_empty)
        || label("coolify.service").is_some()
    {
        return Err("The container is not a workload that Coolify manages.".into());
    }
    if container.pointer("/State/Running") != Some(&serde_json::Value::Bool(true)) {
        return Err("The database container is not running.".into());
    }
    container
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty() && id.chars().all(|character| character.is_ascii_hexdigit()))
        .map(str::to_string)
        .ok_or_else(|| "Podman returned invalid container data.".to_string())
}

/// The part size doubles every [`PARTS_PER_SIZE`] parts.
fn dump_part_size(part_number: u32) -> u64 {
    PART_SIZE_MIN
        .saturating_mul(1 << ((part_number.saturating_sub(1)) / PARTS_PER_SIZE).min(16))
        .min(PART_SIZE_MAX)
}

pub(crate) fn dump(
    podman: &Path,
    request: &DatabaseDumpRequest,
) -> Result<VolumeBackupResult, String> {
    validate_dump(request)?;
    let engine = validate_target(&request.container_name, &request.engine, &request.database)?;
    let podman = podman.to_path_buf();
    let container = request.container_name.clone();
    let database = request.database.clone();
    start_or_poll_backup(
        &request.dump_id,
        format!("database {container} {} {database}", request.engine),
        &request.part_urls,
        request.abort,
        move || {
            let id = running_workload(&podman, &container)?;
            Ok(Box::new(move |shared: &SharedBackup| {
                let (script, arguments) = engine.script(false, &database);
                upload_compressed(
                    Command::new(&podman)
                        .args(["exec", &id, "sh", "-c", &script, "sh"])
                        .args(&arguments),
                    "The dump command",
                    &[0],
                    dump_part_size,
                    shared,
                )
            }))
        },
    )
}

pub(crate) fn restore(
    podman: &Path,
    request: &DatabaseRestoreRequest,
) -> Result<VolumeRestoreResult, String> {
    validate_restore(request)?;
    let engine = validate_target(&request.container_name, &request.engine, &request.database)?;
    let podman = podman.to_path_buf();
    let container = request.container_name.clone();
    let database = request.database.clone();
    let url = request.url.clone();
    let sha256 = request.sha256.clone();
    let archive_bytes = request.archive_bytes;
    let file = PathBuf::from(RESTORE_DIRECTORY).join(format!("{}.zst", request.restore_id));
    start_or_poll_restore(
        &request.restore_id,
        format!(
            "database {container} {} {database} {sha256}",
            request.engine
        ),
        archive_bytes,
        move || {
            let id = running_workload(&podman, &container)?;
            Ok(Box::new(move |shared: &SharedRestore| {
                let outcome = download_to_file(&url, &sha256, archive_bytes, &file, shared)
                    .and_then(|()| {
                        let (script, arguments) = engine.script(true, &database);
                        apply(&podman, &id, &script, &arguments, &file)
                    });
                let _ = std::fs::remove_file(&file);
                outcome
            }))
        },
    )
}

/// Downloads the archive to `file` and checks its size and SHA-256, so a
/// wrong or damaged archive never reaches the database.
fn download_to_file(
    url: &str,
    sha256: &str,
    archive_bytes: u64,
    file: &Path,
    shared: &SharedRestore,
) -> Result<(), String> {
    let directory = file.parent().ok_or("The restore directory is invalid.")?;
    std::fs::create_dir_all(directory)
        .map_err(|_| "The restore directory could not be created.".to_string())?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(file)
        .map_err(|_| "The restore file could not be created.".to_string())?;
    let (runtime, client) = http_client()?;
    let mut hasher = Sha256::new();
    let done = runtime.block_on(async {
        let mut response = client.get(url).send().await.map_err(http_error)?;
        if !response.status().is_success() {
            return Err(rejected(response, "the download").await);
        }
        if let Some(length) = response.content_length()
            && let Ok(mut restore) = shared.lock()
        {
            restore.bytes_total = length;
        }
        let mut done = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(http_error)? {
            hasher.update(&chunk);
            output
                .write_all(&chunk)
                .map_err(|_| "The archive could not be written to the Node.".to_string())?;
            done += chunk.len() as u64;
            if let Ok(mut restore) = shared.lock() {
                restore.bytes_done = done;
            }
        }
        Ok(done)
    })?;
    output
        .sync_all()
        .map_err(|_| "The archive could not be written to the Node.".to_string())?;
    if archive_bytes > 0 && done != archive_bytes {
        return Err(format!(
            "The archive has {done} bytes, but the backup recorded {archive_bytes}."
        ));
    }
    if hex(&hasher.finalize()) != sha256 {
        return Err("The checksum of the archive does not match the backup.".into());
    }
    Ok(())
}

/// Streams `zstd -d` of the archive into the restore command in the container.
fn apply(
    podman: &Path,
    id: &str,
    script: &str,
    arguments: &[String],
    file: &Path,
) -> Result<(), String> {
    let mut zstd = spawn(
        Command::new("zstd")
            .args(["-d", "-q", "-c"])
            .arg(file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        "zstd",
    )?;
    let zstd_errors = drain(zstd.stderr.take());
    let Some(archive) = zstd.stdout.take() else {
        kill(&mut zstd);
        return Err("zstd could not be started.".into());
    };
    let mut restore = match spawn(
        Command::new(podman)
            .args(["exec", "-i", id, "sh", "-c", script, "sh"])
            .args(arguments)
            .stdin(Stdio::from(archive))
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
        "podman",
    ) {
        Ok(restore) => restore,
        Err(error) => {
            kill(&mut zstd);
            return Err(error);
        }
    };
    let restore_errors = drain(restore.stderr.take());
    let restore_status = restore.wait();
    let zstd_status = zstd.wait();
    let restore_errors = restore_errors.join().unwrap_or_default();
    let zstd_errors = zstd_errors.join().unwrap_or_default();
    if !zstd_status.is_ok_and(|status| status.success()) {
        return Err(format!("zstd failed: {zstd_errors}"));
    }
    if !restore_status.is_ok_and(|status| status.success()) {
        return Err(format!("The restore command failed: {restore_errors}"));
    }
    Ok(())
}
