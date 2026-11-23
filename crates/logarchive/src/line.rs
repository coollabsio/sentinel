use std::fmt;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// A log timestamp as `(seconds, nanoseconds)` since the epoch. Compared
/// numerically: Docker trims trailing zeros from the fraction, so the text of
/// two timestamps does not order the way the instants do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    secs: i64,
    nanos: u32,
}

impl Timestamp {
    /// Any RFC 3339 timestamp, with any fraction length and any offset.
    pub fn parse(text: &str) -> Option<Self> {
        let at = OffsetDateTime::parse(text, &Rfc3339).ok()?;
        Some(Self {
            secs: at.unix_timestamp(),
            nanos: at.nanosecond(),
        })
    }

    pub fn from_unix_nanos(nanos: i64) -> Self {
        Self {
            secs: nanos.div_euclid(1_000_000_000),
            nanos: nanos.rem_euclid(1_000_000_000) as u32,
        }
    }

    pub fn now() -> Self {
        let at = OffsetDateTime::now_utc();
        Self {
            secs: at.unix_timestamp(),
            nanos: at.nanosecond(),
        }
    }

    pub fn secs(self) -> i64 {
        self.secs
    }
}

/// RFC 3339 in UTC with exactly nine fraction digits, as `docker logs
/// --timestamps` prints it: `2026-10-27T10:15:30.123456789Z`.
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let at = OffsetDateTime::from_unix_timestamp(self.secs).map_err(|_| fmt::Error)?;
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            at.year(),
            u8::from(at.month()),
            at.day(),
            at.hour(),
            at.minute(),
            at.second(),
            self.nanos
        )
    }
}

/// One log line: its timestamp and its text without the trailing newline.
#[derive(Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub at: Timestamp,
    pub text: &'a [u8],
}

impl Record<'_> {
    /// `<timestamp> <text>\n`
    pub fn to_line(&self) -> Vec<u8> {
        let mut line = format!("{} ", self.at).into_bytes();
        line.extend_from_slice(self.text);
        line.push(b'\n');
        line
    }
}

/// Splits a chunk of a `timestamps=true` log stream into records. A Docker
/// frame is normally one `<timestamp> <text>` line; a piece without a
/// timestamp (a TTY continuation) takes the timestamp before it, or
/// `fallback` when the chunk starts without one.
pub fn parse_chunk(chunk: &[u8], fallback: Timestamp) -> Vec<Record<'_>> {
    let chunk = chunk.strip_suffix(b"\n").unwrap_or(chunk);
    let mut at = fallback;
    chunk
        .split(|&b| b == b'\n')
        .map(|piece| match split_timestamp(piece) {
            Some(record) => {
                at = record.at;
                record
            }
            None => Record { at, text: piece },
        })
        .collect()
}

fn split_timestamp(line: &[u8]) -> Option<Record<'_>> {
    let space = line.iter().position(|&b| b == b' ')?;
    let at = Timestamp::parse(std::str::from_utf8(&line[..space]).ok()?)?;
    Some(Record {
        at,
        text: &line[space + 1..],
    })
}

/// The line appended when a container exits. `at` must be on Docker's clock
/// and not before the last archived line, so it can be the resume point.
pub fn exit_marker(at: Timestamp, exit_code: i64, oom_killed: bool) -> Vec<u8> {
    let oom = if oom_killed { ", OOM killed" } else { "" };
    format!("{at} [coolify] Container exited with code {exit_code}{oom}\n").into_bytes()
}

/// The resume point of an archive: the timestamp of its last line. Exit
/// markers carry Docker's clock too, so they count like log lines.
pub fn resume_point(tail: &[u8]) -> Option<Timestamp> {
    tail.rsplit(|&b| b == b'\n')
        .find_map(split_timestamp)
        .map(|record| record.at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(text: &str) -> Timestamp {
        Timestamp::parse(text).unwrap()
    }

    #[test]
    fn compares_trimmed_fractions_numerically() {
        assert!(ts("2026-10-27T10:15:30.1Z") < ts("2026-10-27T10:15:30.100000001Z"));
        assert_eq!(
            ts("2026-10-27T10:15:30.1Z"),
            ts("2026-10-27T10:15:30.100000000Z")
        );
        assert!(ts("2026-10-27T10:15:30Z") < ts("2026-10-27T10:15:30.000000001Z"));
        assert!(ts("2026-10-27T10:15:30.9Z") < ts("2026-10-27T10:15:31Z"));
        assert_eq!(
            ts("2026-10-27T12:15:30.5+02:00"),
            ts("2026-10-27T10:15:30.5Z")
        );
        assert_eq!(Timestamp::parse("not-a-time"), None);
    }

    #[test]
    fn formats_fixed_width_utc() {
        assert_eq!(
            ts("2026-10-27T10:15:30.1Z").to_string(),
            "2026-10-27T10:15:30.100000000Z"
        );
        assert_eq!(
            ts("2026-10-27T12:15:30.123456789+02:00").to_string(),
            "2026-10-27T10:15:30.123456789Z"
        );
        assert_eq!(
            ts("2026-01-02T03:04:05Z").to_string(),
            "2026-01-02T03:04:05.000000000Z"
        );
    }

    #[test]
    fn parses_a_docker_frame() {
        let records = parse_chunk(b"2026-10-27T10:15:30.1Z hello world\n", Timestamp::now());
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].to_line(),
            b"2026-10-27T10:15:30.100000000Z hello world\n"
        );
    }

    #[test]
    fn terminates_a_partial_frame() {
        let records = parse_chunk(b"2026-10-27T10:15:30.1Z partial", Timestamp::now());
        assert_eq!(
            records[0].to_line(),
            b"2026-10-27T10:15:30.100000000Z partial\n"
        );
    }

    #[test]
    fn untimestamped_pieces_inherit_the_previous_timestamp() {
        let fallback = ts("2026-10-27T09:00:00Z");
        let records = parse_chunk(b"no stamp\n2026-10-27T10:15:30.5Z a\ncontinued\n", fallback);
        let lines: Vec<Vec<u8>> = records.iter().map(Record::to_line).collect();
        assert_eq!(
            lines,
            vec![
                b"2026-10-27T09:00:00.000000000Z no stamp\n".to_vec(),
                b"2026-10-27T10:15:30.500000000Z a\n".to_vec(),
                b"2026-10-27T10:15:30.500000000Z continued\n".to_vec(),
            ]
        );
    }

    #[test]
    fn writes_the_exit_marker() {
        let at = ts("2026-10-27T10:15:30.123456789Z");
        assert_eq!(
            exit_marker(at, 3, false),
            b"2026-10-27T10:15:30.123456789Z [coolify] Container exited with code 3\n"
        );
        assert_eq!(
            exit_marker(at, 137, true),
            b"2026-10-27T10:15:30.123456789Z [coolify] Container exited with code 137, OOM killed\n"
        );
    }

    #[test]
    fn resumes_from_the_last_line() {
        let tail = b"ill line\n\
2026-10-27T10:15:30.100000000Z a\n\
2026-10-27T10:15:31.000000000Z [coolify] Container exited with code 0\n";
        assert_eq!(resume_point(tail), Some(ts("2026-10-27T10:15:31Z")));
        assert_eq!(resume_point(b"no stamp\n"), None);
        assert_eq!(resume_point(b""), None);
    }

    #[test]
    fn converts_unix_nanos() {
        assert_eq!(
            Timestamp::from_unix_nanos(1_793_096_130_500_000_000),
            ts("2026-10-27T10:15:30.5Z")
        );
    }
}
