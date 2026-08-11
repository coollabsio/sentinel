use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

/// Equivalent to the Go layout "2006-01-02T15:04:05Z": a literal trailing Z,
/// no offsets accepted.
pub const LAYOUT: &[BorrowedFormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

#[derive(Debug, thiserror::Error)]
#[error("Invalid date format. Use YYYY-MM-DDTHH:MM:SSZ")]
pub struct TimeError;

/// Parses a `from`/`to` bound into unix milliseconds UTC.
pub fn parse_bound(s: &str) -> Result<i64, TimeError> {
    let dt = PrimitiveDateTime::parse(s, LAYOUT).map_err(|_| TimeError)?;
    Ok((dt.assume_utc().unix_timestamp_nanos() / 1_000_000) as i64)
}

/// Renders unix millis in the same layout, for `human_friendly_time`.
pub fn format_millis(ms: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .ok()
        .and_then(|dt| dt.format(LAYOUT).ok())
        .unwrap_or_default()
}

/// The current time in the same layout, used as the default `to` bound.
pub fn now_layout() -> String {
    OffsetDateTime::now_utc().format(LAYOUT).unwrap_or_default()
}

/// The current time as unix milliseconds UTC, for bucket-aligning a series.
pub fn now_ms() -> i64 {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}
