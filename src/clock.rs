//! Wall-clock time in milliseconds since the Unix epoch.

/// Now, in milliseconds since the Unix epoch (0 if the clock is before 1970).
pub(crate) fn system_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}
