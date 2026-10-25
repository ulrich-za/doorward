//! Wall-clock time in milliseconds since the Unix epoch.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

/// Where doorward gets the time from. The default is the system clock; tests
/// use [`ManualClock`] to move time forward.
pub trait Clock: Send + Sync + 'static {
    /// Now, in milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        system_now_ms()
    }
}

/// A clock that only moves when told to, for tests.
#[derive(Clone, Debug)]
pub struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    /// A clock showing `now_ms`.
    pub fn new(now_ms: i64) -> ManualClock {
        ManualClock(Arc::new(AtomicI64::new(now_ms)))
    }

    /// Move the clock forward (or back, with a negative value).
    pub fn advance(&self, by: std::time::Duration) {
        self.0.fetch_add(by.as_millis().min(i64::MAX as u128) as i64, Ordering::SeqCst);
    }

    /// Set the clock.
    pub fn set(&self, now_ms: i64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Now, in milliseconds since the Unix epoch (0 if the clock is before 1970).
pub(crate) fn system_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// A duration in milliseconds, saturating.
pub(crate) fn ms(d: std::time::Duration) -> i64 {
    d.as_millis().min(i64::MAX as u128) as i64
}
