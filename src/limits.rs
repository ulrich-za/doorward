//! Rate limits that nobody can use to lock you out.
//!
//! - Each visitor (an IPv4 address, or an IPv6 /64) has its own small budget
//!   of sign-in attempts, refilled over time. A flood from one visitor only
//!   slows that visitor.
//! - A visitor that keeps failing is slowed, then refused for a while.
//! - A *remembered browser* (one that signed in before, holding the device
//!   cookie) has its own budget and skips the per-visitor slow-down, so a
//!   flood from elsewhere — even from the same address — can't reach it. The
//!   budget belongs to the account, shared by all its remembered browsers,
//!   and only counts attempts at that same account.
//! - Accounts are never locked: a lock that follows failures can be set off
//!   by anyone who knows a username.
//! - The only global limit is on CPU: one or two password checks at a time
//!   (see [`crate::password::Hasher::turn`]).

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Duration;

use crate::clock::ms;
use crate::error::Error;
use crate::net::VisitorKey;
use uuid::Uuid;

/// Rate-limit settings. The defaults suit a small office behind one address
/// as well as a single owner reached over the internet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Attempts a visitor may make in a burst.
    pub visitor_burst: u32,
    /// One more attempt is allowed every this long.
    pub visitor_refill: Duration,
    /// After this many failures (within `window`) a visitor is slowed…
    pub slow_after: u32,
    /// …by this much per further failure…
    pub slow_step: Duration,
    /// …up to this much per attempt.
    pub slow_max: Duration,
    /// After this many failures within `window`, refuse for `refuse_for`.
    pub refuse_after: u32,
    /// How long failures are remembered.
    pub window: Duration,
    /// How long a visitor (or remembered browser) that failed too often is refused.
    pub refuse_for: Duration,
    /// Attempts a remembered browser may make in a burst.
    pub remembered_burst: u32,
    /// One more attempt for a remembered browser every this long.
    pub remembered_refill: Duration,
    /// Failures within `window` before a remembered browser is refused.
    pub remembered_refuse_after: u32,
    /// Most visitors (and, separately, accounts with remembered browsers)
    /// tracked at once. Visitors being refused are kept beyond this, up to
    /// twice as many.
    pub tracked_max: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            visitor_burst: 20,
            visitor_refill: Duration::from_secs(3),
            slow_after: 5,
            slow_step: Duration::from_millis(500),
            slow_max: Duration::from_secs(5),
            refuse_after: 20,
            window: Duration::from_secs(15 * 60),
            refuse_for: Duration::from_secs(15 * 60),
            remembered_burst: 10,
            remembered_refill: Duration::from_secs(6),
            remembered_refuse_after: 10,
            tracked_max: 100_000,
        }
    }
}

impl Limits {
    pub(crate) fn check(&self) -> Result<(), Error> {
        let ok = self.visitor_burst >= 1
            && self.remembered_burst >= 1
            && !self.visitor_refill.is_zero()
            && !self.remembered_refill.is_zero()
            && self.refuse_after >= 1
            && self.remembered_refuse_after >= 1
            && self.tracked_max >= 100
            && !self.window.is_zero();
        if ok { Ok(()) } else { Err(Error::Config(format!("rate limits out of range: {self:?}"))) }
    }
}

/// Whose budget an attempt is counted against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Who {
    Visitor(VisitorKey),
    /// An attempt at this account, from one of its remembered browsers.
    Remembered(Uuid),
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    tokens: f64,
    refilled_ms: i64,
    failures: u32,
    last_failure_ms: i64,
    refused_until_ms: i64,
    seen_ms: i64,
}

impl Entry {
    fn new(burst: u32, now: i64) -> Entry {
        Entry {
            tokens: burst as f64,
            refilled_ms: now,
            failures: 0,
            last_failure_ms: 0,
            refused_until_ms: 0,
            seen_ms: now,
        }
    }

    fn clean(&self, burst: u32, refill_ms: i64, window_ms: i64, now: i64) -> bool {
        let tokens = self.tokens + (now - self.refilled_ms).max(0) as f64 / refill_ms as f64;
        tokens >= burst as f64
            && self.refused_until_ms <= now
            && (self.failures == 0 || now - self.last_failure_ms >= window_ms)
    }
}

struct Table<K> {
    map: HashMap<K, Entry>,
}

impl<K: Eq + Hash + Copy> Table<K> {
    fn entry(&mut self, k: K, burst: u32, refill_ms: i64, window_ms: i64, max: usize, now: i64) -> &mut Entry {
        if !self.map.contains_key(&k) && self.map.len() >= max {
            self.make_room(burst, refill_ms, window_ms, max, now);
        }
        let e = self.map.entry(k).or_insert_with(|| Entry::new(burst, now));
        e.seen_ms = now;
        e
    }

    /// Forget idle entries first; then a tenth of the rest that aren't
    /// refused, those without recent failures and seen longest ago first.
    /// Refused entries are never forgotten while there are others, so a
    /// flood of fresh addresses can't wash out a visitor that is refused;
    /// the table may then grow to twice `max`, and only beyond that are the
    /// refusals that end soonest forgotten (which keeps memory bounded).
    fn make_room(&mut self, burst: u32, refill_ms: i64, window_ms: i64, max: usize, now: i64) {
        self.map.retain(|_, e| !e.clean(burst, refill_ms, window_ms, now));
        if self.map.len() < max {
            return;
        }
        let tenth = (max / 10).max(1);
        let mut candidates: Vec<((bool, i64), K)> = self
            .map
            .iter()
            .filter(|(_, e)| e.refused_until_ms <= now)
            .map(|(k, e)| ((e.failures > 0 && now - e.last_failure_ms < window_ms, e.seen_ms), *k))
            .collect();
        if candidates.is_empty() {
            if self.map.len() < max.saturating_mul(2) {
                return;
            }
            candidates = self.map.iter().map(|(k, e)| ((false, e.refused_until_ms), *k)).collect();
        }
        candidates.sort_by_key(|(order, _)| *order);
        for (_, k) in candidates.into_iter().take(tenth) {
            self.map.remove(&k);
        }
    }
}

/// The two tables, behind one lock each.
pub(crate) struct Limiter {
    limits: Limits,
    visitors: Mutex<Table<VisitorKey>>,
    remembered: Mutex<Table<Uuid>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // Each update is a few field writes; a panic mid-way can't leave the
    // table unusable, so carry on with a poisoned lock.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Limiter {
    pub(crate) fn new(limits: Limits) -> Limiter {
        Limiter {
            limits,
            visitors: Mutex::new(Table { map: HashMap::new() }),
            remembered: Mutex::new(Table { map: HashMap::new() }),
        }
    }

    /// Ask to make one attempt. `Ok(delay)` to go ahead after waiting
    /// `delay`; [`Error::TooManyAttempts`] to refuse.
    pub(crate) fn admit(&self, who: Who, now: i64) -> Result<Duration, Error> {
        let l = &self.limits;
        let window = ms(l.window);
        match who {
            Who::Visitor(k) => {
                let refill = ms(l.visitor_refill).max(1);
                let mut t = lock(&self.visitors);
                let e = t.entry(k, l.visitor_burst, refill, window, l.tracked_max, now);
                take(e, l.visitor_burst, refill, window, now)?;
                let over = e.failures.saturating_sub(l.slow_after);
                let delay = l.slow_step.saturating_mul(over).min(l.slow_max);
                Ok(delay)
            }
            Who::Remembered(h) => {
                let refill = ms(l.remembered_refill).max(1);
                let mut t = lock(&self.remembered);
                let e = t.entry(h, l.remembered_burst, refill, window, l.tracked_max, now);
                take(e, l.remembered_burst, refill, window, now)?;
                Ok(Duration::ZERO)
            }
        }
    }

    /// Count a failed attempt.
    pub(crate) fn failed(&self, who: Who, now: i64) {
        let l = &self.limits;
        let window = ms(l.window);
        let (e_fail, refuse_after) = match who {
            Who::Visitor(k) => {
                let refill = ms(l.visitor_refill).max(1);
                let mut t = lock(&self.visitors);
                let e = t.entry(k, l.visitor_burst, refill, window, l.tracked_max, now);
                (fail(e, window, now), l.refuse_after)
            }
            Who::Remembered(h) => {
                let refill = ms(l.remembered_refill).max(1);
                let mut t = lock(&self.remembered);
                let e = t.entry(h, l.remembered_burst, refill, window, l.tracked_max, now);
                (fail(e, window, now), l.remembered_refuse_after)
            }
        };
        if e_fail >= refuse_after {
            let until = now.saturating_add(ms(l.refuse_for));
            match who {
                Who::Visitor(k) => {
                    if let Some(e) = lock(&self.visitors).map.get_mut(&k) {
                        e.refused_until_ms = until;
                        e.failures = 0;
                    }
                }
                Who::Remembered(h) => {
                    if let Some(e) = lock(&self.remembered).map.get_mut(&h) {
                        e.refused_until_ms = until;
                        e.failures = 0;
                    }
                }
            }
        }
    }

    /// Forget entries that have nothing against them (for periodic upkeep).
    pub(crate) fn tidy(&self, now: i64) {
        let l = &self.limits;
        let window = ms(l.window);
        let (vb, vr) = (l.visitor_burst, ms(l.visitor_refill).max(1));
        lock(&self.visitors).map.retain(|_, e| !e.clean(vb, vr, window, now));
        let (rb, rr) = (l.remembered_burst, ms(l.remembered_refill).max(1));
        lock(&self.remembered).map.retain(|_, e| !e.clean(rb, rr, window, now));
    }

    #[cfg(test)]
    fn tracked(&self) -> (usize, usize) {
        (lock(&self.visitors).map.len(), lock(&self.remembered).map.len())
    }
}

fn take(e: &mut Entry, burst: u32, refill_ms: i64, window_ms: i64, now: i64) -> Result<(), Error> {
    if e.refused_until_ms > now {
        return Err(Error::TooManyAttempts { retry_after: Duration::from_millis((e.refused_until_ms - now) as u64) });
    }
    if e.failures > 0 && now - e.last_failure_ms >= window_ms {
        e.failures = 0;
    }
    let elapsed = (now - e.refilled_ms).max(0) as f64;
    e.tokens = (e.tokens + elapsed / refill_ms as f64).min(burst as f64);
    e.refilled_ms = now;
    if e.tokens < 1.0 {
        let wait = ((1.0 - e.tokens) * refill_ms as f64).ceil() as u64;
        return Err(Error::TooManyAttempts { retry_after: Duration::from_millis(wait.max(1)) });
    }
    e.tokens -= 1.0;
    Ok(())
}

fn fail(e: &mut Entry, window_ms: i64, now: i64) -> u32 {
    if e.failures > 0 && now - e.last_failure_ms >= window_ms {
        e.failures = 0;
    }
    e.failures = e.failures.saturating_add(1);
    e.last_failure_ms = now;
    e.failures
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u8) -> Who {
        Who::Visitor(VisitorKey::of(std::net::IpAddr::from([198, 51, 100, n])))
    }

    #[test]
    fn a_burst_then_the_refill_rate() {
        let l = Limiter::new(Limits::default());
        for _ in 0..20 {
            assert_eq!(l.admit(v(1), 0).unwrap(), Duration::ZERO);
        }
        let e = l.admit(v(1), 0).unwrap_err();
        assert_eq!(e.retry_after(), Some(Duration::from_secs(3)));
        assert!(l.admit(v(1), 2_999).is_err());
        assert!(l.admit(v(1), 3_000).is_ok());
        // Another visitor is unaffected.
        assert!(l.admit(v(2), 0).is_ok());
    }

    #[test]
    fn failures_slow_then_refuse_the_visitor_only() {
        let l = Limiter::new(Limits::default());
        let mut now = 0;
        for i in 1..=19 {
            now += 3_000;
            let delay = l.admit(v(1), now).unwrap();
            let expect = Duration::from_millis(500 * (i as u64 - 1).saturating_sub(5)).min(Duration::from_secs(5));
            assert_eq!(delay, expect, "attempt {i}");
            l.failed(v(1), now);
        }
        now += 3_000;
        assert!(l.admit(v(1), now).is_ok());
        l.failed(v(1), now); // the 20th failure
        let refused = l.admit(v(1), now + 1).unwrap_err();
        assert!(refused.retry_after().unwrap() > Duration::from_secs(14 * 60));
        assert!(l.admit(v(2), now + 1).is_ok(), "only that visitor");
        // After the refusal ends, it starts clean.
        assert_eq!(l.admit(v(1), now + 15 * 60_000).unwrap(), Duration::ZERO);
    }

    #[test]
    fn old_failures_are_forgotten() {
        let l = Limiter::new(Limits::default());
        for i in 0..10 {
            l.admit(v(1), i * 3_000).unwrap();
            l.failed(v(1), i * 3_000);
        }
        assert!(l.admit(v(1), 30_000).unwrap() > Duration::ZERO);
        assert_eq!(l.admit(v(1), 30_000 + 15 * 60_000).unwrap(), Duration::ZERO);
    }

    #[test]
    fn remembered_browsers_have_their_own_budget_and_no_slow_down() {
        let l = Limiter::new(Limits::default());
        let me = Who::Remembered(Uuid::from_u128(7));
        // The attacker shares my address and has exhausted it.
        for i in 0..40 {
            let _ = l.admit(v(1), i);
            l.failed(v(1), i);
        }
        assert!(l.admit(v(1), 100).is_err());
        assert_eq!(l.admit(me, 100).unwrap(), Duration::ZERO);
        // A stolen remembered cookie still runs out, and the account's
        // remembered browsers are refused after 10 failures.
        for i in 0..9 {
            l.failed(me, 200 + i);
        }
        assert!(l.admit(me, 300).is_ok());
        l.failed(me, 300);
        assert!(l.admit(me, 301).is_err());
    }

    #[test]
    fn tables_stay_bounded_and_keep_the_ones_with_failures() {
        let l = Limiter::new(Limits { tracked_max: 100, ..Limits::default() });
        // A visitor with failures…
        let bad = Who::Visitor(VisitorKey::of("2001:db8::1".parse().unwrap()));
        for i in 0..20 {
            let _ = l.admit(bad, i);
            l.failed(bad, i);
        }
        // …then a flood of fresh addresses.
        for i in 0..5_000u32 {
            let ip = std::net::IpAddr::from((0x0a00_0000u32 + i).to_be_bytes());
            let _ = l.admit(Who::Visitor(VisitorKey::of(ip)), 1_000 + i as i64);
        }
        assert!(l.tracked().0 <= 100);
        assert!(l.admit(bad, 10_000).is_err(), "still refused: entries with failures outlive clean ones");
        l.tidy(10_000_000);
        assert_eq!(l.tracked(), (0, 0));
    }

    #[test]
    fn a_failing_flood_cant_wash_out_a_refused_visitor() {
        let l = Limiter::new(Limits { tracked_max: 100, ..Limits::default() });
        let bad = Who::Visitor(VisitorKey::of("2001:db8:ffff::1".parse().unwrap()));
        for i in 0..20 {
            let _ = l.admit(bad, i);
            l.failed(bad, i);
        }
        assert!(l.admit(bad, 100).is_err());
        // Thousands of other /64s, each failing once.
        for i in 0..5_000u32 {
            let ip = std::net::IpAddr::from(
                (0x2001_0db8_0000_0000_0000_0000_0000_0000u128 + ((i as u128) << 64)).to_be_bytes(),
            );
            let w = Who::Visitor(VisitorKey::of(ip));
            let _ = l.admit(w, 1_000 + i as i64);
            l.failed(w, 1_000 + i as i64);
        }
        assert!(l.tracked().0 <= 100);
        assert!(l.admit(bad, 10_000).is_err(), "still refused");
    }

    #[test]
    fn refused_entries_stay_bounded() {
        let l = Limiter::new(Limits { tracked_max: 100, refuse_after: 1, ..Limits::default() });
        // Every visitor in the flood gets itself refused.
        for i in 0..1_000u32 {
            let w = Who::Visitor(VisitorKey::of(std::net::IpAddr::from((0x0a00_0000u32 + i).to_be_bytes())));
            let _ = l.admit(w, i as i64);
            l.failed(w, i as i64);
        }
        assert!(l.tracked().0 <= 200, "{}", l.tracked().0);
    }

    #[test]
    fn settings_are_checked() {
        assert!(Limits::default().check().is_ok());
        assert!(Limits { visitor_burst: 0, ..Limits::default() }.check().is_err());
        assert!(Limits { visitor_refill: Duration::ZERO, ..Limits::default() }.check().is_err());
        assert!(Limits { tracked_max: 5, ..Limits::default() }.check().is_err());
    }
}
