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
use std::net::IpAddr;
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
    /// New entries let in without another scan: set when a scan couldn't
    /// bring the table below `max` (the entries it may forget ran out,
    /// because refused ones are kept), so a flood of new visitors costs one
    /// scan per tenth of the table, not one each. Meanwhile the table can
    /// pass `max` by that tenth plus the refused entries, never past twice
    /// `max`; `tidy` starts the count afresh.
    skip: usize,
}

impl<K: Eq + Hash + Copy> Table<K> {
    fn entry(&mut self, k: K, burst: u32, refill_ms: i64, window_ms: i64, max: usize, now: i64) -> &mut Entry {
        if !self.map.contains_key(&k) && self.map.len() >= max {
            if self.skip > 0 && self.map.len() < max.saturating_mul(2) {
                self.skip -= 1;
            } else {
                self.make_room(burst, refill_ms, window_ms, max, now);
                self.skip = if self.map.len() >= max { (max / 10).max(1) } else { 0 };
            }
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
            visitors: Mutex::new(Table { map: HashMap::new(), skip: 0 }),
            remembered: Mutex::new(Table { map: HashMap::new(), skip: 0 }),
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
        {
            let mut t = lock(&self.visitors);
            t.map.retain(|_, e| !e.clean(vb, vr, window, now));
            t.skip = 0;
        }
        let (rb, rr) = (l.remembered_burst, ms(l.remembered_refill).max(1));
        let mut t = lock(&self.remembered);
        t.map.retain(|_, e| !e.clean(rb, rr, window, now));
        t.skip = 0;
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

// ----- how many failures reach the store -----------------------------------------

/// Failure events kept in the store with no account: this many at once…
const ANONYMOUS_BURST: f64 = 100.0;
/// …then one every this many milliseconds.
const ANONYMOUS_EVERY_MS: f64 = 30_000.0;
/// Failure events kept per account: this many at once…
const ACCOUNT_BURST: f64 = 50.0;
/// …then one every this many milliseconds.
const ACCOUNT_EVERY_MS: f64 = 300_000.0;
/// Accounts tracked at once, normally (each entry is a few dozen bytes).
/// Accounts with failures still to report are kept beyond this, up to
/// twice as many.
const ACCOUNTS_TRACKED: usize = 100_000;
/// Distinct addresses kept in each report of failures not stored.
const REPORT_IPS: usize = 8;

/// Failures that weren't stored, for the report at the next upkeep: how
/// many, when the first and last were, and from which addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Dropped {
    pub(crate) count: u64,
    pub(crate) first_ms: i64,
    pub(crate) last_ms: i64,
    /// The first few distinct addresses.
    pub(crate) ips: Vec<IpAddr>,
    /// There were more addresses than listed.
    pub(crate) more_ips: bool,
}

impl Dropped {
    fn add(this: &mut Option<Dropped>, ip: Option<IpAddr>, now: i64) {
        let d = this.get_or_insert_with(|| Dropped {
            count: 0,
            first_ms: now,
            last_ms: now,
            ips: Vec::new(),
            more_ips: false,
        });
        d.count = d.count.saturating_add(1);
        d.last_ms = now;
        if let Some(ip) = ip
            && !d.ips.contains(&ip)
        {
            if d.ips.len() < REPORT_IPS {
                d.ips.push(ip);
            } else {
                d.more_ips = true;
            }
        }
    }

    /// The report as the detail of a `failures_not_stored` row.
    pub(crate) fn to_json(&self, user: Option<Uuid>) -> String {
        let mut v = serde_json::json!({
            "count": self.count,
            "first_ms": self.first_ms,
            "last_ms": self.last_ms,
            "ips": self.ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
            "more_ips": self.more_ips,
        });
        if let Some(u) = user {
            v["user"] = serde_json::Value::String(u.to_string());
        }
        v.to_string()
    }
}

#[derive(Clone, Debug)]
struct Bucket {
    tokens: f64,
    at_ms: i64,
    /// Failures not stored since the last report.
    dropped: Option<Dropped>,
}

impl Bucket {
    fn full(burst: f64, now: i64) -> Bucket {
        Bucket { tokens: burst, at_ms: now, dropped: None }
    }

    fn refill(&mut self, burst: f64, every_ms: f64, now: i64) {
        self.tokens = (self.tokens + (now - self.at_ms).max(0) as f64 / every_ms).min(burst);
        self.at_ms = now;
    }

    fn take(&mut self, burst: f64, every_ms: f64, ip: Option<IpAddr>, now: i64) -> bool {
        self.refill(burst, every_ms, now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            Dropped::add(&mut self.dropped, ip, now);
            false
        }
    }
}

#[derive(Default)]
struct LogState {
    anonymous: Option<Bucket>,
    accounts: HashMap<Uuid, Bucket>,
    /// New accounts to let in without another scan (as in the limiter).
    skip: usize,
}

impl LogState {
    /// Make room for one more account: forget accounts whose ration is whole
    /// and that have nothing to report, then a tenth of the rest that have
    /// nothing to report, the least drained first. Accounts with failures
    /// to report are never forgotten. `false` when the table has reached
    /// twice its size even so.
    fn make_room(&mut self, now: i64) -> bool {
        let max = ACCOUNTS_TRACKED;
        if self.skip > 0 && self.accounts.len() < 2 * max {
            self.skip -= 1;
            return true;
        }
        self.accounts.retain(|_, b| {
            b.refill(ACCOUNT_BURST, ACCOUNT_EVERY_MS, now);
            b.dropped.is_some() || b.tokens < ACCOUNT_BURST
        });
        if self.accounts.len() >= max {
            let mut quiet: Vec<(f64, Uuid)> =
                self.accounts.iter().filter(|(_, b)| b.dropped.is_none()).map(|(u, b)| (b.tokens, *u)).collect();
            quiet.sort_by(|a, b| b.0.total_cmp(&a.0));
            for (_, u) in quiet.into_iter().take(max / 10) {
                self.accounts.remove(&u);
            }
        }
        if self.accounts.len() >= max {
            self.skip = max / 10;
        }
        self.accounts.len() < 2 * max
    }
}

/// Rations the failure events written to the store. Every event still goes
/// to the `doorward::security` log target; only the rows are rationed, so a
/// flood of cheap failures (a wrong passkey answer costs no hashing) can't
/// fill the database or crowd out its writes. Per account: 50 at once, then
/// one every five minutes; for failures with no account: 100 at once, then
/// one every 30 seconds. What wasn't stored is reported at the next upkeep,
/// as one row per account (and one without) with the count, the first and
/// last time and the first few addresses.
pub(crate) struct LogBudget {
    state: Mutex<LogState>,
}

impl LogBudget {
    pub(crate) fn new() -> LogBudget {
        LogBudget { state: Mutex::new(LogState::default()) }
    }

    /// May this failure event, from `ip`, be stored?
    pub(crate) fn allow(&self, user: Option<Uuid>, ip: Option<IpAddr>, now: i64) -> bool {
        let mut st = lock(&self.state);
        let st = &mut *st;
        if let Some(u) = user
            && (st.accounts.contains_key(&u) || st.accounts.len() < ACCOUNTS_TRACKED || st.make_room(now))
        {
            let b = st.accounts.entry(u).or_insert_with(|| Bucket::full(ACCOUNT_BURST, now));
            return b.take(ACCOUNT_BURST, ACCOUNT_EVERY_MS, ip, now);
        }
        // No account, or (only past twice the table's size) no room to
        // track one: the shared ration.
        let b = st.anonymous.get_or_insert_with(|| Bucket::full(ANONYMOUS_BURST, now));
        b.take(ANONYMOUS_BURST, ANONYMOUS_EVERY_MS, ip, now)
    }

    /// The failures not stored since the last call, by account, and forget
    /// accounts that have nothing left to ration.
    pub(crate) fn take_dropped(&self, now: i64) -> Vec<(Option<Uuid>, Dropped)> {
        let mut st = lock(&self.state);
        let mut out = Vec::new();
        if let Some(d) = st.anonymous.as_mut().and_then(|b| b.dropped.take()) {
            out.push((None, d));
        }
        for (u, b) in st.accounts.iter_mut() {
            if let Some(d) = b.dropped.take() {
                out.push((Some(*u), d));
            }
        }
        st.accounts.retain(|_, b| {
            b.refill(ACCOUNT_BURST, ACCOUNT_EVERY_MS, now);
            b.tokens < ACCOUNT_BURST
        });
        st.skip = 0;
        out
    }
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
    fn a_table_full_of_refusals_is_scanned_once_per_tenth() {
        let mut t: Table<u32> = Table { map: HashMap::new(), skip: 0 };
        let refused = |now: i64| Entry { refused_until_ms: now + 1_000_000, failures: 0, ..Entry::new(20, now) };
        for k in 0..100u32 {
            t.map.insert(k, refused(0));
        }
        // The first newcomer scans and finds nothing to forget…
        t.entry(1_000, 20, 3_000, 900_000, 100, 1);
        assert_eq!((t.map.len(), t.skip), (101, 10));
        // …so the next ten come in without a scan…
        for k in 1_001..1_011u32 {
            t.entry(k, 20, 3_000, 900_000, 100, 2);
        }
        assert_eq!((t.map.len(), t.skip), (111, 0));
        // …and the one after scans again.
        t.entry(2_000, 20, 3_000, 900_000, 100, 3);
        assert_eq!(t.skip, 10);
        // Newcomers that were let in aren't refused, so the next scan can
        // forget them; refused entries are never forgotten below 2 × max.
        for k in 0..100u32 {
            assert!(t.map.contains_key(&k), "refused {k} kept");
        }
    }

    #[test]
    fn settings_are_checked() {
        assert!(Limits::default().check().is_ok());
        assert!(Limits { visitor_burst: 0, ..Limits::default() }.check().is_err());
        assert!(Limits { visitor_refill: Duration::ZERO, ..Limits::default() }.check().is_err());
        assert!(Limits { tracked_max: 5, ..Limits::default() }.check().is_err());
    }

    #[test]
    fn stored_failures_are_rationed_per_account_and_without_one() {
        let b = LogBudget::new();
        let alice = Some(Uuid::from_u128(1));
        let bob = Some(Uuid::from_u128(2));
        let ip = |n: u8| Some(IpAddr::from([198, 51, 100, n]));
        let stored = |user, n: usize, now| (0..n).filter(|i| b.allow(user, ip((i % 12) as u8), now)).count();
        assert_eq!(stored(alice, 80, 0), 50, "50 at once for an account");
        assert_eq!(stored(bob, 10, 0), 10, "another account has its own");
        assert_eq!(stored(None, 150, 0), 100, "100 at once without an account");
        // Five minutes later, one more for alice; 30 seconds, one more without.
        assert_eq!(stored(alice, 5, 300_000), 1);
        assert_eq!(stored(None, 30, 300_000), 10);
        // What wasn't stored is reported once, with when and from where.
        let mut dropped = b.take_dropped(300_000);
        dropped.sort_by_key(|(u, _)| *u);
        assert_eq!(dropped.len(), 2);
        let (none, a) = (&dropped[0], &dropped[1]);
        assert_eq!((none.0, none.1.count, none.1.first_ms, none.1.last_ms), (None, 70, 0, 300_000));
        assert_eq!((a.0, a.1.count), (alice, 34));
        assert_eq!(a.1.ips.len(), REPORT_IPS);
        assert!(a.1.more_ips);
        assert!(a.1.to_json(alice).contains(r#""count":34"#));
        assert!(b.take_dropped(300_000).is_empty());
        // Accounts with a whole ration are forgotten.
        assert!(b.take_dropped(100_000_000).is_empty());
        assert!(lock(&b.state).accounts.is_empty());
    }

    #[test]
    fn a_full_account_table_never_loses_an_accounts_report() {
        let b = LogBudget::new();
        // Every tracked account has drained its ration and has failures to
        // report, as an attacker could arrange.
        {
            let mut st = lock(&b.state);
            for i in 0..ACCOUNTS_TRACKED as u128 {
                let mut bucket = Bucket::full(ACCOUNT_BURST, 0);
                bucket.tokens = 0.0;
                Dropped::add(&mut bucket.dropped, None, 0);
                st.accounts.insert(Uuid::from_u128(i + 1_000_000), bucket);
            }
        }
        // A victim's failures are still rationed and reported as theirs.
        let victim = Some(Uuid::from_u128(7));
        let kept = (0..60).filter(|_| b.allow(victim, None, 1)).count();
        assert_eq!(kept, 50);
        let report = b.take_dropped(1).into_iter().find(|(u, _)| *u == victim).expect("the victim's report");
        assert_eq!(report.1.count, 10);
        // Accounts with nothing to report make way first, the least drained first.
        let quiet = LogBudget::new();
        {
            let mut st = lock(&quiet.state);
            for i in 0..ACCOUNTS_TRACKED as u128 {
                let mut bucket = Bucket::full(ACCOUNT_BURST, 0);
                bucket.tokens = if i == 0 { 1.0 } else { 49.0 };
                st.accounts.insert(Uuid::from_u128(i + 1_000_000), bucket);
            }
        }
        assert!(quiet.allow(victim, None, 1));
        let st = lock(&quiet.state);
        assert!(st.accounts.len() <= ACCOUNTS_TRACKED);
        assert!(st.accounts.contains_key(&Uuid::from_u128(1_000_000)), "the most drained stays");
    }
}
