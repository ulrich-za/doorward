//! Choosing Argon2id settings for the machine the app runs on.

use argon2::{Algorithm, Argon2, Params, Version};
use std::time::Instant;

use super::memory::{Memory, detect_memory};
use crate::error::Error;

pub(crate) const KIB_PER_MIB: u32 = 1024;
/// OWASP's minimum: 19 MiB with at least 2 passes…
pub(crate) const FLOOR_M: u32 = 19 * KIB_PER_MIB;
/// …or 46 MiB and more with at least 1.
pub(crate) const ONE_PASS_M: u32 = 46 * KIB_PER_MIB;
/// Past a few hundred MiB, more memory buys little; it would mostly slow
/// sign-ins and give a flood more memory to eat.
pub(crate) const CAP_M: u32 = 256 * KIB_PER_MIB;
/// Two checks at a time only when each still gets this much.
const SHARE_MIN_M: u32 = 32 * KIB_PER_MIB;
pub(crate) const MAX_T: u32 = 10;
/// How long one check should take.
const TARGET_MS: f64 = 350.0;
/// Shrink the memory if the fewest passes allowed would take longer.
const SLOW_MS: f64 = 1000.0;
/// Retune when the machine's memory changes by more than this fraction.
const RETUNE_CHANGE: f64 = 0.2;

/// How passwords are hashed on this machine: Argon2id with a memory size
/// and number of passes chosen by [`HashPolicy::tune`].
///
/// Save it (it is small, and serialisable with the `serde` feature) and
/// load it on the next start with [`HashPolicy::load_or_tune`], so the
/// machine is timed only once. Where it is saved is up to the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HashPolicy {
    /// Memory per check, in KiB.
    pub m_kib: u32,
    /// Passes over that memory.
    pub t: u32,
    /// Lanes (always 1).
    pub p: u32,
    /// Checks allowed at once (1 or 2).
    pub concurrency: u32,
    /// The memory the policy was chosen for, in bytes (0 = unknown).
    pub ram_total: u64,
    /// About how long one check takes, in milliseconds.
    pub check_ms: u32,
    /// When it was chosen, in milliseconds since the Unix epoch (0 = never).
    pub tuned_ms: i64,
}

impl HashPolicy {
    /// OWASP's minimum (19 MiB, 2 passes, one check at a time), for machines
    /// whose memory can't be read and for tests.
    pub const fn floor() -> HashPolicy {
        HashPolicy { m_kib: FLOOR_M, t: 2, p: 1, concurrency: 1, ram_total: 0, check_ms: 0, tuned_ms: 0 }
    }

    /// Within doorward's limits: 19–256 MiB, OWASP's fewest passes for that
    /// memory up to 10, one lane, one or two checks at a time.
    pub fn is_valid(&self) -> bool {
        (FLOOR_M..=CAP_M).contains(&self.m_kib)
            && (t_floor(self.m_kib)..=MAX_T).contains(&self.t)
            && self.p == 1
            && (1..=2).contains(&self.concurrency)
    }

    pub(crate) fn params(&self) -> Result<Params, Error> {
        if !self.is_valid() {
            return Err(Error::InvalidHashPolicy);
        }
        Params::new(self.m_kib, self.t, self.p, None).map_err(|_| Error::InvalidHashPolicy)
    }

    pub(crate) fn argon2(&self) -> Result<Argon2<'static>, Error> {
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params()?))
    }

    /// Choose settings for this much memory by timing real hashes on this
    /// machine. Blocks for a second or two of full CPU: call it from a
    /// blocking thread, not an async task.
    ///
    /// With `None` (memory unknown) it uses the minimum memory and times only
    /// the number of passes.
    pub fn tune(mem: Option<Memory>) -> Result<HashPolicy, Error> {
        let (mut m, concurrency) = plan_memory(mem);
        loop {
            match time_pass(m)? {
                Some(pass) if pass * t_floor(m) as f64 <= SLOW_MS || m == FLOOR_M => {
                    let t = pick_t(m, pass);
                    let policy = HashPolicy {
                        m_kib: m,
                        t,
                        p: 1,
                        concurrency,
                        ram_total: mem.map_or(0, |m| m.total),
                        check_ms: (pass * t as f64).round().min(u32::MAX as f64) as u32,
                        tuned_ms: crate::clock::system_now_ms(),
                    };
                    debug_assert!(policy.is_valid());
                    return Ok(policy);
                }
                None if m == FLOOR_M => return Err(Error::NotEnoughMemory),
                // Too slow, or that much memory isn't free: try half.
                _ => m = (m / 2).max(FLOOR_M),
            }
        }
    }

    /// [`HashPolicy::tune`] for this machine's memory as detected.
    pub fn tune_for_this_machine() -> Result<HashPolicy, Error> {
        HashPolicy::tune(detect_memory())
    }

    /// Should this saved policy be replaced? Yes when it is outside
    /// doorward's limits, when it was chosen for unknown memory but memory can
    /// be read now, or when total memory changed by more than a fifth (a RAM
    /// upgrade, a resized VM or container).
    pub fn needs_retune(&self, now: Option<Memory>) -> bool {
        !self.is_valid() || ram_changed(self.ram_total, now)
    }

    /// The saved policy (`saved`, as made by [`HashPolicy::to_json`]) when it
    /// still fits this machine, otherwise a newly tuned one. The flag is
    /// `true` when the policy is new and should be saved. `force` always
    /// retunes. Blocks while tuning (see [`HashPolicy::tune`]).
    pub fn load_or_tune(saved: Option<&str>, force: bool) -> Result<(HashPolicy, bool), Error> {
        let mem = detect_memory();
        if !force
            && let Some(p) = saved.and_then(HashPolicy::from_json)
            && !p.needs_retune(mem)
        {
            return Ok((p, false));
        }
        Ok((HashPolicy::tune(mem)?, true))
    }

    /// The policy as a short JSON string, for saving.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// A saved policy, or `None` when it is unreadable or outside doorward's
    /// limits.
    pub fn from_json(s: &str) -> Option<HashPolicy> {
        if s.len() > 4096 {
            return None;
        }
        serde_json::from_str::<HashPolicy>(s).ok().filter(HashPolicy::is_valid)
    }

    /// One line for the log, such as "Argon2id, 256 MiB, 3 passes, about
    /// 340 ms per check, 2 at a time, sized for 63.9 GiB of memory".
    pub fn describe(&self) -> String {
        let ram = if self.ram_total > 0 {
            format!(", sized for {:.1} GiB of memory", self.ram_total as f64 / (1u64 << 30) as f64)
        } else {
            String::new()
        };
        format!(
            "Argon2id, {} MiB, {} pass{}, about {} ms per check, {} at a time{ram}",
            self.m_kib / KIB_PER_MIB,
            self.t,
            if self.t == 1 { "" } else { "es" },
            self.check_ms,
            self.concurrency
        )
    }
}

/// The fewest passes OWASP allows at this memory.
pub(crate) fn t_floor(m_kib: u32) -> u32 {
    if m_kib >= ONE_PASS_M { 1 } else { 2 }
}

/// Memory per check (KiB) and checks at a time for this much memory: the
/// budget is 2 % of total or 10 % of free, whichever is smaller, split in two
/// when each half still gets 32 MiB, and held to 19–256 MiB per check.
pub fn plan_memory(mem: Option<Memory>) -> (u32, u32) {
    let Some(mem) = mem else { return (FLOOR_M, 1) };
    let budget_kib = ((mem.total / 50).min(mem.available / 10) / 1024).min(u32::MAX as u64) as u32;
    let (per, concurrency) = if budget_kib / 2 >= SHARE_MIN_M { (budget_kib / 2, 2) } else { (budget_kib, 1) };
    (per.clamp(FLOOR_M, CAP_M), concurrency)
}

/// Passes for a check of about 350 ms, given how long one pass takes, never
/// below OWASP's minimum and never above 10.
pub fn pick_t(m_kib: u32, pass_ms: f64) -> u32 {
    let pass_ms = if pass_ms.is_finite() { pass_ms.max(0.1) } else { 0.1 };
    let t = (TARGET_MS / pass_ms).round().min(MAX_T as f64) as u32;
    t.clamp(t_floor(m_kib), MAX_T)
}

/// How long one Argon2id pass over `m_kib` takes here (best of two), or
/// `None` when that memory can't be had.
fn time_pass(m_kib: u32) -> Result<Option<f64>, Error> {
    let params = Params::new(m_kib, 1, 1, Some(32)).map_err(|_| Error::InvalidHashPolicy)?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| Error::Random)?;
    let mut out = [0u8; 32];
    let mut best = f64::MAX;
    for _ in 0..2 {
        let start = Instant::now();
        match a.hash_password_into(b"doorward calibration", &salt, &mut out) {
            Ok(()) => best = best.min(start.elapsed().as_secs_f64() * 1000.0),
            Err(argon2::Error::OutOfMemory) => return Ok(None),
            Err(_) => return Err(Error::Hashing),
        }
    }
    Ok(Some(best))
}

fn ram_changed(was: u64, now: Option<Memory>) -> bool {
    match now {
        Some(now) if was > 0 => (now.total as f64 - was as f64).abs() / was as f64 > RETUNE_CHANGE,
        Some(_) => true,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    fn mem(total: u64, available: u64) -> Option<Memory> {
        Some(Memory { total, available })
    }

    #[test]
    fn memory_follows_the_machine() {
        // 16 GB, mostly free: 2 % = 327 MiB, two checks of 163 MiB.
        assert_eq!(plan_memory(mem(16 * GIB, 12 * GIB)), (163 * KIB_PER_MIB + 860, 2));
        // 64 GB: capped at 256 MiB each.
        assert_eq!(plan_memory(mem(64 * GIB, 60 * GIB)), (CAP_M, 2));
        // Busy 8 GB machine: 10 % of 1 GiB free = 102 MiB, two of 51 MiB.
        assert_eq!(plan_memory(mem(8 * GIB, GIB)).1, 2);
        assert_eq!(plan_memory(mem(8 * GIB, GIB)).0 / KIB_PER_MIB, 51);
        // 2 GB Pi: 41 MiB is too little to share, so one check at a time.
        assert_eq!(plan_memory(mem(2 * GIB, 1500 * MIB)), (40 * KIB_PER_MIB + 983, 1));
        // 512 MB: never below the floor.
        assert_eq!(plan_memory(mem(512 * MIB, 200 * MIB)), (FLOOR_M, 1));
        assert_eq!(plan_memory(mem(0, 0)), (FLOOR_M, 1));
        assert_eq!(plan_memory(mem(u64::MAX, u64::MAX)), (CAP_M, 2));
        assert_eq!(plan_memory(None), (FLOOR_M, 1));
    }

    #[test]
    fn passes_meet_owasp_and_the_time_target() {
        assert_eq!(pick_t(FLOOR_M, 40.0), 9); // fast machine: more passes
        assert_eq!(pick_t(FLOOR_M, 300.0), 2); // never below 2 under 46 MiB
        assert_eq!(pick_t(CAP_M, 600.0), 1);
        assert_eq!(pick_t(CAP_M, 120.0), 3);
        assert_eq!(pick_t(CAP_M, 1.0), MAX_T);
        assert_eq!(pick_t(CAP_M, 0.0), MAX_T);
        assert_eq!(pick_t(CAP_M, f64::NAN), MAX_T);
        assert_eq!(pick_t(FLOOR_M, f64::INFINITY), MAX_T);
        assert_eq!(pick_t(FLOOR_M, 1e12), 2);
    }

    #[test]
    fn retunes_only_on_a_real_memory_change() {
        assert!(!ram_changed(16 * GIB, mem(15 * GIB, GIB)));
        assert!(ram_changed(16 * GIB, mem(8 * GIB, GIB)));
        assert!(ram_changed(16 * GIB, mem(20 * GIB, GIB)));
        assert!(ram_changed(0, mem(8 * GIB, GIB)));
        assert!(!ram_changed(16 * GIB, None));
    }

    #[test]
    fn validity_limits() {
        assert!(HashPolicy::floor().is_valid());
        let ok = HashPolicy { m_kib: CAP_M, t: 1, concurrency: 2, ..HashPolicy::floor() };
        assert!(ok.is_valid());
        for bad in [
            HashPolicy { m_kib: FLOOR_M - 1, ..HashPolicy::floor() },
            HashPolicy { m_kib: CAP_M + 1, t: 1, ..HashPolicy::floor() },
            HashPolicy { t: 1, ..HashPolicy::floor() }, // 19 MiB needs 2 passes
            HashPolicy { t: MAX_T + 1, ..HashPolicy::floor() },
            HashPolicy { p: 2, ..HashPolicy::floor() },
            HashPolicy { concurrency: 0, ..HashPolicy::floor() },
            HashPolicy { concurrency: 3, ..HashPolicy::floor() },
        ] {
            assert!(!bad.is_valid(), "{bad:?}");
            assert!(bad.params().is_err());
            assert!(bad.needs_retune(None));
        }
    }

    #[test]
    fn saved_policies_round_trip_and_bad_ones_are_dropped() {
        let p = HashPolicy {
            m_kib: 64 * KIB_PER_MIB,
            t: 3,
            concurrency: 2,
            ram_total: 8 * GIB,
            check_ms: 300,
            tuned_ms: 1,
            ..HashPolicy::floor()
        };
        assert_eq!(HashPolicy::from_json(&p.to_json()), Some(p));
        assert_eq!(
            HashPolicy::from_json(
                "{\"m_kib\":1,\"t\":1,\"p\":1,\"concurrency\":1,\"ram_total\":0,\"check_ms\":0,\"tuned_ms\":0}"
            ),
            None
        );
        assert_eq!(HashPolicy::from_json("not json"), None);
        assert_eq!(HashPolicy::from_json(&"x".repeat(5000)), None);
    }

    #[test]
    fn tuning_meets_the_floor() {
        let p = HashPolicy::tune(mem(GIB, 512 * MIB)).unwrap();
        assert!(p.is_valid(), "{p:?}");
        assert_eq!(p.concurrency, 1);
        assert!(p.describe().starts_with("Argon2id, 20 MiB"), "{}", p.describe());
        let unknown = HashPolicy::tune(None).unwrap();
        assert_eq!((unknown.m_kib, unknown.concurrency, unknown.ram_total), (FLOOR_M, 1, 0));
    }
}
