//! Password hashing: Argon2id, sized to the machine it runs on.
//!
//! Each password check uses a fixed slice of memory and real CPU time, which
//! is what makes guessing slow. The slice is chosen once from the machine's
//! memory (2 % of the total or 10 % of what's free, whichever is smaller,
//! split between two checks at a time), the number of passes is timed so a
//! check takes about a third of a second, and the result is saved by the app.
//! It is never weaker than OWASP's minimum (19 MiB with 2 passes, or 46 MiB
//! with one) and never more than 256 MiB per check.
//!
//! ```no_run
//! use doorward::password::{HashPolicy, Hasher, Verdict};
//!
//! # fn main() -> Result<(), doorward::Error> {
//! # let saved: Option<String> = None;
//! // On start: reuse the saved policy, or time this machine (a second or two).
//! let (policy, changed) = HashPolicy::load_or_tune(saved.as_deref(), false)?;
//! if changed {
//!     // save policy.to_json() wherever the app keeps its settings
//! }
//! let hasher = Hasher::new(policy)?;
//!
//! let phc = hasher.hash("correct horse battery staple")?;
//! match hasher.verify("correct horse battery staple", Some(&phc)) {
//!     Verdict::Good { rehash } => { /* signed in; if rehash, hash again and save */ }
//!     Verdict::Wrong => { /* refuse */ }
//!     Verdict::Busy => { /* not enough memory right now: ask to retry */ }
//! }
//! # Ok(()) }
//! ```

mod memory;
mod policy;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};
use argon2::{Argon2, Params, Version};
use std::sync::RwLock;
use zeroize::Zeroizing;

use crate::error::Error;
pub use memory::{Memory, detect_memory};
use policy::KIB_PER_MIB;
pub use policy::{HashPolicy, pick_t, plan_memory};

/// Longest password accepted, in bytes. Longer input is refused before any
/// hashing, so nobody can make the server hash megabytes.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Saved hashes asking for more than these are refused rather than tried, so
/// a tampered or corrupt row can't make one check eat the machine.
const SANE_M: u32 = 1024 * KIB_PER_MIB;
const SANE_T: u32 = 32;
const SANE_P: u32 = 16;
/// Memory × passes, in MiB-passes (doorward's own policies stay at or below
/// 256 MiB × 10).
const SANE_WORK: u64 = 4096;

/// What checking a password found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// Right. When `rehash` is set the saved hash uses other settings than
    /// the current policy: hash the password again and save the new hash.
    Good {
        /// The saved hash should be replaced by one made with the current policy.
        rehash: bool,
    },
    /// Wrong password, unknown user, or an unusable saved hash.
    Wrong,
    /// Not enough free memory to check right now; ask the user to retry.
    Busy,
}

impl Verdict {
    /// The password was right.
    pub fn is_good(self) -> bool {
        matches!(self, Verdict::Good { .. })
    }
}

struct Active {
    policy: HashPolicy,
    /// A stand-in hash that unknown usernames are checked against, so they
    /// take as long as real ones.
    dummy: String,
}

/// Hashes and checks passwords with the policy in force.
///
/// The hashing calls block for about a third of a second each: run them on a
/// blocking thread. With the `tokio` feature, [`Hasher::turn`] limits how many
/// run at once to the policy's concurrency (one or two), which bounds the
/// memory a flood of sign-ins can use; [`Hasher::hash_async`] and
/// [`Hasher::verify_async`] do both.
pub struct Hasher {
    active: RwLock<Active>,
    gate: tokio::sync::Semaphore,
}

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hasher").field("policy", &self.policy()).finish_non_exhaustive()
    }
}

impl Hasher {
    /// A hasher for `policy`. Hashes one random stand-in password, so this
    /// blocks for one check.
    pub fn new(policy: HashPolicy) -> Result<Hasher, Error> {
        let dummy = make_dummy(&policy)?;
        Ok(Hasher { active: RwLock::new(Active { policy, dummy }), gate: tokio::sync::Semaphore::new(2) })
    }

    /// The policy in force.
    pub fn policy(&self) -> HashPolicy {
        self.read().policy
    }

    /// Switch to a newly tuned policy. Saved hashes keep working; each one is
    /// reported as needing a rehash at its next successful check.
    pub fn replace(&self, policy: HashPolicy) -> Result<(), Error> {
        let dummy = make_dummy(&policy)?;
        let mut w = self.active.write().unwrap_or_else(|e| e.into_inner());
        *w = Active { policy, dummy };
        Ok(())
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Active> {
        // A panic elsewhere while holding the lock can't leave `Active`
        // half-written (it is replaced whole), so a poisoned lock is safe to use.
        self.active.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Hash a new password as a PHC string (`$argon2id$v=19$m=…`), with a
    /// fresh random salt. Blocks for one check.
    pub fn hash(&self, password: &str) -> Result<String, Error> {
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(Error::PasswordTooLong);
        }
        let policy = self.policy();
        hash_with(password.as_bytes(), &policy)
    }

    /// Check `password` against a saved PHC hash. With no saved hash (an
    /// unknown user, or one without a password) the stand-in is checked
    /// instead, so the answer takes as long, and is always [`Verdict::Wrong`].
    /// Blocks for one check.
    pub fn verify(&self, password: &str, phc: Option<&str>) -> Verdict {
        let (policy, dummy) = {
            let a = self.read();
            (a.policy, a.dummy.clone())
        };
        if password.len() > MAX_PASSWORD_BYTES {
            return Verdict::Wrong;
        }
        match phc {
            Some(phc) => check_with(password.as_bytes(), phc, &policy),
            None => match check_with(password.as_bytes(), &dummy, &policy) {
                Verdict::Busy => Verdict::Busy,
                _ => Verdict::Wrong,
            },
        }
    }

    /// Wait up to `wait` for a turn to hash or check a password. The policy
    /// allows one or two at once; the turn ends when the returned permit is
    /// dropped. `None` when the wait ran out (report the service as busy).
    pub async fn turn(&self, wait: std::time::Duration) -> Option<tokio::sync::SemaphorePermit<'_>> {
        let n = if self.policy().concurrency >= 2 { 1 } else { 2 };
        tokio::time::timeout(wait, self.gate.acquire_many(n)).await.ok()?.ok()
    }

    /// [`Hasher::hash`] on a blocking thread, after waiting up to `wait` for a
    /// turn ([`Error::Busy`] when none came).
    pub async fn hash_async(
        self: &std::sync::Arc<Self>,
        password: Zeroizing<String>,
        wait: std::time::Duration,
    ) -> Result<String, Error> {
        let _turn = self.turn(wait).await.ok_or(Error::Busy)?;
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.hash(&password)).await.map_err(|_| Error::Hashing)?
    }

    /// [`Hasher::verify`] on a blocking thread, after waiting up to `wait` for
    /// a turn ([`Verdict::Busy`] when none came).
    pub async fn verify_async(
        self: &std::sync::Arc<Self>,
        password: Zeroizing<String>,
        phc: Option<String>,
        wait: std::time::Duration,
    ) -> Verdict {
        let Some(_turn) = self.turn(wait).await else {
            return Verdict::Busy;
        };
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.verify(&password, phc.as_deref())).await.unwrap_or(Verdict::Wrong)
    }
}

fn make_dummy(policy: &HashPolicy) -> Result<String, Error> {
    let mut random = Zeroizing::new([0u8; 24]);
    getrandom::fill(random.as_mut()).map_err(|_| Error::Random)?;
    hash_with(random.as_ref(), policy)
}

fn hash_with(password: &[u8], policy: &HashPolicy) -> Result<String, Error> {
    let a = policy.argon2()?;
    match a.hash_password(password) {
        Ok(h) => Ok(h.to_string()),
        Err(argon2::password_hash::Error::OutOfMemory) => Err(Error::Busy),
        Err(_) => Err(Error::Hashing),
    }
}

fn check_with(password: &[u8], phc: &str, policy: &HashPolicy) -> Verdict {
    if phc.len() > 512 {
        tracing::warn!(target: "doorward::security", "a saved password hash is implausibly long; refusing it");
        return Verdict::Wrong;
    }
    let Ok(hash) = PasswordHash::new(phc) else {
        tracing::warn!(target: "doorward::security", "a saved password hash is unreadable");
        return Verdict::Wrong;
    };
    if !hash.algorithm.as_str().starts_with("argon2") {
        tracing::warn!(target: "doorward::security", "a saved password hash isn't Argon2; refusing it");
        return Verdict::Wrong;
    }
    let Ok(saved) = Params::try_from(&hash) else {
        return Verdict::Wrong;
    };
    if !sane(&saved) {
        tracing::warn!(
            target: "doorward::security",
            m_mib = saved.m_cost() / KIB_PER_MIB,
            t = saved.t_cost(),
            p = saved.p_cost(),
            "a saved password hash asks for too much work; refusing it"
        );
        return Verdict::Wrong;
    }
    // The hash's own algorithm, version and settings are used, so hashes made
    // with older settings keep verifying.
    match Argon2::default().verify_password(password, &hash) {
        Ok(()) => Verdict::Good {
            rehash: hash.algorithm.as_str() != "argon2id"
                || hash.version != Some(Version::V0x13.into())
                || saved.m_cost() != policy.m_kib
                || saved.t_cost() != policy.t
                || saved.p_cost() != policy.p
                || saved.output_len().is_some_and(|l| l != Params::DEFAULT_OUTPUT_LEN)
                || hash.salt.as_ref().is_none_or(|s| s.len() < 16),
        },
        Err(argon2::password_hash::Error::OutOfMemory) => Verdict::Busy,
        Err(_) => Verdict::Wrong,
    }
}

fn sane(p: &Params) -> bool {
    p.m_cost() <= SANE_M
        && p.t_cost() <= SANE_T
        && p.p_cost() <= SANE_P
        && (p.m_cost() as u64 / KIB_PER_MIB as u64).max(1) * p.t_cost() as u64 <= SANE_WORK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quick() -> HashPolicy {
        HashPolicy { concurrency: 2, ..HashPolicy::floor() }
    }

    #[test]
    fn hash_check_and_rehash() {
        let pw = Hasher::new(quick()).unwrap();
        let phc = pw.hash("correct horse").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert_eq!(pw.verify("correct horse", Some(&phc)), Verdict::Good { rehash: false });
        assert_eq!(pw.verify("wrong", Some(&phc)), Verdict::Wrong);
        assert_eq!(pw.verify("", Some(&phc)), Verdict::Wrong);
        // Unknown user: the stand-in is checked, never accepted.
        assert_eq!(pw.verify("correct horse", None), Verdict::Wrong);
        // Settings changed since: the right password asks to be rehashed.
        pw.replace(HashPolicy { t: 3, ..quick() }).unwrap();
        assert_eq!(pw.verify("correct horse", Some(&phc)), Verdict::Good { rehash: true });
        // Old argon2 defaults (19 MiB, t=2) from before tuning still sign in.
        let old = Argon2::default().hash_password(b"legacy").unwrap().to_string();
        assert!(pw.verify("legacy", Some(&old)).is_good());
    }

    #[test]
    fn salts_are_fresh() {
        let pw = Hasher::new(quick()).unwrap();
        assert_ne!(pw.hash("same").unwrap(), pw.hash("same").unwrap());
    }

    #[test]
    fn older_variants_verify_and_ask_for_a_rehash() {
        let pw = Hasher::new(quick()).unwrap();
        let params = Params::new(19 * 1024, 2, 1, None).unwrap();
        for alg in [argon2::Algorithm::Argon2i, argon2::Algorithm::Argon2d] {
            let a = Argon2::new(alg, Version::V0x13, params.clone());
            let phc = a.hash_password(b"pw").unwrap().to_string();
            assert_eq!(pw.verify("pw", Some(&phc)), Verdict::Good { rehash: true }, "{alg:?}");
        }
        let a = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x10, params);
        let phc = a.hash_password(b"pw").unwrap().to_string();
        assert_eq!(pw.verify("pw", Some(&phc)), Verdict::Good { rehash: true });
    }

    #[test]
    fn absurd_saved_settings_are_refused() {
        let pw = Hasher::new(quick()).unwrap();
        let salt = "c29tZXNhbHRzb21lc2FsdA";
        let out = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
        for params in ["m=4194304,t=1,p=1", "m=19456,t=4294967295,p=1", "m=19456,t=2,p=255", "m=524288,t=16,p=1"] {
            let phc = format!("$argon2id$v=19${params}${salt}${out}");
            assert_eq!(pw.verify("x", Some(&phc)), Verdict::Wrong, "{params}");
        }
        assert_eq!(pw.verify("x", Some("not a hash")), Verdict::Wrong);
        assert_eq!(pw.verify("x", Some("")), Verdict::Wrong);
        assert_eq!(pw.verify("x", Some(&"$".repeat(10_000))), Verdict::Wrong);
        // Some other scheme entirely.
        assert_eq!(
            pw.verify(
                "x",
                Some("$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E")
            ),
            Verdict::Wrong
        );
    }

    #[test]
    fn overlong_passwords_are_refused_without_hashing() {
        let pw = Hasher::new(quick()).unwrap();
        let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(matches!(pw.hash(&long), Err(Error::PasswordTooLong)));
        let phc = pw.hash(&long[..MAX_PASSWORD_BYTES]).unwrap();
        assert_eq!(pw.verify(&long, Some(&phc)), Verdict::Wrong);
        assert!(pw.verify(&long[..MAX_PASSWORD_BYTES], Some(&phc)).is_good());
    }

    #[test]
    fn unicode_passwords_are_byte_exact() {
        let pw = Hasher::new(quick()).unwrap();
        // "é" precomposed vs. decomposed are different passwords: doorward does
        // not normalise passwords (that is the app's choice to make, if any).
        let phc = pw.hash("caf\u{e9}").unwrap();
        assert!(pw.verify("caf\u{e9}", Some(&phc)).is_good());
        assert_eq!(pw.verify("cafe\u{301}", Some(&phc)), Verdict::Wrong);
    }

    #[test]
    fn invalid_policies_are_refused() {
        assert!(matches!(Hasher::new(HashPolicy { p: 4, ..quick() }), Err(Error::InvalidHashPolicy)));
        let pw = Hasher::new(quick()).unwrap();
        assert!(pw.replace(HashPolicy { m_kib: 1, ..quick() }).is_err());
        assert_eq!(pw.policy(), quick());
    }

    #[test]
    fn debug_shows_no_hash() {
        let pw = Hasher::new(quick()).unwrap();
        let s = format!("{pw:?}");
        assert!(!s.contains("argon2id$"), "{s}");
    }

    #[tokio::test]
    async fn turns_limit_concurrency() {
        use std::time::Duration;
        let one = std::sync::Arc::new(Hasher::new(HashPolicy::floor()).unwrap());
        let first = one.turn(Duration::from_millis(10)).await.expect("free");
        assert!(one.turn(Duration::from_millis(10)).await.is_none(), "one at a time");
        drop(first);
        assert!(one.turn(Duration::from_millis(10)).await.is_some());

        let two = std::sync::Arc::new(Hasher::new(quick()).unwrap());
        let a = two.turn(Duration::from_millis(10)).await.expect("free");
        let b = two.turn(Duration::from_millis(10)).await.expect("second");
        assert!(two.turn(Duration::from_millis(10)).await.is_none(), "two at a time");
        drop((a, b));

        let phc = two.hash_async(Zeroizing::new("pw".into()), Duration::from_secs(5)).await.unwrap();
        assert!(two.verify_async(Zeroizing::new("pw".into()), Some(phc), Duration::from_secs(5)).await.is_good());
        let _held = (two.turn(Duration::from_secs(1)).await, two.turn(Duration::from_secs(1)).await);
        assert_eq!(two.verify_async(Zeroizing::new("pw".into()), None, Duration::from_millis(20)).await, Verdict::Busy);
        assert!(matches!(
            two.hash_async(Zeroizing::new("pw".into()), Duration::from_millis(20)).await,
            Err(Error::Busy)
        ));
    }
}
