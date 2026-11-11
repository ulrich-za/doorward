//! Response times can't tell an unknown username from an account whose saved
//! hash has older, cheaper settings (after a retune, or imported). This runs
//! as a test binary of its own, so no other test competes for the CPU while
//! it times answers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use argon2::password_hash::PasswordHasher as _;
use argon2::{Algorithm, Argon2, Params, Version};
use doorward::Zeroizing;
use doorward::password::{HashPolicy, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn older_hashes_answer_no_sooner_than_unknown_names() {
    // The current settings cost more than the older saved hash: its check
    // is quicker, but its answer must not come sooner.
    let current = HashPolicy { m_kib: 32 * 1024, t: 4, concurrency: 2, ..HashPolicy::floor() };
    let h = Arc::new(Hasher::new(current).unwrap());
    let older = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19 * 1024, 2, 1, None).unwrap())
        .hash_password(b"pw")
        .unwrap()
        .to_string();
    let time = |phc: Option<String>| {
        let h = h.clone();
        async move {
            let t = Instant::now();
            let _ = h.verify_async(Zeroizing::new("wrong".into()), phc, Duration::from_secs(10)).await;
            t.elapsed().as_secs_f64()
        }
    };
    // Timed in pairs, and judged by the typical gap within a pair. Every
    // answer is held to a floor that steps up when the machine slows down;
    // the pair timed across such a step differs by the step, and comparing
    // the two medians instead would report that one pair as a leak whenever
    // the step falls mid-run. A real leak shows in every pair.
    let mut gaps = Vec::new();
    let mut unknown = Vec::new();
    for _ in 0..21 {
        let u = time(None).await;
        let o = time(Some(older.clone())).await;
        unknown.push(u);
        gaps.push(o - u);
    }
    gaps.sort_by(f64::total_cmp);
    unknown.sort_by(f64::total_cmp);
    let (gap, u) = (gaps[10], unknown[10]);
    // Answers end with a sleep, so the OS timer's granularity (about 15 ms
    // on Windows, well under 1 ms elsewhere) blurs them; allow for it.
    let tick = timer_granularity().await;
    let allowed = 0.04 * u + 2.0 * tick;
    assert!(
        gap.abs() <= allowed,
        "an older hash typically answers {gap:+.4} s from an unknown name ({u:.4} s); allowed {allowed:.4} s (timer granularity {tick:.4} s)"
    );
}

/// How much later than asked a short sleep wakes up here (the worst of five).
async fn timer_granularity() -> f64 {
    let mut worst = 0.0f64;
    for _ in 0..5 {
        let t = Instant::now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        worst = worst.max(t.elapsed().as_secs_f64() - 0.001);
    }
    worst.max(0.0)
}
