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
    let (mut unknown, mut old) = (Vec::new(), Vec::new());
    for _ in 0..21 {
        unknown.push(time(None).await);
        old.push(time(Some(older.clone())).await);
    }
    unknown.sort_by(f64::total_cmp);
    old.sort_by(f64::total_cmp);
    let (u, o) = (unknown[10], old[10]);
    assert!((u - o).abs() <= 0.04 * u, "median answer: unknown name {u:.4} s, older hash {o:.4} s");
}
