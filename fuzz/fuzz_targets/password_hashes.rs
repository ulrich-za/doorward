//! Saved password hashes (PHC strings) read back from the store.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use doorward::password::{HashPolicy, Hasher, Verdict};

static H: OnceLock<Hasher> = OnceLock::new();

fuzz_target!(|data: (&str, &str)| {
    let h = H.get_or_init(|| Hasher::new(HashPolicy::floor()).unwrap());
    let (pw, phc) = data;
    assert_ne!(h.verify(pw, Some(phc)), Verdict::Good { rehash: false }, "a fuzzed hash verified");
});
