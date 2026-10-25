//! Usernames, tokens and configured addresses.
#![no_main]
use libfuzzer_sys::fuzz_target;
use doorward::__fuzz as f;

fuzz_target!(|s: &str| {
    let _ = f::username(s);
    let _ = f::hash_token(s);
    let _ = f::address(s);
});
