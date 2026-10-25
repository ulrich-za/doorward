//! Host, cookie, forwarding and origin headers from the network.
#![no_main]
use libfuzzer_sys::fuzz_target;
use doorward::__fuzz as f;

fuzz_target!(|data: &[u8]| {
    let h = f::headers(data);
    let _ = f::cookie(&h, "__Host-doorward");
    let _ = f::client_ip("127.0.0.1".parse().unwrap(), &h);
    let _ = f::client_ip("203.0.113.1".parse().unwrap(), &h);
    let _ = f::same_origin(&h);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = f::parse_host(s);
    }
});
