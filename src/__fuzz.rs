//! Internal parsers for the fuzz targets in `fuzz/` (feature `fuzzing`).
//! Not part of the API: it can change in any release.

#![allow(missing_docs)]

use http::{HeaderMap, HeaderName, HeaderValue};
use std::net::IpAddr;

/// Headers from fuzz input: lines of `name: value`.
pub fn headers(data: &[u8]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for line in data.split(|b| *b == b'\n') {
        let Some(i) = line.iter().position(|b| *b == b':') else { continue };
        if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(&line[..i]), HeaderValue::from_bytes(&line[i + 1..])) {
            m.append(k, v);
        }
    }
    m
}

pub fn parse_host(s: &str) -> bool {
    crate::net::parse_host(s).is_some()
}

pub fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    crate::net::cookie(h, name)
}

pub fn client_ip(peer: IpAddr, h: &HeaderMap) -> IpAddr {
    let trusted = [crate::net::IpNet::parse("127.0.0.0/8").unwrap_or_else(|_| unreachable!())];
    crate::net::client_ip(peer, h, &trusted)
}

pub fn same_origin(h: &HeaderMap) -> bool {
    crate::doorward::same_origin_for_tests(h, "https://a.example:8443")
}

pub fn hash_token(s: &str) -> bool {
    crate::token::hash_token(s).is_some()
}

pub fn username(s: &str) -> bool {
    crate::username::Username::parse(s).is_ok() | crate::username::lookup_key(s).is_some()
}

pub fn address(s: &str) -> bool {
    crate::address::Address::new(s).is_ok()
}
