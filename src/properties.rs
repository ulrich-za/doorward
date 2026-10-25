//! Property tests: every parser that sees network input, fed arbitrary
//! input, never panics and only accepts what it should. (The fuzz targets in
//! `fuzz/` drive the same functions with coverage guidance.)

#![allow(clippy::unwrap_used)]

use http::{HeaderMap, HeaderValue};
use proptest::prelude::*;
use std::net::IpAddr;

use crate::address::Address;
use crate::limits::{Limiter, Limits, Who};
use crate::net::{self, IpNet, VisitorKey};
use crate::password::{HashPolicy, Hasher};
use crate::store::SessionRecord;
use crate::token;
use crate::username::{Username, lookup_key};

fn headers(pairs: &[(&'static str, String)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
        if let Ok(v) = HeaderValue::from_str(v) {
            m.append(*k, v);
        }
    }
    m
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn hosts_parse_safely(s in ".{0,80}") {
        if let Some(hp) = net::parse_host(&s) {
            prop_assert!(!hp.host.is_empty());
            if hp.host.starts_with('[') {
                prop_assert!(hp.host.ends_with(']'));
                prop_assert!(hp.host[1..hp.host.len() - 1].parse::<std::net::Ipv6Addr>().is_ok());
            } else {
                prop_assert!(net::valid_hostname(&hp.host));
                prop_assert_eq!(hp.host.to_ascii_lowercase(), hp.host.clone());
            }
        }
    }

    #[test]
    fn host_like_strings_round_trip(name in "[a-z][a-z0-9-]{0,10}(\\.[a-z][a-z0-9]{0,8}){0,3}", port in proptest::option::of(1u16..)) {
        let raw = match port { Some(p) => format!("{name}:{p}"), None => name.clone() };
        let hp = net::parse_host(&raw.to_uppercase());
        if name.ends_with('-') || name.contains("-.") {
            prop_assert!(hp.is_none());
        } else {
            let hp = hp.unwrap();
            prop_assert_eq!(hp.host, name);
            prop_assert_eq!(hp.port, port);
        }
    }

    #[test]
    fn cookies_parse_safely(a in ".{0,200}", b in ".{0,200}", name in "[A-Za-z_-]{1,20}") {
        let m = headers(&[("cookie", a), ("cookie", b)]);
        if let Some(v) = net::cookie(&m, &name) {
            prop_assert!(!v.is_empty() && v.len() <= 512);
            prop_assert!(v.bytes().all(|b| b.is_ascii_graphic()));
        }
    }

    #[test]
    fn client_addresses_come_only_from_trusted_proxies(
        cf in ".{0,60}", xff in ".{0,120}", peer in any::<[u8; 4]>(), trusted_bit in any::<bool>(),
    ) {
        let peer = IpAddr::from(peer);
        let trusted = if trusted_bit { vec![IpNet::parse(&peer.to_string()).unwrap()] } else { vec![] };
        let m = headers(&[("cf-connecting-ip", cf), ("x-forwarded-for", xff)]);
        let ip = net::client_ip(peer, &m, &trusted);
        if !trusted_bit {
            prop_assert_eq!(ip, peer);
        }
        let _ = VisitorKey::of(ip);
    }

    #[test]
    fn tokens_are_checked_strictly(s in ".{0,60}") {
        if token::hash_token(&s).is_some() {
            prop_assert_eq!(s.len(), token::TOKEN_CHARS);
            prop_assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        }
    }

    #[test]
    fn usernames_are_stable(s in "\\PC{0,80}") {
        if let Ok(u) = Username::parse(&s) {
            prop_assert!(u.as_str().chars().count() <= crate::username::MAX_USERNAME_CHARS);
            prop_assert_eq!(lookup_key(&s), Some(u.key().to_string()));
            let again = Username::parse(u.as_str()).unwrap();
            prop_assert_eq!(again.key(), u.key());
            prop_assert_eq!(again.skeleton(), u.skeleton());
        }
    }

    #[test]
    fn addresses_parse_safely(s in ".{0,80}") {
        if let Ok(a) = Address::new(&s) {
            prop_assert!(a.origin().starts_with("https://"));
            let again = Address::new(a.origin()).unwrap();
            prop_assert_eq!(again.origin(), a.origin());
        }
    }

    #[test]
    fn origin_checks_never_panic(o in ".{0,80}", site in ".{0,20}") {
        let m = headers(&[("origin", o), ("sec-fetch-site", site)]);
        let _ = crate::doorward::same_origin_for_tests(&m, "https://a.example");
    }

    #[test]
    fn session_expiry_never_overflows(c in any::<i64>(), l in any::<i64>(), idle in proptest::option::of(any::<i64>()), max in any::<i64>()) {
        let r = SessionRecord {
            id: uuid::Uuid::nil(), token_hash: [0; 32], user_id: uuid::Uuid::nil(), address: String::new(),
            created_ms: c, last_seen_ms: l, auth_ms: 0, idle_ms: idle, max_ms: max, persistent: false,
            method: String::new(), ip: None, user_agent: None,
        };
        let _ = r.expires_ms();
    }

    #[test]
    fn rate_limits_stay_sane(ops in proptest::collection::vec((0u8..4, 0u8..50, 0i64..10_000), 1..300)) {
        let l = Limiter::new(Limits { tracked_max: 100, ..Limits::default() });
        let mut now = 0i64;
        for (op, who, step) in ops {
            now += step;
            let w = if who % 5 == 0 { Who::Remembered([who; 32]) } else { Who::Visitor(VisitorKey::of(IpAddr::from([10, 0, 0, who]))) };
            match op {
                0 | 1 => {
                    if let Ok(d) = l.admit(w, now) {
                        prop_assert!(d <= std::time::Duration::from_secs(5));
                    }
                }
                2 => l.failed(w, now),
                _ => l.tidy(now),
            }
        }
    }
}

proptest! {
    // Hashing is slow, so fewer cases; most junk fails before any hashing.
    #![proptest_config(ProptestConfig { cases: 200, ..ProptestConfig::default() })]

    #[test]
    fn junk_hashes_never_verify(pw in ".{0,40}", phc in ".{0,120}") {
        let h = hasher();
        prop_assert!(!h.verify(&pw, Some(&phc)).is_good());
    }

    #[test]
    fn plausible_but_forged_hashes_never_verify(pw in "[a-z]{0,12}", m in 8u32..30_000, t in 1u32..4, salt in "[A-Za-z0-9+/]{11,30}", out in "[A-Za-z0-9+/]{43}") {
        let phc = format!("$argon2id$v=19$m={m},t={t},p=1${salt}${out}");
        prop_assert!(!hasher().verify(&pw, Some(&phc)).is_good());
    }
}

fn hasher() -> &'static Hasher {
    static H: std::sync::OnceLock<Hasher> = std::sync::OnceLock::new();
    H.get_or_init(|| Hasher::new(HashPolicy::floor()).unwrap())
}
