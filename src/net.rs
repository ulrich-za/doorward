//! Who is asking, and where they sent the request: client addresses behind
//! trusted proxies, visitor keys for rate limits, Host headers and cookies.

use http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Error;

/// A network such as `127.0.0.1/32` or `2001:db8::/32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parse `addr/prefix`, or a single address (a /32 or /128).
    pub fn parse(s: &str) -> Result<IpNet, Error> {
        let bad = || Error::Config(format!("not a network address: {s:?}"));
        let (addr, prefix) = match s.trim().split_once('/') {
            Some((a, p)) => (a.parse::<IpAddr>().map_err(|_| bad())?, Some(p.parse::<u8>().map_err(|_| bad())?)),
            None => (s.trim().parse::<IpAddr>().map_err(|_| bad())?, None),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return Err(bad());
        }
        Ok(IpNet { addr: mask(addr, prefix), prefix })
    }

    /// Is `ip` in this network? IPv4-mapped IPv6 addresses count as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => mask(ip, self.prefix) == self.addr,
            _ => false,
        }
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & m))
        }
        IpAddr::V6(a) => {
            let m = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix as u32) };
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & m))
        }
    }
}

/// IPv4-mapped IPv6 (`::ffff:1.2.3.4`) as plain IPv4.
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

pub(crate) fn in_any(ip: IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

/// Did this request come through a trusted proxy? Only when the connection
/// is from one of `trusted` *and* it says whom it forwards for.
pub(crate) fn through_proxy(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> bool {
    in_any(peer, trusted) && (headers.contains_key("cf-connecting-ip") || headers.contains_key("x-forwarded-for"))
}

/// The visitor's address. From a trusted proxy, `CF-Connecting-IP` (which
/// Cloudflare always overwrites) is believed; otherwise the right-most
/// `X-Forwarded-For` entry that isn't itself a trusted proxy, since
/// everything left of it could have been written by the visitor. From anyone
/// else, the connection's own address.
pub(crate) fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = canonical(peer);
    if !in_any(peer, trusted) {
        return peer;
    }
    if let Some(ip) = single_header(headers, "cf-connecting-ip").and_then(|v| v.trim().parse::<IpAddr>().ok()) {
        return canonical(ip);
    }
    let mut entries: Vec<&str> = Vec::new();
    for v in headers.get_all("x-forwarded-for") {
        let Ok(v) = v.to_str() else { return peer };
        entries.extend(v.split(','));
    }
    for e in entries.iter().rev() {
        let Ok(ip) = e.trim().parse::<IpAddr>() else { return peer };
        let ip = canonical(ip);
        if !in_any(ip, trusted) {
            return ip;
        }
    }
    peer
}

/// One value of a header that must appear at most once.
pub(crate) fn single_header<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    let mut all = headers.get_all(name).iter();
    let v = all.next()?;
    if all.next().is_some() {
        return None;
    }
    v.to_str().ok()
}

/// The key a visitor's rate limits are kept under: an IPv4 address, or the
/// /64 an IPv6 address is in (one person usually controls a whole /64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum VisitorKey {
    V4(u32),
    V6(u64),
}

impl VisitorKey {
    pub(crate) fn of(ip: IpAddr) -> VisitorKey {
        match canonical(ip) {
            IpAddr::V4(a) => VisitorKey::V4(u32::from(a)),
            IpAddr::V6(a) => VisitorKey::V6((u128::from(a) >> 64) as u64),
        }
    }
}

/// A Host header (or HTTP/2 :authority), parsed: lowercase host without a
/// trailing dot, and the port when one was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostPort {
    pub host: String,
    pub port: Option<u16>,
}

pub(crate) fn parse_host(raw: &str) -> Option<HostPort> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 300 {
        return None;
    }
    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        h.parse::<Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?.parse::<u16>().ok()?),
        };
        (format!("[{}]", h.to_ascii_lowercase()), port)
    } else {
        let (h, port) = match raw.rsplit_once(':') {
            Some((h, p)) => (h, Some(p.parse::<u16>().ok()?)),
            None => (raw, None),
        };
        let h = h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase();
        if !valid_hostname(&h) {
            return None;
        }
        (h, port)
    };
    Some(HostPort { host, port })
}

/// A DNS name or IPv4 address made only of `a-z 0-9 - .`, with no empty
/// labels and no label starting or ending with a hyphen.
pub(crate) fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The value of cookie `name`. `None` when the cookie is absent, sent more
/// than once (an injected duplicate), or not plain printable ASCII.
pub(crate) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found: Option<&str> = None;
    for v in headers.get_all(http::header::COOKIE) {
        let Ok(v) = v.to_str() else { continue };
        for kv in v.split(';') {
            let Some((k, val)) = kv.trim().split_once('=') else { continue };
            if k == name {
                if found.is_some() {
                    return None;
                }
                found = Some(val);
            }
        }
    }
    let v = found?.trim_matches('"');
    (!v.is_empty() && v.len() <= 512 && v.bytes().all(|b| b.is_ascii_graphic())).then(|| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn h(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(*k, HeaderValue::from_static(v));
        }
        m
    }

    fn nets(s: &[&str]) -> Vec<IpNet> {
        s.iter().map(|n| IpNet::parse(n).unwrap()).collect()
    }

    #[test]
    fn networks() {
        let n = IpNet::parse("192.168.1.0/24").unwrap();
        assert!(n.contains("192.168.1.77".parse().unwrap()));
        assert!(!n.contains("192.168.2.1".parse().unwrap()));
        assert!(n.contains("::ffff:192.168.1.5".parse().unwrap()), "mapped IPv4");
        let one = IpNet::parse("127.0.0.1").unwrap();
        assert!(one.contains("127.0.0.1".parse().unwrap()));
        assert!(!one.contains("127.0.0.2".parse().unwrap()));
        let v6 = IpNet::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(IpNet::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        for bad in ["", "1.2.3.4/33", "::/129", "nope", "1.2.3.4/x"] {
            assert!(IpNet::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_ip_only_believes_trusted_proxies() {
        let trusted = nets(&["127.0.0.1"]);
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let stranger: IpAddr = "203.0.113.9".parse().unwrap();
        let fwd = h(&[("cf-connecting-ip", "198.51.100.7")]);
        assert_eq!(client_ip(local, &fwd, &trusted), "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(stranger, &fwd, &trusted), stranger, "stranger's headers ignored");
        assert!(through_proxy(local, &fwd, &trusted));
        assert!(!through_proxy(stranger, &fwd, &trusted));
        assert!(!through_proxy(local, &HeaderMap::new(), &trusted), "a direct local browser");
    }

    #[test]
    fn forwarded_for_is_read_from_the_right() {
        let trusted = nets(&["127.0.0.1", "10.0.0.0/8"]);
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        // The visitor wrote "1.1.1.1"; the proxy appended the real address.
        let spoof = h(&[("x-forwarded-for", "1.1.1.1, 198.51.100.7")]);
        assert_eq!(client_ip(local, &spoof, &trusted), "198.51.100.7".parse::<IpAddr>().unwrap());
        // Trusted hops on the right are skipped.
        let hops = h(&[("x-forwarded-for", "198.51.100.7, 10.1.2.3")]);
        assert_eq!(client_ip(local, &hops, &trusted), "198.51.100.7".parse::<IpAddr>().unwrap());
        // Split across two headers.
        let two = h(&[("x-forwarded-for", "1.1.1.1"), ("x-forwarded-for", "198.51.100.8")]);
        assert_eq!(client_ip(local, &two, &trusted), "198.51.100.8".parse::<IpAddr>().unwrap());
        // Garbage: fall back to the connection.
        let junk = h(&[("x-forwarded-for", "not-an-ip")]);
        assert_eq!(client_ip(local, &junk, &trusted), local);
        // A doubled CF-Connecting-IP isn't believed.
        let double = h(&[("cf-connecting-ip", "1.1.1.1"), ("cf-connecting-ip", "2.2.2.2")]);
        assert_eq!(client_ip(local, &double, &trusted), local);
    }

    #[test]
    fn visitor_keys_group_ipv6_by_64() {
        let a = VisitorKey::of("2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = VisitorKey::of("2001:db8:1:2:ffff::9".parse().unwrap());
        let c = VisitorKey::of("2001:db8:1:3::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(VisitorKey::of("::ffff:1.2.3.4".parse().unwrap()), VisitorKey::of("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn hosts() {
        assert_eq!(
            parse_host("Pc.Lan:8040"),
            Some(HostPort { host: "pc.lan".into(), port: Some(8040) })
        );
        assert_eq!(parse_host("example.com."), Some(HostPort { host: "example.com".into(), port: None }));
        assert_eq!(parse_host("[::1]:8443"), Some(HostPort { host: "[::1]".into(), port: Some(8443) }));
        assert_eq!(parse_host("192.168.1.5"), Some(HostPort { host: "192.168.1.5".into(), port: None }));
        for bad in [
            "",
            "a b",
            "evil.com/x",
            "user@host",
            "host:99999",
            "host:",
            "-a.com",
            "a..b",
            "[zz]",
            "[::1]x",
            "é.com",
            "h:1:2",
        ] {
            assert_eq!(parse_host(bad), None, "{bad}");
        }
    }

    #[test]
    fn cookies() {
        let m = h(&[("cookie", "a=1; __Host-s=abc_DEF-123; b=2")]);
        assert_eq!(cookie(&m, "__Host-s").as_deref(), Some("abc_DEF-123"));
        assert_eq!(cookie(&m, "missing"), None);
        // Duplicates (e.g. one injected by a sibling subdomain) are refused.
        let dup = h(&[("cookie", "s=one"), ("cookie", "s=two")]);
        assert_eq!(cookie(&dup, "s"), None);
        let dup2 = h(&[("cookie", "s=one; s=two")]);
        assert_eq!(cookie(&dup2, "s"), None);
        assert_eq!(cookie(&h(&[("cookie", "s=")]), "s"), None);
        assert_eq!(cookie(&h(&[("cookie", "s=\"q\"")]), "s").as_deref(), Some("q"));
    }
}
