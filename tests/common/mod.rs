//! A pretend browser for the integration tests.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use doorward::password::HashPolicy;
use doorward::store::{MemoryStore, RememberedRecord, Store};
use doorward::{Address, Doorward, IpNet, ManualClock, NewUser, RequestInfo, SetCookie, Visit};
use http::{HeaderMap, HeaderValue, Method};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

pub const LAN: &str = "https://pc.lan:8040";
pub const PUBLIC: &str = "https://pingrail-admin.example.com";
pub const T0: i64 = 1_800_000_000_000;

pub struct Env {
    pub dw: Doorward,
    pub clock: ManualClock,
    pub store: Arc<MemoryStore>,
}

pub async fn env() -> Env {
    env_with(|b| b).await
}

pub async fn env_with(f: impl FnOnce(doorward::Builder) -> doorward::Builder) -> Env {
    let clock = ManualClock::new(T0);
    let store = Arc::new(MemoryStore::new());
    let b = Doorward::builder_shared(store.clone())
        .address(Address::new(LAN).unwrap().passkeys(true))
        .address(Address::new(PUBLIC).unwrap().via_proxy().passkeys(true).passwords(true))
        .trusted_proxies([IpNet::parse("127.0.0.1").unwrap()])
        .hash_policy(HashPolicy { concurrency: 2, ..HashPolicy::floor() })
        .clock(clock.clone())
        .app_name("test app");
    let dw = f(b).build().await.unwrap();
    Env { dw, clock, store }
}

impl Env {
    /// The stored record behind this browser's remembered-browser cookie.
    pub async fn remembered(&self, b: &Browser) -> Option<RememberedRecord> {
        use sha2::Digest;
        let token = b.jar.get("__Host-doorward-device")?;
        let hash: [u8; 32] = sha2::Sha256::digest(token.as_bytes()).into();
        self.store.remembered(&hash).await.unwrap()
    }

    pub async fn user(&self, name: &str, password: Option<&str>) -> doorward::User {
        self.dw
            .create_user(NewUser {
                username: name.into(),
                password: password.map(|p| p.to_string().into()),
                ..Default::default()
            })
            .await
            .unwrap()
    }
}

/// A browser with a cookie jar, at one origin, from one address.
#[derive(Clone)]
pub struct Browser {
    pub origin: String,
    pub ip: IpAddr,
    /// Come through cloudflared on 127.0.0.1, reporting `ip`.
    pub via_proxy: bool,
    pub jar: BTreeMap<String, String>,
    /// Send this Origin header on writes instead of our own.
    pub origin_header: Option<String>,
}

impl Browser {
    pub fn lan() -> Browser {
        Browser {
            origin: LAN.into(),
            ip: "192.168.1.20".parse().unwrap(),
            via_proxy: false,
            jar: BTreeMap::new(),
            origin_header: None,
        }
    }

    pub fn public(ip: &str) -> Browser {
        Browser {
            origin: PUBLIC.into(),
            ip: ip.parse().unwrap(),
            via_proxy: true,
            jar: BTreeMap::new(),
            origin_header: None,
        }
    }

    pub fn host(&self) -> String {
        self.origin.trim_start_matches("https://").to_string()
    }

    pub fn headers(&self, method: &Method) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_str(&self.host()).unwrap());
        if !self.jar.is_empty() {
            let c: Vec<String> = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
            h.insert("cookie", HeaderValue::from_str(&c.join("; ")).unwrap());
        }
        if method != Method::GET {
            let o = self.origin_header.clone().unwrap_or_else(|| self.origin.clone());
            h.insert("origin", HeaderValue::from_str(&o).unwrap());
        }
        h.insert("user-agent", HeaderValue::from_static("TestBrowser/1.0"));
        if self.via_proxy {
            h.insert("cf-connecting-ip", HeaderValue::from_str(&self.ip.to_string()).unwrap());
            h.insert("x-forwarded-for", HeaderValue::from_str(&self.ip.to_string()).unwrap());
            h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        }
        h
    }

    pub fn peer(&self) -> IpAddr {
        if self.via_proxy { "127.0.0.1".parse().unwrap() } else { self.ip }
    }

    pub fn visit(&self, dw: &Doorward, method: Method) -> Result<Visit, doorward::Error> {
        let headers = self.headers(&method);
        dw.visit(&RequestInfo { peer: self.peer(), method: &method, host: None, headers: &headers })
    }

    pub fn post(&self, dw: &Doorward) -> Visit {
        self.visit(dw, Method::POST).unwrap()
    }

    pub fn get(&self, dw: &Doorward) -> Visit {
        self.visit(dw, Method::GET).unwrap()
    }

    /// Store cookies as a browser would (Max-Age=0 deletes).
    pub fn take(&mut self, cookies: &[SetCookie]) {
        for c in cookies {
            let s = c.as_str();
            let (kv, _) = s.split_once(';').unwrap_or((s, ""));
            let (k, v) = kv.split_once('=').unwrap();
            if v.is_empty() || s.contains("Max-Age=0") {
                self.jar.remove(k);
            } else {
                self.jar.insert(k.to_string(), v.to_string());
            }
        }
    }

    pub fn has_session(&self) -> bool {
        self.jar.contains_key("__Host-doorward")
    }
}
