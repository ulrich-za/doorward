//! The addresses an app is reached on, and what each one allows.
//!
//! The app lists every address it answers on (set on the machine, never from
//! the web UI, so a stolen session can't add one of its own). doorward checks
//! every request against the list: a request to any other name is refused.
//! A browser ties each passkey to the name in its address bar, so every
//! address has its own passkeys.

use std::time::Duration;

use crate::error::Error;
use crate::net::{parse_host, valid_hostname};

/// How requests reach an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// Straight from the browser (a LAN name, or a public server with its
    /// own certificate). Requests forwarded by a trusted proxy never match.
    Direct,
    /// Through a trusted reverse proxy such as cloudflared. Only requests
    /// that came from one of the trusted proxies, forwarded over HTTPS, match;
    /// a LAN device that merely claims the name gets nothing.
    Proxy,
}

/// How long sessions last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLengths {
    /// Signed out after this long without a request (`None`: never idle out).
    pub idle: Option<Duration>,
    /// Signed out this long after signing in, whatever happens.
    pub max: Duration,
    /// Keep the cookie when the browser closes. When `false` the cookie is a
    /// browser-session cookie (it ends when the browser closes) and `max` is
    /// only the server-side limit.
    pub persistent: bool,
}

impl SessionLengths {
    /// Ends when the browser closes, and after 12 hours at most: for shared
    /// or borrowed computers. doorward's default when "keep me signed in"
    /// isn't ticked.
    pub const BROWSER: SessionLengths = SessionLengths { idle: None, max: hours(12), persistent: false };
    /// 8 hours idle, 30 days at most, kept across browser restarts: a working
    /// day without signing in again. doorward's default when "keep me signed
    /// in" is ticked.
    pub const REMEMBERED: SessionLengths = SessionLengths { idle: Some(hours(8)), max: days(30), persistent: true };

    /// A persistent session of `max`, idling out after `idle`.
    pub const fn new(idle: Option<Duration>, max: Duration, persistent: bool) -> SessionLengths {
        SessionLengths { idle, max, persistent }
    }

    fn check(&self) -> Result<(), Error> {
        let year = days(366);
        if self.max.is_zero() || self.max > year || self.idle.is_some_and(|i| i.is_zero() || i > self.max) {
            return Err(Error::Config(format!("session lengths out of range: {self:?}")));
        }
        Ok(())
    }
}

const fn hours(h: u64) -> Duration {
    Duration::from_secs(h * 3600)
}

const fn days(d: u64) -> Duration {
    Duration::from_secs(d * 86_400)
}

/// One address the app answers on, such as `https://pc.lan:8040`,
/// and what it allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    origin: String,
    host: String,
    port: Option<u16>,
    secure: bool,
    pub(crate) passwords: bool,
    pub(crate) passkeys: bool,
    pub(crate) via: Via,
    pub(crate) sessions: SessionLengths,
    pub(crate) remembered: Option<SessionLengths>,
}

impl Address {
    /// An address from its origin: `https://` and a host name or IP address,
    /// with a port when it isn't 443. No path, query or user name.
    ///
    /// Defaults: passwords on, passkeys off, reached directly, sessions of
    /// [`SessionLengths::BROWSER`], and [`SessionLengths::REMEMBERED`] when the
    /// user ticks "keep me signed in".
    pub fn new(origin: &str) -> Result<Address, Error> {
        Address::parse(origin, false)
    }

    /// `http://localhost` (or `127.0.0.1`, `[::1]`) for development, where
    /// browsers treat plain HTTP as secure. Never use it in production.
    pub fn localhost_for_development(origin: &str) -> Result<Address, Error> {
        Address::parse(origin, true)
    }

    fn parse(origin: &str, allow_http_localhost: bool) -> Result<Address, Error> {
        let bad = |why: &str| Error::Config(format!("address {origin:?}: {why}"));
        let origin = origin.trim();
        let (secure, rest) = if let Some(r) = origin.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = origin.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(bad("must start with https://"));
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#', '@', '\\']) {
            return Err(bad("must be just a scheme, host and port"));
        }
        let hp = parse_host(rest).ok_or_else(|| bad("host isn't valid"))?;
        if !secure {
            let local = matches!(hp.host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
            if !(allow_http_localhost && local) {
                return Err(bad("must use https:// (plain http only for localhost in development)"));
            }
        }
        let default_port = if secure { 443 } else { 80 };
        let port = hp.port.filter(|p| *p != default_port);
        let scheme = if secure { "https" } else { "http" };
        let origin = match port {
            Some(p) => format!("{scheme}://{}:{p}", hp.host),
            None => format!("{scheme}://{}", hp.host),
        };
        Ok(Address {
            origin,
            host: hp.host,
            port,
            secure,
            passwords: true,
            passkeys: false,
            via: Via::Direct,
            sessions: SessionLengths::BROWSER,
            remembered: Some(SessionLengths::REMEMBERED),
        })
    }

    /// Allow or refuse password sign-in here (default: allowed).
    pub fn passwords(mut self, on: bool) -> Address {
        self.passwords = on;
        self
    }

    /// Allow or refuse passkeys here (default: refused). Passkeys need a
    /// name, not an IP address, and a certificate the browser trusts.
    pub fn passkeys(mut self, on: bool) -> Address {
        self.passkeys = on;
        self
    }

    /// Requests reach this address through a trusted proxy (see [`Via::Proxy`]).
    pub fn via_proxy(mut self) -> Address {
        self.via = Via::Proxy;
        self
    }

    /// Session lengths when "keep me signed in" isn't ticked.
    pub fn sessions(mut self, lengths: SessionLengths) -> Address {
        self.sessions = lengths;
        self
    }

    /// Session lengths when "keep me signed in" is ticked, or `None` to not
    /// offer it here (a ticked box is then ignored).
    pub fn remembered(mut self, lengths: Option<SessionLengths>) -> Address {
        self.remembered = lengths;
        self
    }

    /// The origin, such as `https://pc.lan:8040`.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The host name or IP address.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Passwords allowed here.
    pub fn allows_passwords(&self) -> bool {
        self.passwords
    }

    /// Passkeys allowed here.
    pub fn allows_passkeys(&self) -> bool {
        self.passkeys
    }

    /// "Keep me signed in" offered here.
    pub fn offers_remember(&self) -> bool {
        self.remembered.is_some()
    }

    /// How requests reach this address.
    pub fn via(&self) -> Via {
        self.via
    }

    pub(crate) fn lengths(&self, remember: bool) -> SessionLengths {
        match (remember, self.remembered) {
            (true, Some(r)) => r,
            _ => self.sessions,
        }
    }

    pub(crate) fn check(&self) -> Result<(), Error> {
        self.sessions.check()?;
        if let Some(r) = &self.remembered {
            r.check()?;
        }
        if self.passkeys && (self.host.starts_with('[') || self.host.parse::<std::net::Ipv4Addr>().is_ok()) {
            return Err(Error::Config(format!("address {}: passkeys need a name, not an IP address", self.origin)));
        }
        if self.passkeys && !valid_hostname(&self.host) {
            return Err(Error::Config(format!("address {}: not a valid host name for passkeys", self.origin)));
        }
        if self.via == Via::Proxy && !self.secure {
            return Err(Error::Config(format!("address {}: a proxied address must be https", self.origin)));
        }
        if !self.passwords && !self.passkeys {
            return Err(Error::Config(format!("address {}: allows neither passwords nor passkeys", self.origin)));
        }
        Ok(())
    }

    /// Does a request with this Host header match?
    pub(crate) fn matches(&self, host: &str, port: Option<u16>) -> bool {
        let default_port = if self.secure { 443 } else { 80 };
        self.host == host && self.port.unwrap_or(default_port) == port.unwrap_or(default_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_normalised() {
        let a = Address::new("https://Pc.LAN:8040/").unwrap();
        assert_eq!(a.origin(), "https://pc.lan:8040");
        assert_eq!(Address::new("https://example.com:443").unwrap().origin(), "https://example.com");
        assert!(a.matches("pc.lan", Some(8040)));
        assert!(!a.matches("pc.lan", None));
        let b = Address::new("https://example.com").unwrap();
        assert!(b.matches("example.com", None) && b.matches("example.com", Some(443)));
        assert!(!b.matches("example.com", Some(8443)));
    }

    #[test]
    fn bad_origins_are_refused() {
        for o in [
            "pc.lan",
            "http://example.com",
            "ftp://example.com",
            "https://example.com/path",
            "https://user@example.com",
            "https://example.com?x",
            "https://",
            "https://exa mple.com",
            "https://example.com:0x1",
        ] {
            assert!(Address::new(o).is_err(), "{o}");
        }
        assert!(Address::localhost_for_development("http://localhost:3000").is_ok());
        assert!(Address::localhost_for_development("http://example.com").is_err());
    }

    #[test]
    fn settings_are_checked() {
        assert!(Address::new("https://192.168.1.5:8040").unwrap().passkeys(true).check().is_err());
        assert!(Address::new("https://[::1]:8040").unwrap().passkeys(true).check().is_err());
        assert!(Address::new("https://192.168.1.5:8040").unwrap().check().is_ok());
        assert!(Address::new("https://a.b").unwrap().passwords(false).check().is_err());
        assert!(Address::localhost_for_development("http://localhost").unwrap().via_proxy().check().is_err());
        let zero = SessionLengths::new(None, Duration::ZERO, false);
        assert!(Address::new("https://a.b").unwrap().sessions(zero).check().is_err());
        let idle_too_long = SessionLengths::new(Some(Duration::from_secs(100)), Duration::from_secs(10), true);
        assert!(Address::new("https://a.b").unwrap().sessions(idle_too_long).check().is_err());
    }

    #[test]
    fn remember_falls_back_when_not_offered() {
        let a = Address::new("https://a.b").unwrap().remembered(None);
        assert_eq!(a.lengths(true), SessionLengths::BROWSER);
        let b = Address::new("https://a.b").unwrap();
        assert_eq!(b.lengths(true), SessionLengths::REMEMBERED);
        assert_eq!(b.lengths(false), SessionLengths::BROWSER);
    }
}
