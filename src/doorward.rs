//! The doorkeeper: sign-in, sessions and accounts.

use http::{HeaderMap, Method};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::address::{Address, Via};
use crate::clock::{Clock, SystemClock, ms};
use crate::error::Error;
use crate::limits::{Limiter, Limits, Who};
use crate::model::{
    NewUser, PasswordRules, SecurityEvent, Session, SessionInfo, SetCookie, SignInMethod, SignedIn, User,
};
use crate::net::{self, IpNet, VisitorKey};
use crate::password::{HashPolicy, Hasher, MAX_PASSWORD_BYTES, Verdict};
use crate::store::{EventRecord, RememberedRecord, SessionRecord, Store, StoreError, UserRecord};
use crate::token;
use crate::username::{self, Username};

const POLICY_KEY: &str = "doorward.hash_policy";
/// Sessions are written back at most this often when only `last_seen` changes.
const TOUCH_EVERY_MS: i64 = 60_000;
const MAX_DISPLAY_NAME_CHARS: usize = 100;
const MAX_USER_AGENT_CHARS: usize = 200;

/// The request facts doorward needs, taken from whatever web framework the
/// app uses (the `axum` feature does this for axum).
#[derive(Clone, Copy, Debug)]
pub struct RequestInfo<'a> {
    /// The address of the connection's other end (a proxy, if there is one).
    pub peer: IpAddr,
    /// The request method.
    pub method: &'a Method,
    /// The host the request was sent to: the `Host` header, or for HTTP/2
    /// the `:authority`. `None` to read the `Host` header from `headers`.
    pub host: Option<&'a str>,
    /// The request headers.
    pub headers: &'a HeaderMap,
}

/// One request, as doorward sees it: which of the app's addresses it was
/// sent to, who sent it, and the cookies it carries. Made by
/// [`Doorward::visit`]; every sign-in operation takes one.
#[derive(Clone)]
pub struct Visit {
    address: usize,
    ip: IpAddr,
    key: VisitorKey,
    unsafe_method: bool,
    same_origin: bool,
    session_token: Option<Zeroizing<String>>,
    device_token: Option<Zeroizing<String>>,
    user_agent: Option<String>,
}

impl std::fmt::Debug for Visit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Visit")
            .field("address", &self.address)
            .field("ip", &self.ip)
            .field("unsafe_method", &self.unsafe_method)
            .field("same_origin", &self.same_origin)
            .field("has_session_cookie", &self.session_token.is_some())
            .field("has_device_cookie", &self.device_token.is_some())
            .finish_non_exhaustive()
    }
}

impl Visit {
    /// The visitor's address (behind a trusted proxy, the one it reports).
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Does the request carry a session cookie at all?
    pub fn has_session_cookie(&self) -> bool {
        self.session_token.is_some()
    }

    /// Is this a browser request from another site? (Only judged for methods
    /// other than GET, HEAD and OPTIONS.)
    pub fn is_cross_origin(&self) -> bool {
        self.unsafe_method && !self.same_origin
    }
}

/// What a sign-in page needs to know about the address it is shown on.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct AddressInfo {
    /// The origin.
    pub origin: String,
    /// Password sign-in is allowed here.
    pub passwords: bool,
    /// Passkeys are allowed here.
    pub passkeys: bool,
    /// "Keep me signed in" is offered here.
    pub remember: bool,
}

/// Whether the remembered-browser cookie outlives the browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DeviceCookie {
    /// Only when the session itself is kept (the user ticked "keep me signed
    /// in", or the address's sessions are persistent). Otherwise it lasts
    /// until the browser closes. This follows the rule that long-lived cookies
    /// need the user to ask to be remembered.
    #[default]
    WhenRemembered,
    /// Always, for [`Builder::remembered_browser_lifetime`]. Security cookies
    /// that detect repeated failed sign-ins are generally treated as strictly
    /// necessary under EU cookie rules; check what applies to you.
    Always,
}

/// Sets up a [`Doorward`].
pub struct Builder {
    store: Arc<dyn Store>,
    addresses: Vec<Address>,
    trusted_proxies: Vec<IpNet>,
    cookie_name: String,
    device_cookie_name: String,
    device_cookie: DeviceCookie,
    remembered_lifetime: Duration,
    rules: PasswordRules,
    recent: Duration,
    limits: Limits,
    hash_policy: Option<HashPolicy>,
    hash_wait: Duration,
    clock: Arc<dyn Clock>,
    event_retention: Duration,
    rp_name: String,
    max_passkeys_per_user: usize,
    refused_words: Vec<String>,
}

impl Builder {
    /// Add an address the app answers on.
    pub fn address(mut self, a: Address) -> Builder {
        self.addresses.push(a);
        self
    }

    /// Proxies whose forwarding headers are believed, such as cloudflared on
    /// this machine (`127.0.0.1`, `::1`). Needed for proxied addresses.
    pub fn trusted_proxies(mut self, nets: impl IntoIterator<Item = IpNet>) -> Builder {
        self.trusted_proxies.extend(nets);
        self
    }

    /// The session cookie's name (default `__Host-doorward`). It must start
    /// with `__Host-`, so browsers insist on HTTPS, `Path=/` and no `Domain`.
    pub fn cookie_name(mut self, name: &str) -> Builder {
        self.cookie_name = name.to_string();
        self
    }

    /// The remembered-browser cookie's name (default `__Host-doorward-device`).
    pub fn device_cookie_name(mut self, name: &str) -> Builder {
        self.device_cookie_name = name.to_string();
        self
    }

    /// When the remembered-browser cookie outlives the browser.
    pub fn device_cookie(mut self, d: DeviceCookie) -> Builder {
        self.device_cookie = d;
        self
    }

    /// How long a remembered browser stays remembered after its last use
    /// (default 180 days).
    pub fn remembered_browser_lifetime(mut self, d: Duration) -> Builder {
        self.remembered_lifetime = d;
        self
    }

    /// Rules for new passwords.
    pub fn password_rules(mut self, r: PasswordRules) -> Builder {
        self.rules = r;
        self
    }

    /// How recent a sign-in must be for sensitive actions (default 10 minutes).
    pub fn recent_sign_in(mut self, d: Duration) -> Builder {
        self.recent = d;
        self
    }

    /// Rate limits.
    pub fn limits(mut self, l: Limits) -> Builder {
        self.limits = l;
        self
    }

    /// Use this hash policy instead of loading or tuning one (it is not saved).
    pub fn hash_policy(mut self, p: HashPolicy) -> Builder {
        self.hash_policy = Some(p);
        self
    }

    /// How long a sign-in waits for a turn at password checking before
    /// answering "busy" (default 10 seconds).
    pub fn hash_wait(mut self, d: Duration) -> Builder {
        self.hash_wait = d;
        self
    }

    /// Where the time comes from (for tests).
    pub fn clock(mut self, c: impl Clock) -> Builder {
        self.clock = Arc::new(c);
        self
    }

    /// How long security log lines are kept (default 90 days).
    pub fn event_retention(mut self, d: Duration) -> Builder {
        self.event_retention = d;
        self
    }

    /// The app's name, shown by authenticators when making a passkey.
    pub fn app_name(mut self, name: &str) -> Builder {
        self.rp_name = name.to_string();
        self
    }

    /// Words new passwords may not contain, such as the app's and the
    /// organisation's names (compared in lowercase; words under 4 characters
    /// are ignored).
    pub fn refuse_password_words<I, S>(mut self, words: I) -> Builder
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.refused_words
            .extend(words.into_iter().map(|w| w.as_ref().trim().to_lowercase()).filter(|w| w.chars().count() >= 4));
        self
    }

    /// Most passkeys one user may have (default 20).
    pub fn max_passkeys_per_user(mut self, n: usize) -> Builder {
        self.max_passkeys_per_user = n;
        self
    }

    /// Check the settings, upgrade the store, and load (or, on first start,
    /// time) the password hash policy. Tuning takes a second or two.
    pub async fn build(self) -> Result<Doorward, Error> {
        if self.addresses.is_empty() {
            return Err(Error::Config("no addresses".into()));
        }
        for (i, a) in self.addresses.iter().enumerate() {
            a.check()?;
            if self.addresses[..i].iter().any(|b| b.origin() == a.origin()) {
                return Err(Error::Config(format!("address {} listed twice", a.origin())));
            }
        }
        if self.addresses.iter().any(|a| a.via() == Via::Proxy) && self.trusted_proxies.is_empty() {
            return Err(Error::Config("a proxied address needs trusted proxies".into()));
        }
        for name in [&self.cookie_name, &self.device_cookie_name] {
            let ok = name.starts_with("__Host-")
                && name.len() <= 64
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
            if !ok {
                return Err(Error::Config(format!("cookie name {name:?} must start with __Host- and be plain")));
            }
        }
        if self.cookie_name == self.device_cookie_name {
            return Err(Error::Config("the two cookie names must differ".into()));
        }
        if self.rules.min_chars == 0
            || self.rules.max_chars < self.rules.min_chars
            || self.rules.max_chars > MAX_PASSWORD_BYTES
        {
            return Err(Error::Config(format!("password rules out of range: {:?}", self.rules)));
        }
        if self.recent < Duration::from_secs(60) || self.recent > Duration::from_secs(3600) {
            return Err(Error::Config("the recent sign-in window must be 1–60 minutes".into()));
        }
        if self.remembered_lifetime < Duration::from_secs(86_400)
            || self.remembered_lifetime > Duration::from_secs(400 * 86_400)
        {
            return Err(Error::Config("the remembered-browser lifetime must be 1–400 days".into()));
        }
        if self.rp_name.trim().is_empty() || self.rp_name.chars().count() > 64 {
            return Err(Error::Config("the app name must be 1–64 characters".into()));
        }
        if !(1..=100).contains(&self.max_passkeys_per_user) {
            return Err(Error::Config("passkeys per user must be 1–100".into()));
        }
        self.limits.check()?;
        self.store.migrate().await?;

        let policy = match self.hash_policy {
            Some(p) if p.is_valid() => p,
            Some(_) => return Err(Error::InvalidHashPolicy),
            None => {
                let saved = self.store.meta_get(POLICY_KEY).await?;
                let (p, changed) =
                    tokio::task::spawn_blocking(move || HashPolicy::load_or_tune(saved.as_deref(), false))
                        .await
                        .map_err(|_| Error::Hashing)??;
                if changed {
                    self.store.meta_set(POLICY_KEY, &p.to_json()).await?;
                }
                p
            }
        };
        tracing::info!(target: "doorward", "password hashing: {}", policy.describe());
        let hasher =
            Arc::new(tokio::task::spawn_blocking(move || Hasher::new(policy)).await.map_err(|_| Error::Hashing)??);

        #[cfg(feature = "passkeys")]
        let passkeys = crate::passkey::Passkeys::new(&self.addresses, &self.rp_name)?;

        Ok(Doorward(Arc::new(Inner {
            store: self.store,
            hasher,
            clock: self.clock,
            addresses: self.addresses,
            trusted: self.trusted_proxies,
            cookie: self.cookie_name,
            device_cookie_name: self.device_cookie_name,
            device_cookie: self.device_cookie,
            remembered_lifetime: self.remembered_lifetime,
            rules: self.rules,
            recent: self.recent,
            limiter: Limiter::new(self.limits),
            visitor_gate: tokio::sync::Semaphore::new(1),
            hash_wait: self.hash_wait,
            event_retention: self.event_retention,
            max_passkeys: self.max_passkeys_per_user,
            refused_words: self.refused_words,
            #[cfg(feature = "passkeys")]
            passkeys,
        })))
    }
}

pub(crate) struct Inner {
    pub(crate) store: Arc<dyn Store>,
    hasher: Arc<Hasher>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) addresses: Vec<Address>,
    trusted: Vec<IpNet>,
    cookie: String,
    device_cookie_name: String,
    device_cookie: DeviceCookie,
    remembered_lifetime: Duration,
    rules: PasswordRules,
    recent: Duration,
    pub(crate) limiter: Limiter,
    /// Visitors without a remembered browser check one password at a time,
    /// so of the one or two checks the machine allows, room is left for
    /// remembered browsers even during a flood of guesses.
    visitor_gate: tokio::sync::Semaphore,
    hash_wait: Duration,
    event_retention: Duration,
    #[cfg_attr(not(feature = "passkeys"), allow(dead_code))]
    pub(crate) max_passkeys: usize,
    refused_words: Vec<String>,
    #[cfg(feature = "passkeys")]
    pub(crate) passkeys: crate::passkey::Passkeys,
}

/// The doorkeeper. Cheap to clone; share one between all requests.
#[derive(Clone)]
pub struct Doorward(pub(crate) Arc<Inner>);

impl std::fmt::Debug for Doorward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Doorward")
            .field("addresses", &self.0.addresses.iter().map(|a| a.origin()).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Clean a display name: no control characters, trimmed, at most 100 characters.
fn clean_display_name(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control() && !is_bidi_control(*c)).collect();
    s.trim().chars().take(MAX_DISPLAY_NAME_CHARS).collect()
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Clean a passkey label the same way, at most 40 characters.
#[cfg_attr(not(feature = "passkeys"), allow(dead_code))]
pub(crate) fn clean_label(s: &str, default: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control() && !is_bidi_control(*c)).collect();
    let s: String = s.trim().chars().take(40).collect();
    if s.is_empty() { default.to_string() } else { s }
}

impl Doorward {
    /// Start setting up, with the store to keep everything in.
    pub fn builder(store: impl Store) -> Builder {
        Doorward::builder_shared(Arc::new(store))
    }

    /// [`Doorward::builder`] with a store that is already shared.
    pub fn builder_shared(store: Arc<dyn Store>) -> Builder {
        Builder {
            store,
            addresses: Vec::new(),
            trusted_proxies: Vec::new(),
            cookie_name: "__Host-doorward".into(),
            device_cookie_name: "__Host-doorward-device".into(),
            device_cookie: DeviceCookie::default(),
            remembered_lifetime: Duration::from_secs(180 * 86_400),
            rules: PasswordRules::default(),
            recent: Duration::from_secs(600),
            limits: Limits::default(),
            hash_policy: None,
            hash_wait: Duration::from_secs(10),
            clock: Arc::new(SystemClock),
            event_retention: Duration::from_secs(90 * 86_400),
            rp_name: "doorward".into(),
            max_passkeys_per_user: 20,
            refused_words: Vec::new(),
        }
    }

    pub(crate) fn now(&self) -> i64 {
        self.0.clock.now_ms()
    }

    /// The store, for the app's own queries.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.0.store
    }

    /// The password hasher in force.
    pub fn hasher(&self) -> &Arc<Hasher> {
        &self.0.hasher
    }

    /// The session cookie's name.
    pub fn cookie_name(&self) -> &str {
        &self.0.cookie
    }

    /// The addresses the app answers on.
    pub fn addresses(&self) -> &[Address] {
        &self.0.addresses
    }

    pub(crate) fn address_of(&self, v: &Visit) -> &Address {
        &self.0.addresses[v.address]
    }

    // ----- requests -------------------------------------------------------------

    /// Work out which address a request was sent to, who sent it and what
    /// cookies it carries. [`Error::AddressNotAllowed`] when the host isn't on
    /// the app's list, or claims a proxied address without coming through a
    /// trusted proxy (or a direct one while coming through it).
    pub fn visit(&self, req: &RequestInfo<'_>) -> Result<Visit, Error> {
        let inner = &self.0;
        let host_raw = match req.host {
            Some(h) => Some(h),
            None => net::single_header(req.headers, "host"),
        };
        let hp = host_raw.and_then(net::parse_host).ok_or(Error::AddressNotAllowed)?;
        let through = net::through_proxy(req.peer, req.headers, &inner.trusted);
        let idx = inner
            .addresses
            .iter()
            .position(|a| {
                a.matches(&hp.host, hp.port)
                    && match a.via() {
                        Via::Direct => !through,
                        Via::Proxy => {
                            through
                                && net::single_header(req.headers, "x-forwarded-proto")
                                    .is_some_and(|p| p.trim().eq_ignore_ascii_case("https"))
                        }
                    }
            })
            .ok_or(Error::AddressNotAllowed)?;
        let address = &inner.addresses[idx];
        let ip = net::client_ip(req.peer, req.headers, &inner.trusted);
        let unsafe_method = !matches!(*req.method, Method::GET | Method::HEAD | Method::OPTIONS);
        let same_origin = same_origin(req.headers, address.origin());
        let user_agent = req
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|ua| ua.chars().filter(|c| !c.is_control()).take(MAX_USER_AGENT_CHARS).collect::<String>());
        Ok(Visit {
            address: idx,
            ip,
            key: VisitorKey::of(ip),
            unsafe_method,
            same_origin,
            session_token: net::cookie(req.headers, &inner.cookie).map(Zeroizing::new),
            device_token: net::cookie(req.headers, &inner.device_cookie_name).map(Zeroizing::new),
            user_agent,
        })
    }

    /// What the sign-in page at this address may offer.
    pub fn address_info(&self, v: &Visit) -> AddressInfo {
        let a = self.address_of(v);
        AddressInfo {
            origin: a.origin().to_string(),
            passwords: a.allows_passwords(),
            passkeys: a.allows_passkeys(),
            remember: a.offers_remember(),
        }
    }

    fn refuse_cross_origin(&self, v: &Visit) -> Result<(), Error> {
        if v.is_cross_origin() {
            tracing::warn!(target: "doorward::security", ip = %v.ip, address = self.address_of(v).origin(), "cross-origin request refused");
            return Err(Error::CrossOrigin);
        }
        Ok(())
    }

    /// The session this request belongs to, if any. Expired sessions, ones
    /// made on another address, and ones whose user is disabled don't count.
    /// For methods other than GET, HEAD and OPTIONS, a browser request from
    /// another site is refused ([`Error::CrossOrigin`]).
    pub async fn authenticate(&self, v: &Visit) -> Result<Option<Session>, Error> {
        Ok(self.authenticate_record(v).await?.map(|(s, _)| s))
    }

    /// [`Doorward::authenticate`], refusing with [`Error::NotSignedIn`] when
    /// there is no session.
    pub async fn require_session(&self, v: &Visit) -> Result<Session, Error> {
        self.authenticate(v).await?.ok_or(Error::NotSignedIn)
    }

    pub(crate) async fn authenticate_record(&self, v: &Visit) -> Result<Option<(Session, SessionRecord)>, Error> {
        let Some(token) = v.session_token.as_deref() else { return Ok(None) };
        self.refuse_cross_origin(v)?;
        let Some(hash) = token::hash_token(token) else { return Ok(None) };
        let store = &self.0.store;
        let Some(rec) = store.session_by_token(&hash).await? else { return Ok(None) };
        let now = self.now();
        if rec.address != self.address_of(v).origin() {
            // A cookie can't normally travel to another origin; if one does,
            // it is not accepted here (and the session stays valid at home).
            tracing::warn!(target: "doorward::security", ip = %v.ip, "a session cookie was presented on another address");
            return Ok(None);
        }
        if rec.expires_ms() <= now {
            store.delete_session(rec.id).await?;
            return Ok(None);
        }
        let Some(user) = store.user(rec.user_id).await? else {
            store.delete_session(rec.id).await?;
            return Ok(None);
        };
        if !user.active {
            store.delete_session(rec.id).await?;
            return Ok(None);
        }
        let ip = v.ip.to_string();
        let mut rec = rec;
        if now - rec.last_seen_ms >= TOUCH_EVERY_MS || rec.ip.as_deref() != Some(ip.as_str()) {
            store.touch_session(rec.id, now, Some(&ip)).await?;
            rec.last_seen_ms = now;
            rec.ip = Some(ip);
        }
        Ok(Some((Session::from_parts(&rec, user.into()), rec)))
    }

    // ----- signing in -------------------------------------------------------------

    /// The remembered browser this request carries, if valid.
    async fn remembered(&self, v: &Visit) -> Result<Option<RememberedRecord>, Error> {
        let Some(hash) = v.device_token.as_deref().and_then(|t| token::hash_token(t)) else { return Ok(None) };
        let rec = self.0.store.remembered(&hash).await?;
        Ok(rec.filter(|r| r.expires_ms > self.now()))
    }

    /// Whose budget this attempt counts against: the remembered browser when
    /// it belongs to `user` (or to anyone, when the user isn't known yet).
    pub(crate) async fn who(&self, v: &Visit, user: Option<Uuid>) -> Result<(Who, Option<RememberedRecord>), Error> {
        let device = self.remembered(v).await?;
        let who = match &device {
            Some(d) if user.is_none_or(|u| u == d.user_id) => Who::Remembered(d.token_hash),
            _ => Who::Visitor(v.key),
        };
        Ok((who, device))
    }

    /// Check a password, after a turn at the visitor gate when the attempt
    /// isn't from a remembered browser.
    async fn check_password(&self, who: Who, password: &str, phc: Option<String>) -> Verdict {
        if password.len() > MAX_PASSWORD_BYTES {
            return Verdict::Wrong;
        }
        let _visitor_turn = match who {
            Who::Visitor(_) => match tokio::time::timeout(self.0.hash_wait, self.0.visitor_gate.acquire()).await {
                Ok(Ok(permit)) => Some(permit),
                _ => return Verdict::Busy,
            },
            Who::Remembered(_) => None,
        };
        self.0.hasher.verify_async(Zeroizing::new(password.to_string()), phc, self.0.hash_wait).await
    }

    pub(crate) async fn admit(&self, who: Who) -> Result<(), Error> {
        let delay = self.0.limiter.admit(who, self.now())?;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        Ok(())
    }

    /// Sign in with a username and password. `remember` is the "keep me
    /// signed in" box (ignored where the address doesn't offer it).
    ///
    /// Wrong passwords and unknown usernames give the same error and take
    /// the same time.
    pub async fn sign_in_password(
        &self,
        v: &Visit,
        username: &str,
        password: &str,
        remember: bool,
    ) -> Result<SignedIn, Error> {
        self.refuse_cross_origin(v)?;
        let address = self.address_of(v);
        if !address.allows_passwords() {
            return Err(Error::PasswordsDisabledHere);
        }
        let store = &self.0.store;
        let user = match username::lookup_key(username) {
            Some(k) => store.user_by_key(&k).await?,
            None => None,
        };
        let (who, device) = self.who(v, user.as_ref().map(|u| u.id)).await?;
        self.admit(who).await?;

        // Look a hash up even for an unknown user, so both take the same steps.
        let phc = store.password(user.as_ref().map_or(Uuid::nil(), |u| u.id)).await?;
        let phc = if user.is_some() { phc } else { None };
        let verdict = self.check_password(who, password, phc.clone()).await;
        match (verdict, user, phc) {
            (Verdict::Busy, _, _) => Err(Error::Busy),
            (Verdict::Good { rehash }, Some(user), Some(phc)) => {
                if !user.active {
                    self.event(Some(user.id), "sign_in_refused", Some(v), Some(r#"{"reason":"disabled"}"#)).await;
                    return Err(Error::AccountDisabled);
                }
                if rehash {
                    match self.0.hasher.hash_async(Zeroizing::new(password.to_string()), self.0.hash_wait).await {
                        Ok(new) => {
                            if let Err(e) = store.replace_password(user.id, &phc, &new, self.now()).await {
                                tracing::warn!(target: "doorward", "saving a rehashed password failed: {e}");
                            }
                        }
                        Err(e) => tracing::warn!(target: "doorward", "rehashing a password failed: {e}"),
                    }
                }
                self.start_session(v, user, SignInMethod::Password, remember, device).await
            }
            (_, user, _) => {
                self.0.limiter.failed(who, self.now());
                self.event(user.map(|u| u.id), "sign_in_failed", Some(v), Some(r#"{"method":"password"}"#)).await;
                Err(Error::InvalidCredentials)
            }
        }
    }

    /// Begin a session for `user` (already proven) and make its cookies.
    pub(crate) async fn start_session(
        &self,
        v: &Visit,
        user: UserRecord,
        method: SignInMethod,
        remember: bool,
        device: Option<RememberedRecord>,
    ) -> Result<SignedIn, Error> {
        let inner = &self.0;
        let address = self.address_of(v);
        let lengths = address.lengths(remember);
        let now = self.now();
        let (token, hash) = token::new_token()?;
        let rec = SessionRecord {
            id: token::random_uuid()?,
            token_hash: hash,
            user_id: user.id,
            address: address.origin().to_string(),
            created_ms: now,
            last_seen_ms: now,
            auth_ms: now,
            idle_ms: lengths.idle.map(ms),
            max_ms: ms(lengths.max),
            persistent: lengths.persistent,
            method: method.as_str().to_string(),
            ip: Some(v.ip.to_string()),
            user_agent: v.user_agent.clone(),
        };
        // A new sign-in always gets a new cookie; the one this browser had
        // (if any) ends, so a planted cookie can't ride along.
        if let Some(old) = v.session_token.as_deref().and_then(|t| token::hash_token(t))
            && let Some(old) = inner.store.session_by_token(&old).await?
        {
            inner.store.delete_session(old.id).await?;
        }
        inner.store.insert_session(&rec).await?;
        let mut cookies = vec![SetCookie::set(
            &inner.cookie,
            &token,
            lengths.persistent.then(|| lengths.max.as_secs().min(i64::MAX as u64) as i64),
        )];
        cookies.push(self.remember_browser(&user, device, lengths.persistent).await?);
        let detail = format!(r#"{{"method":"{}"}}"#, method.as_str());
        self.event(Some(user.id), "sign_in", Some(v), Some(&detail)).await;
        Ok(SignedIn { session: Session::from_parts(&rec, user.into()), cookies })
    }

    /// Issue or refresh the remembered-browser cookie for `user`.
    async fn remember_browser(
        &self,
        user: &UserRecord,
        device: Option<RememberedRecord>,
        persistent_session: bool,
    ) -> Result<SetCookie, Error> {
        let inner = &self.0;
        let now = self.now();
        let lifetime = ms(inner.remembered_lifetime);
        let persistent = persistent_session || inner.device_cookie == DeviceCookie::Always;
        let max_age = persistent.then_some(lifetime / 1000);
        // Each sign-in gets a fresh value, so a copied device cookie stops
        // working once the real browser signs in again.
        if let Some(d) = device {
            inner.store.delete_remembered(&d.token_hash).await?;
        }
        let (t, h) = token::new_token()?;
        inner
            .store
            .insert_remembered(&RememberedRecord {
                token_hash: h,
                user_id: user.id,
                created_ms: now,
                last_used_ms: now,
                expires_ms: now.saturating_add(lifetime),
            })
            .await?;
        Ok(SetCookie::set(&inner.device_cookie_name, &t, max_age))
    }

    /// End this request's session. Returns the cookie to clear it.
    pub async fn sign_out(&self, v: &Visit) -> Result<SetCookie, Error> {
        if let Some((s, rec)) = self.authenticate_record(v).await? {
            self.0.store.delete_session(rec.id).await?;
            self.event(Some(s.user.id), "sign_out", Some(v), None).await;
        }
        Ok(SetCookie::clear(&self.0.cookie))
    }

    /// The cookie that clears the session cookie (for example after
    /// [`Error::NotSignedIn`] on a request that carried a stale one).
    pub fn clear_session_cookie(&self) -> SetCookie {
        SetCookie::clear(&self.0.cookie)
    }

    // ----- recent sign-in (step-up) -------------------------------------------------

    /// Has the user proved who they are within the recent window?
    pub fn is_recent(&self, s: &Session) -> bool {
        self.now() - s.auth_ms < ms(self.0.recent)
    }

    /// How long until the session is no longer recent.
    pub fn recent_left(&self, s: &Session) -> Duration {
        let left = ms(self.0.recent) - (self.now() - s.auth_ms);
        Duration::from_millis(left.max(0) as u64)
    }

    /// Refuse with [`Error::NeedsRecentSignIn`] unless the user proved who
    /// they are within the recent window. Use it before sensitive actions,
    /// even on a trusted device.
    pub fn require_recent(&self, s: &Session) -> Result<(), Error> {
        if self.is_recent(s) { Ok(()) } else { Err(Error::NeedsRecentSignIn) }
    }

    /// Confirm it's still the user by asking for their password again. On
    /// success the session counts as recent and gets a new cookie (send the
    /// returned cookies), so a copy of the old one stops working.
    pub async fn confirm_password(&self, v: &Visit, password: &str) -> Result<SignedIn, Error> {
        self.refuse_cross_origin(v)?;
        let (session, rec) = self.authenticate_record(v).await?.ok_or(Error::NotSignedIn)?;
        if !self.address_of(v).allows_passwords() {
            return Err(Error::PasswordsDisabledHere);
        }
        let (who, _) = self.who(v, Some(session.user.id)).await?;
        self.admit(who).await?;
        let phc = self.0.store.password(session.user.id).await?;
        let verdict = self.check_password(who, password, phc).await;
        match verdict {
            Verdict::Busy => Err(Error::Busy),
            Verdict::Good { .. } => self.mark_recent(v, session, &rec, "password").await,
            Verdict::Wrong => {
                self.0.limiter.failed(who, self.now());
                self.event(Some(session.user.id), "confirm_failed", Some(v), Some(r#"{"method":"password"}"#)).await;
                Err(Error::InvalidCredentials)
            }
        }
    }

    /// The user proved who they are again: a new cookie for the same session
    /// (the old value stops working), and the session counts as recent.
    pub(crate) async fn mark_recent(
        &self,
        v: &Visit,
        mut session: Session,
        rec: &SessionRecord,
        how: &str,
    ) -> Result<SignedIn, Error> {
        let now = self.now();
        let (token, hash) = token::new_token()?;
        if !self.0.store.reauth_session(rec.id, &hash, now).await? {
            return Err(Error::NotSignedIn);
        }
        session.auth_ms = now;
        let max_age = rec.persistent.then(|| (rec.created_ms.saturating_add(rec.max_ms) - now) / 1000);
        let cookie = SetCookie::set(&self.0.cookie, &token, max_age);
        self.event(Some(session.user.id), "confirmed", Some(v), Some(&format!(r#"{{"method":"{how}"}}"#))).await;
        Ok(SignedIn { session, cookies: vec![cookie] })
    }

    // ----- the user's own account ------------------------------------------------

    /// Check a new password against the rules: its length, the most common
    /// passwords, the user's own name and the app's words.
    pub fn check_new_password(&self, username: &str, password: &str) -> Result<(), Error> {
        let n = password.chars().count();
        if password.len() > MAX_PASSWORD_BYTES || n > self.0.rules.max_chars {
            return Err(Error::PasswordTooLong);
        }
        if n < self.0.rules.min_chars {
            return Err(Error::PasswordTooShort);
        }
        let lower = password.to_lowercase();
        if self.0.rules.refuse_common && crate::common::is_common(&lower) {
            return Err(Error::PasswordTooCommon);
        }
        let name = username.to_lowercase();
        if name.chars().count() >= 4 && lower.contains(&name) {
            return Err(Error::PasswordTooCommon);
        }
        if self.0.refused_words.iter().any(|w| lower.contains(w.as_str())) {
            return Err(Error::PasswordTooCommon);
        }
        Ok(())
    }

    async fn hash_new(&self, username: &str, password: &str) -> Result<String, Error> {
        self.check_new_password(username, password)?;
        self.0.hasher.hash_async(Zeroizing::new(password.to_string()), self.0.hash_wait).await
    }

    /// Change the signed-in user's own password. A user who has a password
    /// must give it (`current`); a user without one (passkeys only) needs a
    /// recent sign-in instead. Every other session of theirs ends; this one
    /// gets a new cookie (send the returned cookies).
    pub async fn change_password(
        &self,
        v: &Visit,
        current: Option<&str>,
        new_password: &str,
    ) -> Result<SignedIn, Error> {
        self.refuse_cross_origin(v)?;
        let (session, rec) = self.authenticate_record(v).await?.ok_or(Error::NotSignedIn)?;
        let store = &self.0.store;
        // Check the new one first: a refused new password costs no guess at the old one.
        self.check_new_password(&session.user.username, new_password)?;
        match store.password(session.user.id).await? {
            Some(old) => {
                let (who, _) = self.who(v, Some(session.user.id)).await?;
                self.admit(who).await?;
                match self.check_password(who, current.unwrap_or(""), Some(old)).await {
                    Verdict::Good { .. } => {}
                    Verdict::Busy => return Err(Error::Busy),
                    Verdict::Wrong => {
                        self.0.limiter.failed(who, self.now());
                        self.event(Some(session.user.id), "password_change_failed", Some(v), None).await;
                        return Err(Error::InvalidCredentials);
                    }
                }
            }
            None => self.require_recent(&session)?,
        }
        let phc = self.hash_new(&session.user.username, new_password).await?;
        store.set_password(session.user.id, &phc, self.now()).await?;
        let ended = store.delete_sessions_for_user(session.user.id, Some(rec.id)).await?;
        self.event(
            Some(session.user.id),
            "password_changed",
            Some(v),
            Some(&format!(r#"{{"sessions_ended":{ended}}}"#)),
        )
        .await;
        self.mark_recent(v, session, &rec, "password").await
    }

    /// The signed-in user's sessions, newest first, marking this one.
    pub async fn sessions(&self, s: &Session) -> Result<Vec<SessionInfo>, Error> {
        let now = self.now();
        Ok(self
            .0
            .store
            .sessions_for_user(s.user.id)
            .await?
            .iter()
            .filter(|r| r.expires_ms() > now)
            .map(|r| SessionInfo::from_record(r, s.id))
            .collect())
    }

    /// End one of the signed-in user's sessions (it may be this one; then
    /// clear the cookie too). Ending another session needs a recent sign-in.
    /// [`Error::NotFound`] when it isn't theirs.
    pub async fn end_session(&self, v: &Visit, s: &Session, id: Uuid) -> Result<(), Error> {
        self.refuse_cross_origin(v)?;
        if id != s.id {
            self.require_recent(s)?;
        }
        let mine = self.0.store.sessions_for_user(s.user.id).await?.iter().any(|r| r.id == id);
        if !mine || !self.0.store.delete_session(id).await? {
            return Err(Error::NotFound);
        }
        self.event(Some(s.user.id), "session_ended", Some(v), None).await;
        Ok(())
    }

    /// End every other session of the signed-in user ("sign out everywhere
    /// else"). Needs a recent sign-in. Returns how many ended.
    pub async fn end_other_sessions(&self, v: &Visit, s: &Session) -> Result<u64, Error> {
        self.refuse_cross_origin(v)?;
        self.require_recent(s)?;
        let n = self.0.store.delete_sessions_for_user(s.user.id, Some(s.id)).await?;
        self.event(Some(s.user.id), "sessions_ended", Some(v), Some(&format!(r#"{{"count":{n}}}"#))).await;
        Ok(n)
    }

    /// The signed-in user's recent security log, newest first (at most 100).
    pub async fn events(&self, s: &Session, limit: u32) -> Result<Vec<SecurityEvent>, Error> {
        Ok(self.0.store.events_for_user(s.user.id, limit.min(100)).await?.into_iter().map(Into::into).collect())
    }

    // ----- accounts (for the app's admin screens and command line) -------------------

    /// Make an account. Its id is random; roles are checked; a first password
    /// is optional (a user without one can only sign in with a passkey added
    /// through a one-time link, or after an admin sets a password).
    pub async fn create_user(&self, new: NewUser) -> Result<User, Error> {
        let name = Username::parse(&new.username)?;
        for r in &new.roles {
            username::check_role(r)?;
        }
        let phc = match &new.password {
            Some(p) => Some(self.hash_new(name.as_str(), p).await?),
            None => None,
        };
        let display = clean_display_name(new.display_name.as_deref().unwrap_or(name.as_str()));
        let rec = UserRecord {
            id: token::random_uuid()?,
            username: name.as_str().to_string(),
            username_key: name.key().to_string(),
            username_skeleton: name.skeleton().to_string(),
            display_name: if display.is_empty() { name.as_str().to_string() } else { display },
            active: true,
            created_ms: self.now(),
            roles: new.roles,
        };
        let store = &self.0.store;
        store.insert_user(&rec).await.map_err(conflict_to_taken)?;
        if let Some(phc) = phc {
            store.set_password(rec.id, &phc, self.now()).await?;
        }
        self.event(Some(rec.id), "account_created", None, None).await;
        Ok(store.user(rec.id).await?.ok_or(Error::NotFound)?.into())
    }

    /// A user by id.
    pub async fn user(&self, id: Uuid) -> Result<Option<User>, Error> {
        Ok(self.0.store.user(id).await?.map(Into::into))
    }

    /// A user by username (any capitalisation).
    pub async fn user_by_username(&self, name: &str) -> Result<Option<User>, Error> {
        let Some(k) = username::lookup_key(name) else { return Ok(None) };
        Ok(self.0.store.user_by_key(&k).await?.map(Into::into))
    }

    /// All users.
    pub async fn users(&self) -> Result<Vec<User>, Error> {
        Ok(self.0.store.users().await?.into_iter().map(Into::into).collect())
    }

    /// Does the user have a password?
    pub async fn has_password(&self, id: Uuid) -> Result<bool, Error> {
        Ok(self.0.store.password(id).await?.is_some())
    }

    /// Set a user's password (an admin reset, or `app passwd` on the
    /// machine). Every session of theirs ends.
    pub async fn set_password(&self, id: Uuid, password: &str) -> Result<(), Error> {
        let store = &self.0.store;
        let user = store.user(id).await?.ok_or(Error::NotFound)?;
        let phc = self.hash_new(&user.username, password).await?;
        store.set_password(id, &phc, self.now()).await?;
        store.delete_sessions_for_user(id, None).await?;
        self.event(Some(id), "password_set", None, None).await;
        Ok(())
    }

    /// Remove a user's password (they can then sign in only with passkeys).
    /// Every session of theirs that began with the password ends.
    pub async fn remove_password(&self, id: Uuid) -> Result<(), Error> {
        let store = &self.0.store;
        if !store.remove_password(id).await? {
            return Err(Error::NotFound);
        }
        for s in store.sessions_for_user(id).await? {
            if s.method == SignInMethod::Password.as_str() {
                store.delete_session(s.id).await?;
            }
        }
        self.event(Some(id), "password_removed", None, None).await;
        Ok(())
    }

    /// Replace a user's roles.
    pub async fn set_roles(&self, id: Uuid, roles: &[String]) -> Result<(), Error> {
        for r in roles {
            username::check_role(r)?;
        }
        if !self.0.store.set_roles(id, roles).await? {
            return Err(Error::NotFound);
        }
        self.event(Some(id), "roles_changed", None, None).await;
        Ok(())
    }

    /// Enable or disable an account. Disabling ends its sessions at once.
    pub async fn set_active(&self, id: Uuid, active: bool) -> Result<(), Error> {
        let store = &self.0.store;
        let mut u = store.user(id).await?.ok_or(Error::NotFound)?;
        u.active = active;
        store.update_user(&u).await?;
        if !active {
            store.delete_sessions_for_user(id, None).await?;
        }
        self.event(Some(id), if active { "account_enabled" } else { "account_disabled" }, None, None).await;
        Ok(())
    }

    /// Rename a user (checked like a new username).
    pub async fn rename_user(&self, id: Uuid, new_name: &str) -> Result<(), Error> {
        let name = Username::parse(new_name)?;
        let store = &self.0.store;
        let mut u = store.user(id).await?.ok_or(Error::NotFound)?;
        u.username = name.as_str().to_string();
        u.username_key = name.key().to_string();
        u.username_skeleton = name.skeleton().to_string();
        store.update_user(&u).await.map_err(conflict_to_taken)?;
        self.event(Some(id), "renamed", None, None).await;
        Ok(())
    }

    /// Change a user's display name.
    pub async fn set_display_name(&self, id: Uuid, display_name: &str) -> Result<(), Error> {
        let store = &self.0.store;
        let mut u = store.user(id).await?.ok_or(Error::NotFound)?;
        let d = clean_display_name(display_name);
        u.display_name = if d.is_empty() { u.username.clone() } else { d };
        store.update_user(&u).await?;
        Ok(())
    }

    /// End every session of a user.
    pub async fn end_all_sessions(&self, id: Uuid) -> Result<u64, Error> {
        let n = self.0.store.delete_sessions_for_user(id, None).await?;
        self.event(Some(id), "sessions_ended", None, Some(&format!(r#"{{"count":{n}}}"#))).await;
        Ok(n)
    }

    /// Delete a user and everything that is theirs.
    pub async fn delete_user(&self, id: Uuid) -> Result<(), Error> {
        if !self.0.store.delete_user(id).await? {
            return Err(Error::NotFound);
        }
        tracing::info!(target: "doorward::security", user = %id, "account deleted");
        Ok(())
    }

    /// Time password hashing again for this machine and switch to the new
    /// settings (saved in the store). Takes a second or two of full CPU.
    pub async fn retune_hashing(&self) -> Result<HashPolicy, Error> {
        let _turn = self.0.hasher.turn(self.0.hash_wait).await.ok_or(Error::Busy)?;
        let hasher = self.0.hasher.clone();
        let p = tokio::task::spawn_blocking(move || -> Result<HashPolicy, Error> {
            let (p, _) = HashPolicy::load_or_tune(None, true)?;
            hasher.replace(p)?;
            Ok(p)
        })
        .await
        .map_err(|_| Error::Hashing)??;
        self.0.store.meta_set(POLICY_KEY, &p.to_json()).await?;
        tracing::info!(target: "doorward", "password hashing retuned: {}", p.describe());
        Ok(p)
    }

    // ----- upkeep ------------------------------------------------------------------

    /// Remove expired sessions and remembered browsers, old log lines, and
    /// idle rate-limit entries. Run it now and then (see
    /// [`Doorward::spawn_upkeep`]).
    pub async fn upkeep(&self) -> Result<(), Error> {
        let now = self.now();
        let s = &self.0.store;
        s.prune_sessions(now).await?;
        s.prune_remembered(now).await?;
        s.prune_events(now - ms(self.0.event_retention)).await?;
        self.0.limiter.tidy(now);
        #[cfg(feature = "passkeys")]
        self.0.passkeys.tidy(now);
        Ok(())
    }

    /// Run [`Doorward::upkeep`] every `every` on the current tokio runtime.
    pub fn spawn_upkeep(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(every.max(Duration::from_secs(1)));
            loop {
                iv.tick().await;
                if let Err(e) = me.upkeep().await {
                    tracing::warn!(target: "doorward", "upkeep failed: {e}");
                }
            }
        })
    }

    // ----- the security log -----------------------------------------------------------

    /// Record a security event in the store and on the `doorward::security`
    /// log target. Never fails the caller: a log that can't be written is
    /// reported on the log target instead.
    pub(crate) async fn event(&self, user: Option<Uuid>, kind: &str, v: Option<&Visit>, detail: Option<&str>) {
        let address = v.map(|v| self.address_of(v).origin().to_string());
        let ip = v.map(|v| v.ip.to_string());
        let user_s = user.map(|u| u.to_string()).unwrap_or_default();
        let failure = kind.ends_with("_failed") || kind.ends_with("_refused");
        if failure {
            tracing::warn!(target: "doorward::security", kind, user = %user_s, ip = ip.as_deref().unwrap_or(""), address = address.as_deref().unwrap_or(""), detail = detail.unwrap_or(""));
        } else {
            tracing::info!(target: "doorward::security", kind, user = %user_s, ip = ip.as_deref().unwrap_or(""), address = address.as_deref().unwrap_or(""), detail = detail.unwrap_or(""));
        }
        let e = EventRecord {
            id: 0,
            at_ms: self.now(),
            user_id: user,
            kind: kind.to_string(),
            address,
            ip,
            detail: detail.map(String::from),
        };
        if let Err(err) = self.0.store.insert_event(&e).await {
            tracing::error!(target: "doorward::security", "writing the security log failed: {err}");
        }
    }
}

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn same_origin_for_tests(headers: &HeaderMap, origin: &str) -> bool {
    same_origin(headers, origin)
}

fn conflict_to_taken(e: StoreError) -> Error {
    match e {
        StoreError::Conflict("username" | "skeleton") => Error::UsernameTaken,
        e => Error::Store(e),
    }
}

/// Was this request sent by a page of `origin` (or by something that isn't a
/// browser)? `Sec-Fetch-Site` is believed when present; otherwise `Origin`
/// must match exactly. With neither header, it isn't a cross-site browser
/// request (browsers send `Origin` on every cross-site request that isn't a
/// GET or HEAD).
fn same_origin(headers: &HeaderMap, origin: &str) -> bool {
    if let Some(site) = net::single_header(headers, "sec-fetch-site") {
        if site != "same-origin" {
            return false;
        }
    } else if headers.contains_key("sec-fetch-site") {
        return false;
    }
    match headers.get_all(http::header::ORIGIN).iter().count() {
        0 => true,
        1 => net::single_header(headers, "origin").is_some_and(|o| o.eq_ignore_ascii_case(origin)),
        _ => false,
    }
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

    #[test]
    fn origin_checks() {
        let o = "https://pc.lan:8040";
        assert!(same_origin(&h(&[]), o), "non-browser client");
        assert!(same_origin(&h(&[("origin", "https://pc.lan:8040")]), o));
        assert!(same_origin(&h(&[("origin", "https://PC.lan:8040")]), o));
        assert!(!same_origin(&h(&[("origin", "https://evil.example")]), o));
        assert!(!same_origin(&h(&[("origin", "https://pc.lan")]), o), "port matters");
        assert!(!same_origin(&h(&[("origin", "http://pc.lan:8040")]), o), "scheme matters");
        assert!(!same_origin(&h(&[("origin", "null")]), o));
        assert!(same_origin(&h(&[("sec-fetch-site", "same-origin"), ("origin", "https://pc.lan:8040")]), o));
        assert!(!same_origin(&h(&[("sec-fetch-site", "same-site"), ("origin", "https://pc.lan:8040")]), o));
        assert!(!same_origin(&h(&[("sec-fetch-site", "cross-site")]), o));
        assert!(!same_origin(&h(&[("sec-fetch-site", "none")]), o), "not for writes");
        assert!(!same_origin(&h(&[("origin", "https://pc.lan:8040"), ("origin", "https://evil.example")]), o));
    }

    #[tokio::test]
    async fn remembered_browsers_skip_the_visitor_queue() {
        use crate::store::MemoryStore;
        let dw = Doorward::builder(MemoryStore::new())
            .address(Address::new("https://a.example").unwrap())
            .hash_policy(HashPolicy { concurrency: 2, ..HashPolicy::floor() })
            .hash_wait(Duration::from_millis(200))
            .build()
            .await
            .unwrap();
        // A flood of visitors holds the visitor gate.
        let _flood = dw.0.visitor_gate.acquire().await.unwrap();
        let visitor = Who::Visitor(VisitorKey::of("192.0.2.1".parse().unwrap()));
        assert_eq!(dw.check_password(visitor, "pw", None).await, Verdict::Busy);
        // A remembered browser still gets its check.
        let phc = dw.0.hasher.hash("pw").unwrap();
        assert!(dw.check_password(Who::Remembered([1; 32]), "pw", Some(phc)).await.is_good());
    }

    #[test]
    fn display_names_and_labels_are_cleaned() {
        assert_eq!(clean_display_name("  Ulrich\u{0}\u{202e} H\n "), "Ulrich H");
        assert_eq!(clean_display_name(&"x".repeat(500)).chars().count(), 100);
        assert_eq!(clean_label("  ", "Passkey"), "Passkey");
        assert_eq!(clean_label("Phone\u{7}", "Passkey"), "Phone");
    }
}
