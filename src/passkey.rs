//! Passkeys (WebAuthn, through webauthn-rs): signing in with a phone, a
//! security key or this computer instead of a password.
//!
//! A passkey belongs to the name in the browser's address bar (its "relying
//! party"), so each address has its own passkeys. Every ceremony requires
//! user verification (a PIN, fingerprint or face), so a passkey alone is
//! already two factors.
//!
//! Requests in progress live in memory for two minutes and are single-use.
//! Starting one counts against the visitor's (or remembered browser's)
//! budget, and open ones are capped per visitor, per network, per account
//! and in all: a full table refuses new requests instead of dropping old
//! ones, so nobody can push out your sign-in mid-way. Remembered browsers
//! and signed-in users have tables of their own, which visitors can't fill.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CredentialID, DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyAuthentication, PasskeyRegistration,
    Url, Webauthn, WebauthnBuilder,
};

pub use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};

use crate::address::Address;
use crate::doorward::{Doorward, Visit, clean_label};
use crate::error::Error;
use crate::limits::Who;
use crate::model::{Session, SignInMethod, SignedIn};
use crate::net::VisitorKey;
use crate::store::{PasskeyRecord, StoreError};
use crate::token;

/// How long a passkey request stays open.
const CEREMONY_TTL: Duration = Duration::from_secs(120);
/// Open sign-in requests per visitor (an IPv4 address or IPv6 /64)…
const PER_VISITOR: usize = 8;
/// …per network of visitors (an IPv4 /24 or IPv6 /48)…
const PER_NETWORK: usize = 64;
/// …per account, from its remembered browsers…
const PER_ACCOUNT: usize = 8;
/// …per account, from its sessions (adding a passkey, or confirming it's you)…
const PER_SIGNED_IN: usize = 4;
/// …and in all, for each of the three kinds of owner.
const PER_POOL: usize = 10_000;
/// Expired requests are swept out at most this often (and at upkeep).
const SWEEP_EVERY_MS: i64 = 1_000;
/// The wait suggested when a whole pool or network is full.
const FULL_RETRY: Duration = Duration::from_secs(5);

/// A passkey request for the browser: pass `options` to
/// `navigator.credentials.get()` or `.create()` (after the usual base64url
/// decoding), and send back the result with `ceremony`.
#[derive(Debug, serde::Serialize)]
pub struct PasskeyChallenge<T> {
    /// Identifies this request; send it back with the browser's answer.
    pub ceremony: String,
    /// The WebAuthn options.
    pub options: T,
}

/// One of a user's passkeys.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PasskeyInfo {
    /// Its public id.
    pub id: Uuid,
    /// The label the user gave it.
    pub label: String,
    /// The name it works at.
    pub rp_id: String,
    /// When it was added.
    pub created_ms: i64,
    /// When it last signed in.
    pub last_used_ms: Option<i64>,
    /// It works at the address of this request.
    pub here: bool,
}

/// Who a request in progress is counted against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Owner {
    /// A visitor without a remembered browser.
    Visitor(VisitorKey),
    /// An account, through one of its remembered browsers.
    Remembered(Uuid),
    /// An account, through one of its sessions.
    SignedIn(Uuid),
}

impl Owner {
    fn from_who(w: Who) -> Owner {
        match w {
            Who::Visitor(k) => Owner::Visitor(k),
            Who::Remembered(u) => Owner::Remembered(u),
        }
    }

    fn pool(&self) -> usize {
        match self {
            Owner::Visitor(_) => 0,
            Owner::Remembered(_) => 1,
            Owner::SignedIn(_) => 2,
        }
    }

    fn cap(&self) -> usize {
        match self {
            Owner::Visitor(_) => PER_VISITOR,
            Owner::Remembered(_) => PER_ACCOUNT,
            Owner::SignedIn(_) => PER_SIGNED_IN,
        }
    }

    fn network(&self) -> Option<VisitorKey> {
        match self {
            Owner::Visitor(k) => Some(k.network()),
            _ => None,
        }
    }
}

enum Kind {
    SignIn(DiscoverableAuthentication),
    Register { user_id: Uuid, session_id: Uuid, label: String, state: PasskeyRegistration },
    Confirm { user_id: Uuid, session_id: Uuid, state: PasskeyAuthentication },
}

struct Pending {
    owner: Owner,
    address: String,
    created_ms: i64,
    kind: Kind,
}

#[derive(Default)]
struct Table {
    map: HashMap<String, Pending>,
    /// When each owner's open requests began.
    per_owner: HashMap<Owner, Vec<i64>>,
    per_network: HashMap<VisitorKey, usize>,
    per_pool: [usize; 3],
    swept_ms: i64,
}

impl Table {
    fn remove(&mut self, id: &str) -> Option<Pending> {
        let p = self.map.remove(id)?;
        if let Some(times) = self.per_owner.get_mut(&p.owner) {
            if let Some(i) = times.iter().position(|t| *t == p.created_ms) {
                times.swap_remove(i);
            }
            if times.is_empty() {
                self.per_owner.remove(&p.owner);
            }
        }
        if let Some(net) = p.owner.network()
            && let Some(n) = self.per_network.get_mut(&net)
        {
            *n -= 1;
            if *n == 0 {
                self.per_network.remove(&net);
            }
        }
        self.per_pool[p.owner.pool()] -= 1;
        Some(p)
    }

    /// Remove expired requests: always when `force`, otherwise at most once
    /// every [`SWEEP_EVERY_MS`], so a flood can't make every request scan
    /// the whole table under the lock.
    fn sweep(&mut self, now: i64, force: bool) {
        if !force && now - self.swept_ms < SWEEP_EVERY_MS {
            return;
        }
        self.swept_ms = now;
        let ttl = CEREMONY_TTL.as_millis() as i64;
        let old: Vec<String> =
            self.map.iter().filter(|(_, p)| now - p.created_ms >= ttl).map(|(k, _)| k.clone()).collect();
        for k in old {
            self.remove(&k);
        }
    }

    /// Keep a request, or refuse when its owner, network or pool is full.
    fn keep(&mut self, id: String, p: Pending, now: i64) -> Result<(), Error> {
        self.sweep(now, false);
        let ttl = CEREMONY_TTL.as_millis() as i64;
        let mine = self.per_owner.get(&p.owner).map(Vec::as_slice).unwrap_or(&[]);
        if mine.len() >= p.owner.cap() {
            // When the owner's oldest request expires, there is room again.
            let oldest = mine.iter().copied().min().unwrap_or(now);
            let wait = (oldest + ttl - now).max(1000) as u64;
            return Err(Error::TooManyAttempts { retry_after: Duration::from_millis(wait) });
        }
        let net = p.owner.network();
        let full_network = net.is_some_and(|n| self.per_network.get(&n).copied().unwrap_or(0) >= PER_NETWORK);
        if full_network || self.per_pool[p.owner.pool()] >= PER_POOL {
            return Err(Error::TooManyAttempts { retry_after: FULL_RETRY });
        }
        self.per_owner.entry(p.owner).or_default().push(p.created_ms);
        if let Some(n) = net {
            *self.per_network.entry(n).or_insert(0) += 1;
        }
        self.per_pool[p.owner.pool()] += 1;
        self.map.insert(id, p);
        Ok(())
    }

    /// Take a request (it can be used once), if it hasn't expired.
    fn take(&mut self, id: &str, now: i64) -> Option<Pending> {
        let p = self.remove(id)?;
        (now - p.created_ms < CEREMONY_TTL.as_millis() as i64).then_some(p)
    }
}

/// Passkey state: a WebAuthn verifier per passkey address, and the requests
/// in progress.
pub(crate) struct Passkeys {
    by_origin: HashMap<String, Webauthn>,
    pending: Mutex<Table>,
}

impl Passkeys {
    pub(crate) fn new(addresses: &[Address], rp_name: &str) -> Result<Passkeys, Error> {
        let mut by_origin = HashMap::new();
        for a in addresses.iter().filter(|a| a.allows_passkeys()) {
            let url = Url::parse(a.origin()).map_err(|e| Error::Config(format!("address {}: {e}", a.origin())))?;
            let w = WebauthnBuilder::new(a.host(), &url)
                .and_then(|b| {
                    b.rp_name(rp_name).timeout(CEREMONY_TTL).allow_subdomains(false).allow_any_port(false).build()
                })
                .map_err(|e| Error::Config(format!("address {}: passkeys: {e}", a.origin())))?;
            by_origin.insert(a.origin().to_string(), w);
        }
        Ok(Passkeys { by_origin, pending: Mutex::new(Table::default()) })
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        // Every change to the table is made whole under the lock.
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn tidy(&self, now: i64) {
        self.table().sweep(now, true);
    }

    #[cfg(test)]
    fn open(&self) -> usize {
        self.table().map.len()
    }
}

fn cred_key(id: &CredentialID) -> String {
    <base64ct::Base64UrlUnpadded as base64ct::Encoding>::encode_string(id.as_ref())
}

/// Ask for a discoverable passkey where possible (the account lives on the
/// authenticator, so the sign-in page needs no username).
fn prefer_resident(ccr: &CreationChallengeResponse) -> Result<serde_json::Value, Error> {
    let mut v = serde_json::to_value(ccr).map_err(|_| Error::PasskeyRejected)?;
    if let Some(sel) = v.pointer_mut("/publicKey/authenticatorSelection").and_then(|s| s.as_object_mut()) {
        sel.insert("residentKey".into(), "preferred".into());
    }
    Ok(v)
}

fn detail(pairs: &[(&str, &str)]) -> String {
    let m: serde_json::Map<String, serde_json::Value> =
        pairs.iter().map(|(k, v)| ((*k).to_string(), serde_json::Value::String((*v).to_string()))).collect();
    serde_json::Value::Object(m).to_string()
}

impl Doorward {
    fn webauthn(&self, v: &Visit) -> Result<&Webauthn, Error> {
        let a = self.address_of(v);
        if !a.allows_passkeys() {
            return Err(Error::PasskeysUnavailableHere);
        }
        self.0.passkeys.by_origin.get(a.origin()).ok_or(Error::PasskeysUnavailableHere)
    }

    /// The user's passkeys, decoded, for the name of this request's address.
    async fn passkeys_here(&self, user_id: Uuid, v: &Visit) -> Result<Vec<(PasskeyRecord, Passkey)>, Error> {
        let rp = self.address_of(v).host().to_string();
        Ok(self
            .0
            .store
            .passkeys_for_user(user_id)
            .await?
            .into_iter()
            .filter(|r| r.rp_id == rp)
            .filter_map(|r| match serde_json::from_str::<Passkey>(&r.passkey_json) {
                Ok(p) => Some((r, p)),
                Err(_) => {
                    tracing::warn!(target: "doorward::security", passkey = %r.id, "a saved passkey is unreadable; skipping it");
                    None
                }
            })
            .collect())
    }

    /// Record a successful use: the time, and the passkey's new counter or
    /// backup state when they changed.
    async fn passkey_used(
        &self,
        rec: &PasskeyRecord,
        mut pk: Passkey,
        res: &webauthn_rs::prelude::AuthenticationResult,
    ) -> Result<(), Error> {
        let json = match pk.update_credential(res) {
            Some(true) => serde_json::to_string(&pk).ok(),
            _ => None,
        };
        self.0.store.passkey_used(rec.id, json.as_deref(), self.now()).await?;
        Ok(())
    }

    /// Begin signing in with a passkey. The options ask for a discoverable
    /// passkey with conditional mediation (browser autofill); for a "Sign in
    /// with a passkey" button, drop `mediation` from them before calling
    /// `navigator.credentials.get()`.
    pub async fn passkey_sign_in_start(&self, v: &Visit) -> Result<PasskeyChallenge<RequestChallengeResponse>, Error> {
        if v.is_cross_origin() {
            return Err(Error::CrossOrigin);
        }
        let w = self.webauthn(v)?;
        // Starting counts against the budget too, so requests can't be
        // opened faster than sign-ins could be tried.
        let (who, _) = self.who(v, None).await?;
        self.admit(who).await?;
        let (options, state) = w.start_discoverable_authentication().map_err(|e| {
            tracing::error!(target: "doorward", "starting a passkey sign-in failed: {e}");
            Error::PasskeysUnavailableHere
        })?;
        let id = token::random_id()?;
        let now = self.now();
        let pending = Pending {
            owner: Owner::from_who(who),
            address: self.address_of(v).origin().to_string(),
            created_ms: now,
            kind: Kind::SignIn(state),
        };
        self.0.passkeys.table().keep(id.clone(), pending, now)?;
        Ok(PasskeyChallenge { ceremony: id, options })
    }

    /// Finish signing in with a passkey.
    pub async fn passkey_sign_in_finish(
        &self,
        v: &Visit,
        ceremony: &str,
        credential: &PublicKeyCredential,
        remember: bool,
    ) -> Result<SignedIn, Error> {
        if v.is_cross_origin() {
            return Err(Error::CrossOrigin);
        }
        let w = self.webauthn(v)?;
        let origin = self.address_of(v).origin().to_string();
        let taken = self.0.passkeys.table().take(ceremony, self.now());
        let state = match taken {
            Some(Pending { address, kind: Kind::SignIn(state), .. }) if address == origin => state,
            _ => return Err(Error::CeremonyExpired),
        };
        let (who, device) = self.who(v, None).await?;
        self.admit(who).await?;

        let failed = |user: Option<Uuid>| async move {
            self.0.limiter.failed(who, self.now());
            self.event(user, "sign_in_failed", Some(v), Some(r#"{"method":"passkey"}"#)).await;
            Error::PasskeyNotRecognised
        };
        let Ok((user_id, cred_id)) = w.identify_discoverable_authentication(credential) else {
            return Err(failed(None).await);
        };
        let cred_id = cred_id.to_vec();
        let Some(user) = self.0.store.user(user_id).await? else {
            return Err(failed(None).await);
        };
        let keys = self.passkeys_here(user.id, v).await?;
        if !keys.iter().any(|(_, p)| p.cred_id().as_ref() == cred_id.as_slice()) {
            return Err(failed(Some(user.id)).await);
        }
        let discoverable: Vec<DiscoverableKey> = keys.iter().map(|(_, p)| p.into()).collect();
        let result = match w.finish_discoverable_authentication(credential, state, &discoverable) {
            Ok(r) => r,
            Err(e) => {
                tracing::info!(target: "doorward::security", user = %user.id, "passkey sign-in refused: {e}");
                return Err(failed(Some(user.id)).await);
            }
        };
        if let Some((rec, pk)) = keys.into_iter().find(|(_, p)| p.cred_id() == result.cred_id()) {
            self.passkey_used(&rec, pk, &result).await?;
        }
        if !user.active {
            self.event(Some(user.id), "sign_in_refused", Some(v), Some(r#"{"reason":"disabled"}"#)).await;
            return Err(Error::AccountDisabled);
        }
        // The remembered browser (if any, even someone else's) is replaced by
        // a fresh one for this user.
        self.start_session(v, user, SignInMethod::Passkey, remember, device).await
    }

    /// Begin adding a passkey for the signed-in user at this address. Needs a
    /// recent sign-in. `label` is the user's name for it ("Ulrich's phone").
    pub async fn passkey_register_start(
        &self,
        v: &Visit,
        label: &str,
    ) -> Result<PasskeyChallenge<serde_json::Value>, Error> {
        if v.is_cross_origin() {
            return Err(Error::CrossOrigin);
        }
        let w = self.webauthn(v)?;
        let (session, rec) = self.authenticate_record(v).await?.ok_or(Error::NotSignedIn)?;
        self.require_recent(&session)?;
        let all = self.0.store.passkeys_for_user(session.user.id).await?;
        if all.len() >= self.0.max_passkeys {
            return Err(Error::TooManyPasskeys);
        }
        let exclude: Vec<CredentialID> =
            self.passkeys_here(session.user.id, v).await?.into_iter().map(|(_, p)| p.cred_id().clone()).collect();
        let user = &session.user;
        let (options, state) =
            w.start_passkey_registration(user.id, &user.username, &user.display_name, Some(exclude)).map_err(|e| {
                tracing::error!(target: "doorward", "starting a passkey registration failed: {e}");
                Error::PasskeyRejected
            })?;
        let options = prefer_resident(&options)?;
        let id = token::random_id()?;
        let now = self.now();
        let pending = Pending {
            owner: Owner::SignedIn(user.id),
            address: self.address_of(v).origin().to_string(),
            created_ms: now,
            kind: Kind::Register { user_id: user.id, session_id: rec.id, label: clean_label(label, "Passkey"), state },
        };
        self.0.passkeys.table().keep(id.clone(), pending, now)?;
        Ok(PasskeyChallenge { ceremony: id, options })
    }

    /// Finish adding a passkey. The user's other sessions end (there is a
    /// new way in); this one stays.
    pub async fn passkey_register_finish(
        &self,
        v: &Visit,
        ceremony: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<PasskeyInfo, Error> {
        if v.is_cross_origin() {
            return Err(Error::CrossOrigin);
        }
        let w = self.webauthn(v)?;
        let (session, rec) = self.authenticate_record(v).await?.ok_or(Error::NotSignedIn)?;
        let origin = self.address_of(v).origin().to_string();
        let taken = self.0.passkeys.table().take(ceremony, self.now());
        let (label, state) = match taken {
            Some(Pending { address, kind: Kind::Register { user_id, session_id, label, state }, .. })
                if address == origin && user_id == session.user.id && session_id == rec.id =>
            {
                (label, state)
            }
            _ => return Err(Error::CeremonyExpired),
        };
        self.require_recent(&session)?;
        let pk = w.finish_passkey_registration(credential, &state).map_err(|e| {
            tracing::info!(target: "doorward::security", user = %session.user.id, "passkey registration refused: {e}");
            Error::PasskeyRejected
        })?;
        let store = &self.0.store;
        if store.passkeys_for_user(session.user.id).await?.len() >= self.0.max_passkeys {
            return Err(Error::TooManyPasskeys);
        }
        let json = serde_json::to_string(&pk).map_err(|_| Error::PasskeyRejected)?;
        let record = PasskeyRecord {
            id: token::random_uuid()?,
            user_id: session.user.id,
            rp_id: self.address_of(v).host().to_string(),
            cred_id: cred_key(pk.cred_id()),
            passkey_json: json,
            label,
            created_ms: self.now(),
            last_used_ms: None,
        };
        store.insert_passkey(&record).await.map_err(|e| match e {
            StoreError::Conflict("cred_id") => Error::PasskeyAlreadyAdded,
            e => Error::Store(e),
        })?;
        let ended = store.delete_sessions_for_user(session.user.id, Some(rec.id)).await?;
        let d = detail(&[("label", &record.label), ("rp_id", &record.rp_id), ("sessions_ended", &ended.to_string())]);
        self.event(Some(session.user.id), "passkey_added", Some(v), Some(&d)).await;
        Ok(PasskeyInfo {
            id: record.id,
            label: record.label,
            rp_id: record.rp_id,
            created_ms: record.created_ms,
            last_used_ms: None,
            here: true,
        })
    }

    /// Begin confirming it's still the user with one of their passkeys for
    /// this address (step-up).
    pub async fn passkey_confirm_start(&self, v: &Visit) -> Result<PasskeyChallenge<RequestChallengeResponse>, Error> {
        if v.is_cross_origin() {
            return Err(Error::CrossOrigin);
        }
        let w = self.webauthn(v)?;
        let (session, rec) = self.authenticate_record(v).await?.ok_or(Error::NotSignedIn)?;
        let keys: Vec<Passkey> = self.passkeys_here(session.user.id, v).await?.into_iter().map(|(_, p)| p).collect();
        if keys.is_empty() {
            return Err(Error::PasskeyNotRecognised);
        }
        let (options, state) = w.start_passkey_authentication(&keys).map_err(|e| {
            tracing::error!(target: "doorward", "starting a passkey confirmation failed: {e}");
            Error::PasskeyNotRecognised
        })?;
        let id = token::random_id()?;
        let now = self.now();
        let pending = Pending {
            owner: Owner::SignedIn(session.user.id),
            address: self.address_of(v).origin().to_string(),
            created_ms: now,
            kind: Kind::Confirm { user_id: session.user.id, session_id: rec.id, state },
        };
        self.0.passkeys.table().keep(id.clone(), pending, now)?;
        Ok(PasskeyChallenge { ceremony: id, options })
    }

    /// Finish confirming with a passkey. On success the session counts as
    /// recent and gets a new cookie (send the returned cookies).
    pub async fn passkey_confirm_finish(
        &self,
        v: &Visit,
        ceremony: &str,
        credential: &PublicKeyCredential,
    ) -> Result<SignedIn, Error> {
        if v.is_cross_origin() {
            return Err(Error::CrossOrigin);
        }
        let w = self.webauthn(v)?;
        let (session, rec) = self.authenticate_record(v).await?.ok_or(Error::NotSignedIn)?;
        let origin = self.address_of(v).origin().to_string();
        let taken = self.0.passkeys.table().take(ceremony, self.now());
        let state = match taken {
            Some(Pending { address, kind: Kind::Confirm { user_id, session_id, state }, .. })
                if address == origin && user_id == session.user.id && session_id == rec.id =>
            {
                state
            }
            _ => return Err(Error::CeremonyExpired),
        };
        let (who, _) = self.who(v, Some(session.user.id)).await?;
        self.admit(who).await?;
        match w.finish_passkey_authentication(credential, &state) {
            Ok(result) => {
                let keys = self.passkeys_here(session.user.id, v).await?;
                if let Some((r, pk)) = keys.into_iter().find(|(_, p)| p.cred_id() == result.cred_id()) {
                    self.passkey_used(&r, pk, &result).await?;
                }
                self.mark_recent(v, session, &rec, "passkey").await
            }
            Err(e) => {
                tracing::info!(target: "doorward::security", user = %session.user.id, "passkey confirmation refused: {e}");
                self.0.limiter.failed(who, self.now());
                self.event(Some(session.user.id), "confirm_failed", Some(v), Some(r#"{"method":"passkey"}"#)).await;
                Err(Error::PasskeyNotRecognised)
            }
        }
    }

    /// The signed-in user's passkeys, oldest first, marking those that work
    /// at this request's address.
    pub async fn passkeys(&self, v: &Visit, s: &Session) -> Result<Vec<PasskeyInfo>, Error> {
        let here = self.address_of(v).host().to_string();
        Ok(self
            .user_passkeys(s.user.id)
            .await?
            .into_iter()
            .map(|mut p| {
                p.here = p.rp_id == here;
                p
            })
            .collect())
    }

    /// A user's passkeys (for admin screens; `here` is always false).
    pub async fn user_passkeys(&self, user_id: Uuid) -> Result<Vec<PasskeyInfo>, Error> {
        Ok(self
            .0
            .store
            .passkeys_for_user(user_id)
            .await?
            .into_iter()
            .map(|r| PasskeyInfo {
                id: r.id,
                label: r.label,
                rp_id: r.rp_id,
                created_ms: r.created_ms,
                last_used_ms: r.last_used_ms,
                here: false,
            })
            .collect())
    }

    /// Rename one of the signed-in user's passkeys.
    pub async fn rename_passkey(&self, v: &Visit, s: &Session, id: Uuid, label: &str) -> Result<(), Error> {
        if v.is_cross_origin() {
            return Err(Error::CrossOrigin);
        }
        if !self.0.store.rename_passkey(id, s.user.id, &clean_label(label, "Passkey")).await? {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Remove one of the signed-in user's passkeys. Needs a recent sign-in.
    /// Refused ([`Error::LastPasskey`]) when it would leave them no way in at
    /// an address that has passwords turned off, or no way in at all. Their
    /// other sessions end.
    pub async fn remove_passkey(&self, v: &Visit, s: &Session, id: Uuid) -> Result<(), Error> {
        if v.is_cross_origin() {
            return Err(Error::CrossOrigin);
        }
        self.require_recent(s)?;
        let store = &self.0.store;
        let all = store.passkeys_for_user(s.user.id).await?;
        let Some(target) = all.iter().find(|p| p.id == id) else { return Err(Error::NotFound) };
        let left: Vec<&PasskeyRecord> = all.iter().filter(|p| p.id != id).collect();
        let stranded = self.0.addresses.iter().any(|a| {
            a.allows_passkeys()
                && !a.allows_passwords()
                && a.host() == target.rp_id
                && !left.iter().any(|p| p.rp_id == a.host())
        });
        let no_way_in = left.is_empty() && store.password(s.user.id).await?.is_none();
        if stranded || no_way_in {
            return Err(Error::LastPasskey);
        }
        if !store.delete_passkey(id, s.user.id).await? {
            return Err(Error::NotFound);
        }
        store.delete_sessions_for_user(s.user.id, Some(s.id)).await?;
        let d = detail(&[("label", &target.label), ("rp_id", &target.rp_id)]);
        self.event(Some(s.user.id), "passkey_removed", Some(v), Some(&d)).await;
        Ok(())
    }

    /// Remove every passkey of a user (an admin action, such as recovery on
    /// the machine). Their sessions that began with a passkey end.
    pub async fn remove_all_passkeys(&self, user_id: Uuid) -> Result<usize, Error> {
        let store = &self.0.store;
        let all = store.passkeys_for_user(user_id).await?;
        for p in &all {
            store.delete_passkey(p.id, user_id).await?;
        }
        for s in store.sessions_for_user(user_id).await? {
            if s.method == SignInMethod::Passkey.as_str() {
                store.delete_session(s.id).await?;
            }
        }
        self.event(Some(user_id), "passkeys_reset", None, Some(&format!(r#"{{"count":{}}}"#, all.len()))).await;
        Ok(all.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(owner: Owner, at: i64) -> Pending {
        // Any state will do for table tests; make a real one cheaply.
        let url = Url::parse("https://a.example").unwrap();
        let w = WebauthnBuilder::new("a.example", &url).unwrap().build().unwrap();
        let (_, s) = w.start_discoverable_authentication().unwrap();
        Pending { owner, address: "https://a.example".into(), created_ms: at, kind: Kind::SignIn(s) }
    }

    #[test]
    fn requests_are_single_use_and_expire() {
        let mut t = Table::default();
        let v = Owner::Visitor(VisitorKey::of("192.0.2.1".parse().unwrap()));
        t.keep("a".into(), pending(v, 0), 0).unwrap();
        assert!(t.take("a", 1).is_some());
        assert!(t.take("a", 1).is_none(), "single use");
        t.keep("b".into(), pending(v, 0), 0).unwrap();
        assert!(t.take("b", 120_000).is_none(), "expired");
        assert_eq!(
            (t.map.len(), t.per_owner.len(), t.per_network.len(), t.per_pool),
            (0, 0, 0, [0, 0, 0]),
            "counts follow removals"
        );
    }

    #[test]
    fn a_full_owner_is_refused_without_pushing_anyone_out() {
        let mut t = Table::default();
        let v = Owner::Visitor(VisitorKey::of("192.0.2.1".parse().unwrap()));
        let other = Owner::Visitor(VisitorKey::of("192.0.2.2".parse().unwrap()));
        let me = Owner::Remembered(Uuid::from_u128(1));
        for i in 0..PER_VISITOR {
            t.keep(format!("v{i}"), pending(v, 1_000), 1_000).unwrap();
        }
        let e = t.keep("v-more".into(), pending(v, 2_000), 2_000).unwrap_err();
        assert_eq!(e.retry_after(), Some(Duration::from_millis(119_000)));
        assert!(t.map.contains_key("v0"), "nobody pushed out");
        t.keep("other".into(), pending(other, 2_000), 2_000).unwrap();
        t.keep("mine".into(), pending(me, 2_000), 2_000).unwrap();
        for i in 1..PER_ACCOUNT {
            t.keep(format!("mine{i}"), pending(me, 2_000), 2_000).unwrap();
        }
        assert!(t.keep("mine-more".into(), pending(me, 2_000), 2_000).is_err(), "per account");
        let s = Owner::SignedIn(Uuid::nil());
        for i in 0..PER_SIGNED_IN {
            t.keep(format!("s{i}"), pending(s, 2_000), 2_000).unwrap();
        }
        assert!(t.keep("s-more".into(), pending(s, 2_000), 2_000).is_err());
        // After expiry (and the next sweep) there is room again.
        t.keep("v-later".into(), pending(v, 121_000), 121_000).unwrap();
    }

    #[test]
    fn networks_and_pools_are_capped() {
        let mut t = Table::default();
        // Many /64s of one /48 share the network's allowance.
        let mut n = 0;
        for net64 in 0..100u128 {
            let ip =
                std::net::IpAddr::from((0x2001_0db8_0001_0000_0000_0000_0000_0000u128 + (net64 << 64)).to_be_bytes());
            let o = Owner::Visitor(VisitorKey::of(ip));
            for j in 0..PER_VISITOR {
                if t.keep(format!("{net64}-{j}"), pending(o, 0), 0).is_ok() {
                    n += 1;
                }
            }
        }
        assert_eq!(n, PER_NETWORK);
        // Another /48 is unaffected, and so are remembered browsers.
        let elsewhere = Owner::Visitor(VisitorKey::of("2001:db8:2::1".parse().unwrap()));
        t.keep("elsewhere".into(), pending(elsewhere, 0), 0).unwrap();
        // A full pool refuses everyone of that kind, but no other kind.
        t.per_pool[0] = PER_POOL;
        let fresh = Owner::Visitor(VisitorKey::of("198.51.100.1".parse().unwrap()));
        assert_eq!(t.keep("fresh".into(), pending(fresh, 0), 0).unwrap_err().retry_after(), Some(FULL_RETRY));
        t.keep("me".into(), pending(Owner::Remembered(Uuid::from_u128(9)), 0), 0).unwrap();
    }

    #[test]
    fn expired_requests_are_swept_at_most_once_a_second() {
        let mut t = Table::default();
        let v = Owner::Visitor(VisitorKey::of("192.0.2.1".parse().unwrap()));
        t.keep("a".into(), pending(v, 0), 0).unwrap();
        t.keep("b".into(), pending(v, 119_500), 119_500).unwrap(); // sweeps; "a" isn't expired yet
        assert_eq!(t.map.len(), 2);
        t.keep("c".into(), pending(v, 120_200), 120_200).unwrap(); // "a" has expired, but too soon to sweep
        assert_eq!(t.map.len(), 3);
        assert!(t.take("a", 120_200).is_none(), "an expired request is never used, swept or not");
        t.keep("d".into(), pending(v, 120_600), 120_600).unwrap();
        t.keep("e".into(), pending(v, 130_000), 130_000).unwrap();
        assert_eq!(t.per_owner[&v].len(), 4);
        t.sweep(250_000, true);
        assert!(t.map.is_empty() && t.per_owner.is_empty() && t.per_network.is_empty());
    }

    #[test]
    fn credential_ids_are_base64url() {
        let id: CredentialID = vec![0xfb, 0xff, 0x00].into();
        assert_eq!(cred_key(&id), "-_8A");
    }

    #[test]
    fn registration_options_prefer_resident_keys() {
        let url = Url::parse("https://a.example").unwrap();
        let w = WebauthnBuilder::new("a.example", &url).unwrap().build().unwrap();
        let (ccr, _) = w.start_passkey_registration(Uuid::nil(), "u", "U", None).unwrap();
        let v = prefer_resident(&ccr).unwrap();
        assert_eq!(
            v.pointer("/publicKey/authenticatorSelection/residentKey").and_then(|x| x.as_str()),
            Some("preferred")
        );
        assert_eq!(
            v.pointer("/publicKey/authenticatorSelection/userVerification").and_then(|x| x.as_str()),
            Some("required")
        );
    }

    #[test]
    fn open_counts() {
        let p = Passkeys::new(&[], "x").unwrap();
        assert_eq!(p.open(), 0);
    }
}
