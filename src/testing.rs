//! Helpers for testing sign-in without a browser (feature `test-util`).
//!
//! [`TestAuthenticator`] is a software passkey device: it answers the
//! WebAuthn options doorward hands out with real P-256 signatures, keeps its
//! credentials discoverable (it returns the user handle, like a phone or
//! password manager), and can misbehave on request to test the refusals.
//! It is for tests only: its keys live in memory unprotected.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

pub use crate::store::conformance;

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

struct Credential {
    id: Vec<u8>,
    rp_id: String,
    user_handle: Vec<u8>,
    key: SigningKey,
    counter: u32,
}

/// A software passkey device for tests.
pub struct TestAuthenticator {
    creds: Vec<Credential>,
    /// Report user verification (a PIN or fingerprint). On by default.
    pub user_verified: bool,
    /// Report the credential as backed up (synced), like most passkeys.
    pub backed_up: bool,
    /// Increase the signature counter on each use (security keys do; synced
    /// passkeys report 0). Off by default.
    pub counting: bool,
}

impl Default for TestAuthenticator {
    fn default() -> Self {
        TestAuthenticator::new()
    }
}

impl std::fmt::Debug for TestAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestAuthenticator").field("credentials", &self.creds.len()).finish_non_exhaustive()
    }
}

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

fn unb64(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_end_matches('=');
    Base64UrlUnpadded::decode_vec(s).map_err(|e| format!("base64: {e}"))
}

fn new_key() -> SigningKey {
    loop {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        if let Ok(k) = SigningKey::from_bytes(&b.into()) {
            return k;
        }
    }
}

fn cbor(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).unwrap();
    out
}

fn int(i: i64) -> Value {
    Value::Integer(i.into())
}

impl TestAuthenticator {
    /// A device with no credentials that verifies its user.
    pub fn new() -> TestAuthenticator {
        TestAuthenticator { creds: Vec::new(), user_verified: true, backed_up: true, counting: false }
    }

    /// How many passkeys the device holds.
    pub fn len(&self) -> usize {
        self.creds.len()
    }

    /// Holds no passkeys.
    pub fn is_empty(&self) -> bool {
        self.creds.is_empty()
    }

    /// Set the signature counter of every credential (to fake a clone).
    pub fn set_counter(&mut self, counter: u32) {
        for c in &mut self.creds {
            c.counter = counter;
        }
    }

    /// Replace the device's user handles (to fake a passkey claiming to
    /// belong to someone else).
    pub fn set_user_handle(&mut self, handle: &[u8]) {
        for c in &mut self.creds {
            c.user_handle = handle.to_vec();
        }
    }

    fn flags(&self) -> u8 {
        let mut f = UP;
        if self.user_verified {
            f |= UV;
        }
        if self.backed_up {
            f |= BE | BS;
        }
        f
    }

    /// Answer `navigator.credentials.create()` as the page at `origin` would
    /// get it. `options` is what doorward returned (`{"publicKey": …}`).
    pub fn register(&mut self, origin: &str, options: &Json) -> Result<Json, String> {
        let pk = options.get("publicKey").ok_or("no publicKey")?;
        let rp_id = pk.pointer("/rp/id").and_then(Json::as_str).ok_or("no rp.id")?.to_string();
        let challenge = pk.get("challenge").and_then(Json::as_str).ok_or("no challenge")?;
        let user_handle = unb64(pk.pointer("/user/id").and_then(Json::as_str).ok_or("no user.id")?)?;
        let excluded: Vec<Vec<u8>> = pk
            .get("excludeCredentials")
            .and_then(Json::as_array)
            .map(|a| {
                a.iter().filter_map(|c| c.get("id").and_then(Json::as_str)).filter_map(|s| unb64(s).ok()).collect()
            })
            .unwrap_or_default();
        if self.creds.iter().any(|c| c.rp_id == rp_id && excluded.contains(&c.id)) {
            return Err("InvalidStateError: already registered".into());
        }
        let mut id = vec![0u8; 32];
        getrandom::fill(&mut id).unwrap();
        let key = new_key();
        let point = key.verifying_key().to_encoded_point(false);
        let cose = cbor(&Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(point.x().unwrap().to_vec())),
            (int(-3), Value::Bytes(point.y().unwrap().to_vec())),
        ]));
        let mut auth = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth.push(self.flags() | AT);
        auth.extend_from_slice(&0u32.to_be_bytes());
        auth.extend_from_slice(&[0u8; 16]);
        auth.extend_from_slice(&(id.len() as u16).to_be_bytes());
        auth.extend_from_slice(&id);
        auth.extend_from_slice(&cose);
        let attestation = cbor(&Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth)),
        ]));
        let client_data =
            json!({"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
                .to_string();
        self.creds.push(Credential { id: id.clone(), rp_id, user_handle, key, counter: 0 });
        Ok(json!({
            "id": b64(&id),
            "rawId": b64(&id),
            "type": "public-key",
            "response": {"attestationObject": b64(&attestation), "clientDataJSON": b64(client_data.as_bytes())},
            "extensions": {}
        }))
    }

    /// Answer `navigator.credentials.get()` as the page at `origin` would get
    /// it, with the first credential for the options' relying party (and in
    /// their allow list, when they have one).
    pub fn sign_in(&mut self, origin: &str, options: &Json) -> Result<Json, String> {
        let pk = options.get("publicKey").ok_or("no publicKey")?;
        let rp_id = pk.get("rpId").and_then(Json::as_str).ok_or("no rpId")?.to_string();
        let challenge = pk.get("challenge").and_then(Json::as_str).ok_or("no challenge")?.to_string();
        self.answer(origin, &rp_id, &challenge, pk)
    }

    /// Like [`TestAuthenticator::sign_in`], but signing for `rp_id` whatever
    /// the options say (to fake a passkey made for another site).
    pub fn sign_in_as_rp(&mut self, origin: &str, rp_id: &str, options: &Json) -> Result<Json, String> {
        let pk = options.get("publicKey").ok_or("no publicKey")?;
        let challenge = pk.get("challenge").and_then(Json::as_str).ok_or("no challenge")?.to_string();
        self.answer(origin, rp_id, &challenge, pk)
    }

    fn answer(&mut self, origin: &str, rp_id: &str, challenge: &str, pk: &Json) -> Result<Json, String> {
        let allowed: Vec<Vec<u8>> = pk
            .get("allowCredentials")
            .and_then(Json::as_array)
            .map(|a| {
                a.iter().filter_map(|c| c.get("id").and_then(Json::as_str)).filter_map(|s| unb64(s).ok()).collect()
            })
            .unwrap_or_default();
        let flags = self.flags();
        let counting = self.counting;
        let cred = self
            .creds
            .iter_mut()
            .find(|c| c.rp_id == rp_id && (allowed.is_empty() || allowed.contains(&c.id)))
            .ok_or("NotAllowedError: no credential for this site")?;
        if counting {
            cred.counter += 1;
        }
        let mut auth = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend_from_slice(&cred.counter.to_be_bytes());
        let client_data =
            json!({"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false}).to_string();
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let sig: Signature = cred.key.sign(&signed);
        Ok(json!({
            "id": b64(&cred.id),
            "rawId": b64(&cred.id),
            "type": "public-key",
            "response": {
                "authenticatorData": b64(&auth),
                "clientDataJSON": b64(client_data.as_bytes()),
                "signature": b64(sig.to_der().as_bytes()),
                "userHandle": b64(&cred.user_handle)
            },
            "extensions": {}
        }))
    }
}
