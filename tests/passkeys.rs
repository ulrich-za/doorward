//! Passkeys end to end, with the software authenticator: registration,
//! discoverable sign-in, confirmation, and the refusals that matter.

#![cfg(all(feature = "passkeys", feature = "test-util"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use doorward::passkey::{PublicKeyCredential, RegisterPublicKeyCredential};
use doorward::testing::TestAuthenticator;
use doorward::{Error, ErrorCode};
use std::time::Duration;

fn reg(v: serde_json::Value) -> RegisterPublicKeyCredential {
    serde_json::from_value(v).unwrap()
}

fn cred(v: serde_json::Value) -> PublicKeyCredential {
    serde_json::from_value(v).unwrap()
}

/// Sign in with the password, then add a passkey from `device` at the
/// browser's address.
async fn with_passkey(e: &Env, b: &mut Browser, device: &mut TestAuthenticator) {
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    let start = e.dw.passkey_register_start(&b.post(&e.dw), "Ulrich's phone").await.unwrap();
    let answer = device.register(&b.origin, &start.options).unwrap();
    let info = e.dw.passkey_register_finish(&b.post(&e.dw), &start.ceremony, &reg(answer)).await.unwrap();
    assert_eq!(info.label, "Ulrich's phone");
    assert_eq!(info.rp_id, b.host().split(':').next().unwrap());
}

async fn passkey_sign_in(e: &Env, b: &Browser, device: &mut TestAuthenticator) -> Result<doorward::SignedIn, Error> {
    let start = e.dw.passkey_sign_in_start(&b.post(&e.dw)).await?;
    let opts = serde_json::to_value(&start.options).unwrap();
    assert_eq!(opts["mediation"], "conditional");
    assert_eq!(opts["publicKey"]["userVerification"], "required");
    let answer = device.sign_in(&b.origin, &opts).map_err(|_| Error::PasskeyNotRecognised)?;
    e.dw.passkey_sign_in_finish(&b.post(&e.dw), &start.ceremony, &cred(answer), false).await
}

#[tokio::test]
async fn register_then_sign_in_without_a_username() {
    let e = env().await;
    let u = e.user("admin", Some("correct horse battery")).await;
    let mut device = TestAuthenticator::new();
    let mut b = Browser::lan();
    with_passkey(&e, &mut b, &mut device).await;
    let me = e.dw.require_session(&b.get(&e.dw)).await.unwrap();
    let list = e.dw.passkeys(&b.get(&e.dw), &me).await.unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0].here);
    assert_eq!(list[0].last_used_ms, None);

    let fresh = Browser::lan();
    let s = passkey_sign_in(&e, &fresh, &mut device).await.unwrap();
    assert_eq!(s.session.user.id, u.id);
    assert_eq!(s.session.method, doorward::SignInMethod::Passkey);
    let list = e.dw.user_passkeys(u.id).await.unwrap();
    assert!(list[0].last_used_ms.is_some());
    let kinds: Vec<String> = doorward::store::Store::events_for_user(e.store.as_ref(), u.id, 20)
        .await
        .unwrap()
        .into_iter()
        .map(|x| x.kind)
        .collect();
    assert!(kinds.contains(&"passkey_added".to_string()));
}

#[tokio::test]
async fn adding_a_passkey_needs_a_recent_sign_in_and_ends_other_sessions() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut other = Browser::lan();
    let s = e.dw.sign_in_password(&other.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    other.take(&s.cookies);
    let mut b = Browser::lan();
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);

    e.clock.advance(Duration::from_secs(11 * 60));
    assert!(matches!(e.dw.passkey_register_start(&b.post(&e.dw), "x").await, Err(Error::NeedsRecentSignIn)));
    e.dw.confirm_password(&b.post(&e.dw), "correct horse battery").await.unwrap();
    let start = e.dw.passkey_register_start(&b.post(&e.dw), "x").await.unwrap();
    let mut device = TestAuthenticator::new();
    let answer = device.register(&b.origin, &start.options).unwrap();
    e.dw.passkey_register_finish(&b.post(&e.dw), &start.ceremony, &reg(answer)).await.unwrap();
    assert!(e.dw.authenticate(&b.get(&e.dw)).await.unwrap().is_some());
    assert!(e.dw.authenticate(&other.get(&e.dw)).await.unwrap().is_none(), "a new way in ends other sessions");
}

#[tokio::test]
async fn requests_are_single_use_and_tied_to_their_address_and_session() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut device = TestAuthenticator::new();
    let mut b = Browser::lan();
    with_passkey(&e, &mut b, &mut device).await;

    // A sign-in request can be answered once.
    let start = e.dw.passkey_sign_in_start(&b.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    let answer = cred(device.sign_in(&b.origin, &opts).unwrap());
    let fresh = Browser::lan();
    assert!(e.dw.passkey_sign_in_finish(&fresh.post(&e.dw), &start.ceremony, &answer, false).await.is_ok());
    assert!(matches!(
        e.dw.passkey_sign_in_finish(&fresh.post(&e.dw), &start.ceremony, &answer, false).await,
        Err(Error::CeremonyExpired)
    ));

    // A request from the LAN address can't be finished at the public one.
    let start = e.dw.passkey_sign_in_start(&b.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    let answer = cred(device.sign_in(&b.origin, &opts).unwrap());
    let public = Browser::public("198.51.100.7");
    assert!(matches!(
        e.dw.passkey_sign_in_finish(&public.post(&e.dw), &start.ceremony, &answer, false).await,
        Err(Error::CeremonyExpired)
    ));

    // Requests expire after two minutes.
    let start = e.dw.passkey_sign_in_start(&b.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    let answer = cred(device.sign_in(&b.origin, &opts).unwrap());
    e.clock.advance(Duration::from_secs(121));
    assert!(matches!(
        e.dw.passkey_sign_in_finish(&fresh.post(&e.dw), &start.ceremony, &answer, false).await,
        Err(Error::CeremonyExpired)
    ));

    // A registration started in one session can't be finished in another.
    e.dw.confirm_password(&b.post(&e.dw), "correct horse battery").await.unwrap();
    let start = e.dw.passkey_register_start(&b.post(&e.dw), "second").await.unwrap();
    let mut device2 = TestAuthenticator::new();
    let answer = reg(device2.register(&b.origin, &start.options).unwrap());
    let mut thief = Browser::lan();
    let s = e.dw.sign_in_password(&thief.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    thief.take(&s.cookies);
    assert!(matches!(
        e.dw.passkey_register_finish(&thief.post(&e.dw), &start.ceremony, &answer).await,
        Err(Error::CeremonyExpired)
    ));

    // Unknown ceremony ids are just expired.
    assert!(matches!(
        e.dw.passkey_sign_in_finish(&fresh.post(&e.dw), "nonsense", &answer_for(&mut device, &e, &b).await, false)
            .await,
        Err(Error::CeremonyExpired)
    ));
}

async fn answer_for(device: &mut TestAuthenticator, e: &Env, b: &Browser) -> PublicKeyCredential {
    let start = e.dw.passkey_sign_in_start(&b.post(&e.dw)).await.unwrap();
    cred(device.sign_in(&b.origin, &serde_json::to_value(&start.options).unwrap()).unwrap())
}

#[tokio::test]
async fn forged_answers_are_refused() {
    let e = env().await;
    let victim = e.user("admin", Some("correct horse battery")).await;
    let mut device = TestAuthenticator::new();
    let mut b = Browser::lan();
    with_passkey(&e, &mut b, &mut device).await;
    let fresh = Browser::lan();

    // Signed for another origin (a phishing site that relayed the options).
    let start = e.dw.passkey_sign_in_start(&fresh.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    let phished = cred(device.sign_in("https://pc.lan.evil.example", &opts).unwrap());
    let err = e.dw.passkey_sign_in_finish(&fresh.post(&e.dw), &start.ceremony, &phished, false).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::PasskeyNotRecognised);

    // Signed for another relying party.
    let start = e.dw.passkey_sign_in_start(&fresh.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    let mut other_site = TestAuthenticator::new();
    // A credential the device made for another site, claiming the victim's handle.
    let fake_reg = serde_json::json!({"publicKey": {"rp": {"id": "evil.example"}, "user": {"id": base64url(victim.id.as_bytes())}, "challenge": "AAAA"}});
    other_site.register("https://evil.example", &fake_reg).unwrap();
    let wrong_rp = other_site.sign_in_as_rp(LAN, "evil.example", &opts).unwrap();
    let err =
        e.dw.passkey_sign_in_finish(&fresh.post(&e.dw), &start.ceremony, &cred(wrong_rp), false).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::PasskeyNotRecognised);

    // A different key presenting the victim's user handle.
    let mut attacker = TestAuthenticator::new();
    let mut ab = Browser::lan();
    e.user("mallory", Some("mallory's password")).await;
    let s = e.dw.sign_in_password(&ab.post(&e.dw), "mallory", "mallory's password", false).await.unwrap();
    ab.take(&s.cookies);
    let start = e.dw.passkey_register_start(&ab.post(&e.dw), "mine").await.unwrap();
    let a = attacker.register(&ab.origin, &start.options).unwrap();
    e.dw.passkey_register_finish(&ab.post(&e.dw), &start.ceremony, &reg(a)).await.unwrap();
    attacker.set_user_handle(victim.id.as_bytes());
    let start = e.dw.passkey_sign_in_start(&fresh.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    let swapped = cred(attacker.sign_in(&fresh.origin, &opts).unwrap());
    assert_eq!(
        e.dw.passkey_sign_in_finish(&fresh.post(&e.dw), &start.ceremony, &swapped, false).await.unwrap_err().code(),
        ErrorCode::PasskeyNotRecognised
    );

    // No user verification (no PIN or fingerprint).
    device.user_verified = false;
    let start = e.dw.passkey_sign_in_start(&fresh.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    let unverified = cred(device.sign_in(&fresh.origin, &opts).unwrap());
    let err = e.dw.passkey_sign_in_finish(&fresh.post(&e.dw), &start.ceremony, &unverified, false).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::PasskeyNotRecognised);
    device.user_verified = true;

    // A tampered signature.
    let start = e.dw.passkey_sign_in_start(&fresh.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    let mut ans = device.sign_in(&fresh.origin, &opts).unwrap();
    let sig = ans["response"]["signature"].as_str().unwrap().to_string();
    let flipped = format!("{}{}", &sig[..sig.len() - 2], if sig.ends_with("AA") { "BA" } else { "AA" });
    ans["response"]["signature"] = flipped.into();
    let err = e.dw.passkey_sign_in_finish(&fresh.post(&e.dw), &start.ceremony, &cred(ans), false).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::PasskeyNotRecognised);

    // The real thing still works afterwards.
    assert!(passkey_sign_in(&e, &fresh, &mut device).await.is_ok());
}

fn base64url(b: &[u8]) -> String {
    use base64ct::Encoding;
    base64ct::Base64UrlUnpadded::encode_string(b)
}

#[tokio::test]
async fn a_cloned_security_key_is_caught_by_its_counter() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut device = TestAuthenticator::new();
    device.counting = true;
    let mut b = Browser::lan();
    with_passkey(&e, &mut b, &mut device).await;
    let fresh = Browser::lan();
    assert!(passkey_sign_in(&e, &fresh, &mut device).await.is_ok());
    assert!(passkey_sign_in(&e, &fresh, &mut device).await.is_ok());
    // A clone with an older counter.
    device.set_counter(0);
    assert_eq!(passkey_sign_in(&e, &fresh, &mut device).await.unwrap_err().code(), ErrorCode::PasskeyNotRecognised);
}

#[tokio::test]
async fn the_same_passkey_cant_be_registered_twice() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut device = TestAuthenticator::new();
    let mut b = Browser::lan();
    with_passkey(&e, &mut b, &mut device).await;
    // The options exclude the passkey already there; the device refuses.
    let start = e.dw.passkey_register_start(&b.post(&e.dw), "again").await.unwrap();
    assert!(device.register(&b.origin, &start.options).is_err());
}

#[tokio::test]
async fn passkeys_work_only_where_they_were_made() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut device = TestAuthenticator::new();
    let mut lan = Browser::lan();
    with_passkey(&e, &mut lan, &mut device).await;
    // At the public name the device has nothing for that site.
    let public = Browser::public("198.51.100.7");
    let start = e.dw.passkey_sign_in_start(&public.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    assert!(device.sign_in(&public.origin, &opts).is_err());
    // Forcing the LAN credential onto the public address fails too.
    let forced = cred(device.sign_in_as_rp(PUBLIC, "pc.lan", &opts).unwrap());
    let err = e.dw.passkey_sign_in_finish(&public.post(&e.dw), &start.ceremony, &forced, false).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::PasskeyNotRecognised);
    let me = e.dw.require_session(&lan.get(&e.dw)).await.unwrap();
    let list = e.dw.passkeys(&public.get(&e.dw), &me).await.unwrap();
    assert!(!list[0].here, "listed as not working at the public address");
}

#[tokio::test]
async fn passkeys_are_refused_where_turned_off() {
    let e = env_with(|b| b.address(doorward::Address::new("https://192.168.1.5:8040").unwrap())).await;
    let mut b = Browser::lan();
    b.origin = "https://192.168.1.5:8040".into();
    assert!(matches!(e.dw.passkey_sign_in_start(&b.post(&e.dw)).await, Err(Error::PasskeysUnavailableHere)));
}

#[tokio::test]
async fn confirming_with_a_passkey() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut device = TestAuthenticator::new();
    let mut b = Browser::lan();
    with_passkey(&e, &mut b, &mut device).await;
    e.clock.advance(Duration::from_secs(11 * 60));
    let me = e.dw.require_session(&b.get(&e.dw)).await.unwrap();
    assert!(!e.dw.is_recent(&me));
    let start = e.dw.passkey_confirm_start(&b.post(&e.dw)).await.unwrap();
    let opts = serde_json::to_value(&start.options).unwrap();
    assert!(opts["publicKey"]["allowCredentials"].as_array().is_some_and(|a| a.len() == 1));
    let ans = cred(device.sign_in(&b.origin, &opts).unwrap());
    let me = e.dw.passkey_confirm_finish(&b.post(&e.dw), &start.ceremony, &ans).await.unwrap();
    assert!(e.dw.is_recent(&me));
}

#[tokio::test]
async fn the_last_way_in_cant_be_removed() {
    use doorward::store::{PasskeyRecord, Store};
    let e = env_with(|b| {
        b.address(doorward::Address::new("https://keys-only.example").unwrap().passkeys(true).passwords(false))
    })
    .await;
    let u = e.user("admin", Some("correct horse battery")).await;
    let mut device = TestAuthenticator::new();
    let mut lan = Browser::lan();
    with_passkey(&e, &mut lan, &mut device).await;
    let me = e.dw.require_session(&lan.get(&e.dw)).await.unwrap();
    let lan_key = e.dw.passkeys(&lan.get(&e.dw), &me).await.unwrap()[0].id;

    // Without a password, the only passkey is the only way in.
    e.dw.remove_password(u.id).await.unwrap();
    assert!(e.dw.authenticate(&lan.get(&e.dw)).await.unwrap().is_none(), "password sessions ended");
    let mut lan2 = Browser::lan();
    let s = passkey_sign_in(&e, &lan2, &mut device).await.unwrap();
    lan2.take(&s.cookies);
    let me = e.dw.require_session(&lan2.get(&e.dw)).await.unwrap();
    assert!(matches!(e.dw.remove_passkey(&lan2.post(&e.dw), &me, lan_key).await, Err(Error::LastPasskey)));

    // A passkey for the passkey-only address (made there through a one-time
    // link in a later release; written directly here).
    let only = PasskeyRecord {
        id: doorward::Uuid::new_v4(),
        user_id: u.id,
        rp_id: "keys-only.example".into(),
        cred_id: "keys-only-cred".into(),
        passkey_json: "{}".into(),
        label: "Laptop".into(),
        created_ms: T0,
        last_used_ms: None,
    };
    e.store.insert_passkey(&only).await.unwrap();
    // Its last passkey can't go: that address has no passwords.
    assert!(matches!(e.dw.remove_passkey(&lan2.post(&e.dw), &me, only.id).await, Err(Error::LastPasskey)));
    // Now the LAN one can go (the other passkey is still a way in somewhere).
    e.dw.remove_passkey(&lan2.post(&e.dw), &me, lan_key).await.unwrap();
    // Removing needs a recent sign-in.
    let second = PasskeyRecord { id: doorward::Uuid::new_v4(), cred_id: "keys-only-cred-2".into(), ..only.clone() };
    e.store.insert_passkey(&second).await.unwrap();
    e.clock.advance(Duration::from_secs(11 * 60));
    assert!(matches!(e.dw.remove_passkey(&lan2.post(&e.dw), &me, second.id).await, Err(Error::NeedsRecentSignIn)));
}

#[tokio::test]
async fn open_requests_are_capped_per_visitor() {
    let e = env().await;
    let b = Browser::public("198.51.100.7");
    let mut n = 0;
    loop {
        match e.dw.passkey_sign_in_start(&b.post(&e.dw)).await {
            Ok(_) => n += 1,
            Err(Error::TooManyAttempts { retry_after }) => {
                assert!(retry_after <= Duration::from_secs(120));
                break;
            }
            Err(other) => panic!("{other:?}"),
        }
        assert!(n <= 1000);
    }
    assert_eq!(n, 32);
    // Someone else still gets a request.
    assert!(e.dw.passkey_sign_in_start(&Browser::public("203.0.113.9").post(&e.dw)).await.is_ok());
    e.clock.advance(Duration::from_secs(120));
    assert!(e.dw.passkey_sign_in_start(&b.post(&e.dw)).await.is_ok(), "room again after expiry");
}

#[tokio::test]
async fn admin_reset_removes_every_passkey() {
    let e = env().await;
    let u = e.user("admin", Some("correct horse battery")).await;
    let mut device = TestAuthenticator::new();
    let mut b = Browser::lan();
    with_passkey(&e, &mut b, &mut device).await;
    let mut pk = Browser::lan();
    let s = passkey_sign_in(&e, &pk, &mut device).await.unwrap();
    pk.take(&s.cookies);
    assert_eq!(e.dw.remove_all_passkeys(u.id).await.unwrap(), 1);
    assert!(e.dw.user_passkeys(u.id).await.unwrap().is_empty());
    assert!(e.dw.authenticate(&pk.get(&e.dw)).await.unwrap().is_none(), "passkey sessions end");
    assert!(e.dw.authenticate(&b.get(&e.dw)).await.unwrap().is_some(), "password sessions stay");
}
