//! Password sign-in, sessions, addresses, rate limits and accounts, end to end
//! against the in-memory store.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use doorward::store::Store;
use doorward::{Error, ErrorCode, Limits, NewUser, PasswordRules, SessionLengths};
use http::Method;
use std::time::Duration;

#[tokio::test]
async fn sign_in_sign_out() {
    let e = env().await;
    let u = e.user("Admin", Some("correct horse battery")).await;
    let mut b = Browser::lan();

    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    assert_eq!(s.session.user.id, u.id);
    assert_eq!(s.session.address, LAN);
    let cookie = s.cookies[0].as_str().to_string();
    assert!(cookie.starts_with("__Host-doorward="), "{cookie}");
    for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
        assert!(cookie.contains(attr), "{attr} in {cookie}");
    }
    assert!(!cookie.contains("Max-Age"), "not ticked: a browser-session cookie");
    assert!(!format!("{:?}", s.cookies).contains(&cookie[16..30]), "Debug hides cookie values");
    b.take(&s.cookies);
    assert!(b.jar.contains_key("__Host-doorward-device"));

    let me = e.dw.authenticate(&b.get(&e.dw)).await.unwrap().expect("signed in");
    assert_eq!(me.user.username, "Admin");
    assert!(e.dw.is_recent(&me));

    let clear = e.dw.sign_out(&b.post(&e.dw)).await.unwrap();
    assert!(clear.as_str().contains("Max-Age=0"));
    let stale = b.clone();
    b.take(&[clear]);
    assert!(!b.has_session());
    assert!(e.dw.authenticate(&stale.get(&e.dw)).await.unwrap().is_none(), "the old cookie is dead server-side");
}

#[tokio::test]
async fn wrong_password_and_unknown_user_look_the_same() {
    let e = env().await;
    let u = e.user("admin", Some("correct horse battery")).await;
    let b = Browser::lan();
    let wrong = e.dw.sign_in_password(&b.post(&e.dw), "admin", "nope", false).await.unwrap_err();
    let unknown = e.dw.sign_in_password(&b.post(&e.dw), "nobody", "nope", false).await.unwrap_err();
    assert_eq!(wrong.code(), ErrorCode::InvalidCredentials);
    assert_eq!(unknown.code(), ErrorCode::InvalidCredentials);
    assert_eq!(wrong.to_string(), unknown.to_string());
    // Case and full-width forms find the same account.
    assert!(e.dw.sign_in_password(&b.post(&e.dw), "ＡＤＭＩＮ", "correct horse battery", false).await.is_ok());
    // The owner can see the failed attempt in their log.
    let events = e.store.events_for_user(u.id, 10).await.unwrap();
    assert!(events.iter().any(|x| x.kind == "sign_in_failed" && x.ip.as_deref() == Some("192.168.1.20")));
    // Overlong input is refused without hashing.
    let long = "x".repeat(5000);
    assert_eq!(
        e.dw.sign_in_password(&b.post(&e.dw), &long, &long, false).await.unwrap_err().code(),
        ErrorCode::InvalidCredentials
    );
}

#[tokio::test]
async fn sessions_belong_to_their_address() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut lan = Browser::lan();
    let s = e.dw.sign_in_password(&lan.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    lan.take(&s.cookies);
    // Somehow carry the LAN cookie to the public address: it isn't accepted.
    let mut public = Browser::public("198.51.100.7");
    public.jar = lan.jar.clone();
    assert!(e.dw.authenticate(&public.get(&e.dw)).await.unwrap().is_none());
    // …and it still works at home.
    assert!(e.dw.authenticate(&lan.get(&e.dw)).await.unwrap().is_some());
}

#[tokio::test]
async fn addresses_are_checked() {
    let e = env().await;
    let dw = &e.dw;
    // A name that isn't on the list.
    let mut b = Browser::lan();
    b.origin = "https://evil.example".into();
    assert!(matches!(b.visit(dw, Method::GET), Err(Error::AddressNotAllowed)));
    // A LAN device that merely claims the public name.
    let mut liar = Browser::lan();
    liar.origin = PUBLIC.into();
    assert!(matches!(liar.visit(dw, Method::GET), Err(Error::AddressNotAllowed)));
    // A stranger that sends proxy headers isn't a trusted proxy.
    let mut fake_proxy = Browser::public("198.51.100.7");
    fake_proxy.via_proxy = false;
    let headers = Browser::public("198.51.100.7").headers(&Method::GET);
    let req = doorward::RequestInfo {
        peer: "203.0.113.5".parse().unwrap(),
        method: &Method::GET,
        host: None,
        headers: &headers,
    };
    assert!(matches!(dw.visit(&req), Err(Error::AddressNotAllowed)));
    // Through the proxy, the LAN name isn't reachable.
    let mut tunnelled = Browser::public("198.51.100.7");
    tunnelled.origin = LAN.into();
    assert!(matches!(tunnelled.visit(dw, Method::GET), Err(Error::AddressNotAllowed)));
    // Through the proxy over plain HTTP: refused.
    let mut h = Browser::public("198.51.100.7").headers(&Method::GET);
    h.insert("x-forwarded-proto", "http".parse().unwrap());
    let req =
        doorward::RequestInfo { peer: "127.0.0.1".parse().unwrap(), method: &Method::GET, host: None, headers: &h };
    assert!(matches!(dw.visit(&req), Err(Error::AddressNotAllowed)));
    // The real thing works, and the visitor's address is the forwarded one.
    let v = Browser::public("198.51.100.7").get(dw);
    assert_eq!(v.ip().to_string(), "198.51.100.7");
    assert_eq!(dw.address_info(&v).origin, PUBLIC);
}

#[tokio::test]
async fn cross_site_requests_are_refused() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut b = Browser::lan();
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    let mut evil = b.clone();
    evil.origin_header = Some("https://evil.example".into());
    assert!(matches!(e.dw.authenticate(&evil.post(&e.dw)).await, Err(Error::CrossOrigin)));
    assert!(matches!(
        e.dw.change_password(&evil.post(&e.dw), Some("correct horse battery"), "another long one").await,
        Err(Error::CrossOrigin)
    ));
    // Reading with GET is not a write; it still authenticates.
    assert!(e.dw.authenticate(&evil.get(&e.dw)).await.unwrap().is_some());
    // Login CSRF: signing a victim in to the attacker's account.
    let mut victim = Browser::lan();
    victim.origin_header = Some("https://evil.example".into());
    assert!(matches!(
        e.dw.sign_in_password(&victim.post(&e.dw), "admin", "correct horse battery", false).await,
        Err(Error::CrossOrigin)
    ));
}

#[tokio::test]
async fn sessions_expire() {
    let e = env_with(|b| {
        b.address(doorward::Address::new("https://short.example").unwrap().sessions(SessionLengths::new(
            Some(Duration::from_secs(1800)),
            Duration::from_secs(12 * 3600),
            false,
        )))
    })
    .await;
    e.user("admin", Some("correct horse battery")).await;
    let mut b = Browser::lan();
    b.origin = "https://short.example".into();
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    // Used every 20 minutes, it lasts until the 12-hour limit.
    for _ in 0..35 {
        e.clock.advance(Duration::from_secs(20 * 60));
        assert!(e.dw.authenticate(&b.get(&e.dw)).await.unwrap().is_some());
    }
    e.clock.advance(Duration::from_secs(20 * 60));
    assert!(e.dw.authenticate(&b.get(&e.dw)).await.unwrap().is_none(), "12 hours is the limit");
    // Idle for 30 minutes: gone.
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    e.clock.advance(Duration::from_secs(30 * 60));
    assert!(e.dw.authenticate(&b.get(&e.dw)).await.unwrap().is_none(), "idle limit");
}

#[tokio::test]
async fn keep_me_signed_in() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let b = Browser::lan();
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", true).await.unwrap();
    assert!(s.session.persistent);
    assert!(s.cookies[0].as_str().contains(&format!("Max-Age={}", 30 * 86_400)));
    assert!(s.cookies[1].as_str().contains(&format!("Max-Age={}", 180 * 86_400)), "device cookie kept too");
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    assert!(
        !s.cookies[1].as_str().contains("Max-Age"),
        "not asked to be remembered: device cookie ends with the browser"
    );
}

#[tokio::test]
async fn a_new_sign_in_replaces_a_planted_cookie() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    e.user("mallory", Some("an attacker's own secret")).await;
    // Mallory signs in and plants her session cookie in the victim's browser.
    let mut mallory = Browser::lan();
    let ms = e.dw.sign_in_password(&mallory.post(&e.dw), "mallory", "an attacker's own secret", false).await.unwrap();
    mallory.take(&ms.cookies);
    let mut victim = Browser::lan();
    victim.jar.insert("__Host-doorward".into(), mallory.jar["__Host-doorward"].clone());
    let vs = e.dw.sign_in_password(&victim.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    victim.take(&vs.cookies);
    assert_ne!(victim.jar["__Host-doorward"], mallory.jar["__Host-doorward"]);
    assert_eq!(e.dw.authenticate(&victim.get(&e.dw)).await.unwrap().unwrap().user.username, "admin");
    assert!(e.dw.authenticate(&mallory.get(&e.dw)).await.unwrap().is_none(), "the planted session ended");
}

#[tokio::test(start_paused = true)]
async fn floods_slow_only_the_flooder_and_remembered_browsers_get_through() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    // The owner signed in from home before; their browser is remembered.
    let mut owner = Browser::public("198.51.100.7");
    let s = e.dw.sign_in_password(&owner.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    owner.take(&s.cookies);
    owner.jar.remove("__Host-doorward");

    // An attacker at the owner's own address (a shared NAT) guesses away.
    let attacker = Browser::public("198.51.100.7");
    let mut refused = None;
    for _ in 0..40 {
        match e.dw.sign_in_password(&attacker.post(&e.dw), "admin", "guess", false).await {
            Err(Error::TooManyAttempts { retry_after }) => {
                refused = Some(retry_after);
                break;
            }
            Err(Error::InvalidCredentials) => e.clock.advance(Duration::from_secs(3)),
            other => panic!("{other:?}"),
        }
    }
    assert!(refused.unwrap() > Duration::from_secs(10 * 60), "refused for a while");
    assert!(
        matches!(
            e.dw.sign_in_password(&attacker.post(&e.dw), "admin", "correct horse battery", false).await,
            Err(Error::TooManyAttempts { .. })
        ),
        "even the right password, from the flooded address without the device cookie"
    );

    // The owner's remembered browser still signs in at once.
    let s = e.dw.sign_in_password(&owner.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    assert_eq!(s.session.user.username, "admin");
    // Someone elsewhere is unaffected.
    let other = Browser::public("203.0.113.50");
    assert!(matches!(
        e.dw.sign_in_password(&other.post(&e.dw), "admin", "nope", false).await,
        Err(Error::InvalidCredentials)
    ));
}

#[tokio::test]
async fn a_remembered_browser_counts_only_for_its_own_user() {
    let e = env_with(|b| {
        b.limits(Limits { visitor_burst: 1, visitor_refill: Duration::from_secs(3600), ..Limits::default() })
    })
    .await;
    e.user("admin", Some("correct horse battery")).await;
    e.user("other", Some("a second user secret")).await;
    let mut b = Browser::lan();
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    // The visitor budget (1) is spent. admin's device cookie still works for admin…
    assert!(e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.is_ok());
    // …but not for another account.
    assert!(matches!(
        e.dw.sign_in_password(&b.post(&e.dw), "other", "a second user secret", false).await,
        Err(Error::TooManyAttempts { .. })
    ));
}

#[tokio::test]
async fn recent_sign_in_and_confirming() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut b = Browser::lan();
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    e.clock.advance(Duration::from_secs(9 * 60));
    let me = e.dw.require_session(&b.get(&e.dw)).await.unwrap();
    assert!(e.dw.require_recent(&me).is_ok());
    assert!(e.dw.recent_left(&me) <= Duration::from_secs(60));
    e.clock.advance(Duration::from_secs(61));
    let me = e.dw.require_session(&b.get(&e.dw)).await.unwrap();
    assert!(matches!(e.dw.require_recent(&me), Err(Error::NeedsRecentSignIn)));
    assert!(matches!(e.dw.end_other_sessions(&b.post(&e.dw), &me).await, Err(Error::NeedsRecentSignIn)));
    assert!(matches!(e.dw.confirm_password(&b.post(&e.dw), "wrong").await, Err(Error::InvalidCredentials)));
    let old = b.clone();
    let confirmed = e.dw.confirm_password(&b.post(&e.dw), "correct horse battery").await.unwrap();
    assert!(e.dw.is_recent(&confirmed.session));
    b.take(&confirmed.cookies);
    // Re-authenticating issues a new cookie; the old value stops working.
    assert_ne!(old.jar["__Host-doorward"], b.jar["__Host-doorward"]);
    assert!(e.dw.authenticate(&old.get(&e.dw)).await.unwrap().is_none());
    let me = e.dw.require_session(&b.get(&e.dw)).await.unwrap();
    assert!(e.dw.is_recent(&me), "saved");
    assert_eq!(me.id, confirmed.session.id, "the same session");
    assert_eq!(e.dw.end_other_sessions(&b.post(&e.dw), &me).await.unwrap(), 0);
}

#[tokio::test]
async fn changing_a_password_needs_the_current_one() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut b = Browser::lan();
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    for current in [None, Some("wrong")] {
        let err = e.dw.change_password(&b.post(&e.dw), current, "a new long password").await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidCredentials, "{current:?}");
    }
    // Even long after signing in, the current password is enough.
    e.clock.advance(Duration::from_secs(3600));
    let old = b.clone();
    let s = e.dw.change_password(&b.post(&e.dw), Some("correct horse battery"), "a new long password").await.unwrap();
    b.take(&s.cookies);
    assert!(e.dw.authenticate(&old.get(&e.dw)).await.unwrap().is_none(), "a new cookie after the change");
    assert!(e.dw.authenticate(&b.get(&e.dw)).await.unwrap().is_some());
    let fresh = Browser::lan();
    assert!(e.dw.sign_in_password(&fresh.post(&e.dw), "admin", "a new long password", false).await.is_ok());
}

#[tokio::test]
async fn easy_passwords_are_refused() {
    let e = env_with(|b| b.refuse_password_words(["pingrail", "Northwind", "abc"])).await;
    let u = e.user("ulrich", Some("correct horse battery")).await;
    for (pw, code) in [
        ("password", ErrorCode::PasswordTooCommon),
        ("PASSWORD", ErrorCode::PasswordTooCommon),
        ("1qaz2wsx", ErrorCode::PasswordTooCommon),
        ("my name is ulrich!", ErrorCode::PasswordTooCommon),
        ("pingrail-admin-2026", ErrorCode::PasswordTooCommon),
        ("northwind rocks", ErrorCode::PasswordTooCommon),
        ("short", ErrorCode::PasswordTooShort),
    ] {
        assert_eq!(e.dw.set_password(u.id, pw).await.unwrap_err().code(), code, "{pw}");
    }
    // Short words are ignored; character classes are never required.
    assert!(e.dw.set_password(u.id, "abcdefghijklmnop").await.is_ok());
    assert!(e.dw.set_password(u.id, "\u{1F600} \u{1F680} lowercase only \u{fc}").await.is_ok());
    // 64 and more characters are fine.
    assert!(e.dw.set_password(u.id, &"z".repeat(200)).await.is_ok());
    let new = NewUser { username: "bob".into(), password: Some("football".to_string().into()), ..Default::default() };
    assert_eq!(e.dw.create_user(new).await.unwrap_err().code(), ErrorCode::PasswordTooCommon);
}

#[tokio::test]
async fn changing_a_password_ends_other_sessions() {
    let e = env().await;
    let u = e.user("admin", Some("correct horse battery")).await;
    let mut phone = Browser::lan();
    let mut laptop = Browser::public("198.51.100.7");
    let s = e.dw.sign_in_password(&phone.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    phone.take(&s.cookies);
    let s = e.dw.sign_in_password(&laptop.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    laptop.take(&s.cookies);
    let me = e.dw.require_session(&phone.get(&e.dw)).await.unwrap();
    let list = e.dw.sessions(&me).await.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list.iter().filter(|x| x.current).count(), 1);

    let s =
        e.dw.change_password(&phone.post(&e.dw), Some("correct horse battery"), "a brand new password").await.unwrap();
    phone.take(&s.cookies);
    assert!(e.dw.authenticate(&phone.get(&e.dw)).await.unwrap().is_some(), "this one stays");
    assert!(e.dw.authenticate(&laptop.get(&e.dw)).await.unwrap().is_none(), "the other ended");
    assert!(e.dw.sign_in_password(&laptop.post(&e.dw), "admin", "correct horse battery", false).await.is_err());
    // Rules for new passwords.
    let short = e.dw.change_password(&phone.post(&e.dw), Some("a brand new password"), "short").await.unwrap_err();
    assert_eq!(short.code(), ErrorCode::PasswordTooShort);
    // An admin reset ends every session.
    e.dw.set_password(u.id, "reset by the boss").await.unwrap();
    assert!(e.dw.authenticate(&phone.get(&e.dw)).await.unwrap().is_none());
    let events: Vec<String> = e.store.events_for_user(u.id, 50).await.unwrap().into_iter().map(|x| x.kind).collect();
    assert!(
        events.contains(&"password_changed".to_string()) && events.contains(&"password_set".to_string()),
        "{events:?}"
    );
}

#[tokio::test]
async fn ending_sessions() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    e.user("eve", Some("eve's own password")).await;
    let mut a = Browser::lan();
    let mut b = Browser::lan();
    let mut eve = Browser::lan();
    for (br, name, pw) in [
        (&mut a, "admin", "correct horse battery"),
        (&mut b, "admin", "correct horse battery"),
        (&mut eve, "eve", "eve's own password"),
    ] {
        let s = e.dw.sign_in_password(&br.post(&e.dw), name, pw, false).await.unwrap();
        br.take(&s.cookies);
    }
    let me = e.dw.require_session(&a.get(&e.dw)).await.unwrap();
    let eve_s = e.dw.require_session(&eve.get(&e.dw)).await.unwrap();
    // Eve can't end admin's sessions.
    assert!(matches!(e.dw.end_session(&eve.post(&e.dw), &eve_s, me.id).await, Err(Error::NotFound)));
    let other = e.dw.sessions(&me).await.unwrap().into_iter().find(|x| !x.current).unwrap();
    e.dw.end_session(&a.post(&e.dw), &me, other.id).await.unwrap();
    // After ten minutes, ending another session needs a confirmation first.
    e.clock.advance(Duration::from_secs(11 * 60));
    let stale = e.dw.require_session(&a.get(&e.dw)).await.unwrap();
    assert!(matches!(e.dw.end_other_sessions(&a.post(&e.dw), &stale).await, Err(Error::NeedsRecentSignIn)));
    let c = e.dw.confirm_password(&a.post(&e.dw), "correct horse battery").await.unwrap();
    a.take(&c.cookies);
    let me = e.dw.require_session(&a.get(&e.dw)).await.unwrap();
    assert!(e.dw.authenticate(&b.get(&e.dw)).await.unwrap().is_none());
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    assert_eq!(e.dw.end_other_sessions(&a.post(&e.dw), &me).await.unwrap(), 1);
    assert!(e.dw.authenticate(&b.get(&e.dw)).await.unwrap().is_none());
    assert!(e.dw.authenticate(&a.get(&e.dw)).await.unwrap().is_some());
    assert!(e.dw.authenticate(&eve.get(&e.dw)).await.unwrap().is_some());
}

#[tokio::test]
async fn disabled_accounts() {
    let e = env().await;
    let u = e.user("admin", Some("correct horse battery")).await;
    let mut b = Browser::lan();
    let s = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    e.dw.set_active(u.id, false).await.unwrap();
    assert!(e.dw.authenticate(&b.get(&e.dw)).await.unwrap().is_none());
    let err = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::AccountDisabled);
    // The wrong password on a disabled account still just says wrong.
    let err = e.dw.sign_in_password(&b.post(&e.dw), "admin", "wrong", false).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidCredentials);
    e.dw.set_active(u.id, true).await.unwrap();
    assert!(e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.is_ok());
}

#[tokio::test]
async fn accounts_and_names() {
    let e = env().await;
    let u = e.user("Ulrich", Some("correct horse battery")).await;
    let taken = e.dw.create_user(NewUser { username: "ulrich".into(), ..Default::default() }).await.unwrap_err();
    assert_eq!(taken.code(), ErrorCode::UsernameTaken);
    e.user("paul", None).await;
    let lookalike = e.dw.create_user(NewUser { username: "pau1".into(), ..Default::default() }).await.unwrap_err();
    assert_eq!(lookalike.code(), ErrorCode::UsernameTaken);
    let bad = e.dw.create_user(NewUser { username: "has space".into(), ..Default::default() }).await.unwrap_err();
    assert_eq!(bad.code(), ErrorCode::UsernameInvalid);
    let bad_role =
        e.dw.create_user(NewUser { username: "x".into(), roles: vec!["Admin!".into()], ..Default::default() })
            .await
            .unwrap_err();
    assert_eq!(bad_role.code(), ErrorCode::RoleInvalid);

    e.dw.set_roles(u.id, &["sales".into(), "admin".into()]).await.unwrap();
    let got = e.dw.user_by_username("ULRICH").await.unwrap().unwrap();
    assert!(got.has_role("admin") && got.has_role("sales") && !got.has_role("tech"));
    e.dw.rename_user(u.id, "ulrich.h").await.unwrap();
    assert!(e.dw.user_by_username("ulrich").await.unwrap().is_none());
    assert!(matches!(e.dw.rename_user(u.id, "PAUL").await, Err(Error::UsernameTaken)));
    e.dw.set_display_name(u.id, "  Ulrich H\u{202e}  ").await.unwrap();
    assert_eq!(e.dw.user(u.id).await.unwrap().unwrap().display_name, "Ulrich H");
    let b = Browser::lan();
    assert!(e.dw.sign_in_password(&b.post(&e.dw), "Ulrich.H", "correct horse battery", false).await.is_ok());

    // A user without a password can't sign in with one.
    let nopw = e.user("nopass", None).await;
    assert!(!e.dw.has_password(nopw.id).await.unwrap());
    assert!(e.dw.sign_in_password(&b.post(&e.dw), "nopass", "", false).await.is_err());

    e.dw.delete_user(u.id).await.unwrap();
    assert!(e.dw.user(u.id).await.unwrap().is_none());
    assert!(matches!(e.dw.delete_user(u.id).await, Err(Error::NotFound)));
}

#[tokio::test]
async fn old_hashes_are_upgraded_at_sign_in() {
    let e = env().await;
    let u = e.user("admin", Some("correct horse battery")).await;
    let before = e.store.password(u.id).await.unwrap().unwrap();
    assert!(before.contains("m=19456,t=2"));
    // The machine is retuned to other settings (here: one more pass).
    e.dw.hasher()
        .replace(doorward::password::HashPolicy { t: 3, concurrency: 2, ..doorward::password::HashPolicy::floor() })
        .unwrap();
    let b = Browser::lan();
    let _ = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    let after = e.store.password(u.id).await.unwrap().unwrap();
    assert!(after.contains("m=19456,t=3"), "{after}");
    assert!(e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.is_ok());
}

#[tokio::test]
async fn upkeep_removes_what_has_expired() {
    let e = env().await;
    let u = e.user("admin", Some("correct horse battery")).await;
    let b = Browser::lan();
    let _ = e.dw.sign_in_password(&b.post(&e.dw), "admin", "correct horse battery", false).await.unwrap();
    assert_eq!(e.store.sessions_for_user(u.id).await.unwrap().len(), 1);
    e.clock.advance(Duration::from_secs(13 * 3600));
    e.dw.upkeep().await.unwrap();
    assert!(e.store.sessions_for_user(u.id).await.unwrap().is_empty());
    e.clock.advance(Duration::from_secs(91 * 86_400));
    e.dw.upkeep().await.unwrap();
    assert!(e.store.events_for_user(u.id, 10).await.unwrap().is_empty(), "old log lines go after 90 days");
}

#[tokio::test]
async fn configuration_is_checked() {
    use doorward::store::MemoryStore;
    use doorward::{Address, Doorward};
    let ok = || Doorward::builder(MemoryStore::new()).hash_policy(doorward::password::HashPolicy::floor());
    assert!(ok().build().await.is_err(), "no addresses");
    assert!(
        ok().address(Address::new(PUBLIC).unwrap().via_proxy()).build().await.is_err(),
        "proxy without trusted proxies"
    );
    assert!(
        ok().address(Address::new(LAN).unwrap()).address(Address::new(LAN).unwrap()).build().await.is_err(),
        "duplicate"
    );
    assert!(ok().address(Address::new(LAN).unwrap()).cookie_name("session").build().await.is_err(), "__Host- prefix");
    assert!(ok().address(Address::new(LAN).unwrap()).recent_sign_in(Duration::from_secs(5)).build().await.is_err());
    assert!(
        ok().address(Address::new(LAN).unwrap())
            .password_rules(PasswordRules { min_chars: 0, max_chars: 10, refuse_common: true })
            .build()
            .await
            .is_err()
    );
    assert!(ok().address(Address::new(LAN).unwrap()).build().await.is_ok());
}

#[tokio::test]
async fn the_hash_policy_is_tuned_once_and_saved() {
    use doorward::store::MemoryStore;
    use doorward::{Address, Doorward};
    let store = std::sync::Arc::new(MemoryStore::new());
    let dw = Doorward::builder_shared(store.clone()).address(Address::new(LAN).unwrap()).build().await.unwrap();
    let saved = store.meta_get("doorward.hash_policy").await.unwrap().expect("saved");
    assert_eq!(doorward::password::HashPolicy::from_json(&saved), Some(dw.hasher().policy()));
    let again = Doorward::builder_shared(store.clone()).address(Address::new(LAN).unwrap()).build().await.unwrap();
    assert_eq!(again.hasher().policy(), dw.hasher().policy(), "reused, not retuned");
}
