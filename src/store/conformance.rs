//! The behaviour every [`Store`] must have, as one test suite. Store crates
//! run it against their own store:
//!
//! ```ignore
//! #[tokio::test]
//! async fn conforms() {
//!     let store = MyStore::open_for_tests().await;
//!     doorward::store::conformance::run(&store).await;
//! }
//! ```
//!
//! The suite uses fresh random names and ids, so it may share a database with
//! other data, and it can run twice against the same store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use uuid::Uuid;

use super::{EventRecord, PasskeyRecord, RememberedRecord, SessionRecord, Store, StoreError, UserRecord};

fn rand_suffix() -> String {
    crate::token::random_id().unwrap().replace(['-', '_'], "x").to_lowercase()
}

fn uuid() -> Uuid {
    crate::token::random_uuid().unwrap()
}

fn hash32() -> [u8; 32] {
    let mut h = [0u8; 32];
    getrandom::fill(&mut h).unwrap();
    h
}

fn user(name: &str) -> UserRecord {
    UserRecord {
        id: uuid(),
        username: name.to_string(),
        username_key: name.to_lowercase(),
        username_skeleton: format!("sk-{}", name.to_lowercase()),
        display_name: format!("{name} display"),
        active: true,
        created_ms: 1_000,
        roles: vec!["tech".into(), "admin".into(), "tech".into()],
    }
}

fn session(user_id: Uuid, created: i64) -> SessionRecord {
    SessionRecord {
        id: uuid(),
        token_hash: hash32(),
        user_id,
        address: "https://a.example:8040".into(),
        created_ms: created,
        last_seen_ms: created,
        auth_ms: created,
        idle_ms: Some(1_000),
        max_ms: 10_000,
        persistent: true,
        method: "password".into(),
        ip: Some("192.0.2.1".into()),
        user_agent: Some("Test/1.0".into()),
    }
}

/// Run every check against `store`. Panics on the first difference.
pub async fn run<S: Store + ?Sized>(store: &S) {
    store.migrate().await.unwrap();
    store.migrate().await.expect("migrate twice");
    meta(store).await;
    users(store).await;
    passwords(store).await;
    sessions(store).await;
    remembered(store).await;
    passkeys(store).await;
    events(store).await;
    deleting_a_user_takes_everything(store).await;
}

async fn meta<S: Store + ?Sized>(s: &S) {
    let k = format!("conformance.{}", rand_suffix());
    assert_eq!(s.meta_get(&k).await.unwrap(), None);
    s.meta_set(&k, "one").await.unwrap();
    s.meta_set(&k, "two").await.unwrap();
    assert_eq!(s.meta_get(&k).await.unwrap().as_deref(), Some("two"));
}

async fn users<S: Store + ?Sized>(s: &S) {
    let name = format!("Alice{}", rand_suffix());
    let mut a = user(&name);
    s.insert_user(&a).await.unwrap();
    let got = s.user(a.id).await.unwrap().expect("user by id");
    assert_eq!(got.roles, vec!["admin".to_string(), "tech".to_string()], "roles sorted and unique");
    assert_eq!(got.username, a.username);
    assert_eq!(got.display_name, a.display_name);
    assert!(got.active);
    assert_eq!(got.created_ms, 1_000);
    assert_eq!(s.user_by_key(&a.username_key).await.unwrap().map(|u| u.id), Some(a.id));
    assert_eq!(s.user_by_key("no-such-key-anywhere").await.unwrap(), None);
    assert_eq!(s.user(uuid()).await.unwrap(), None);
    assert!(s.users().await.unwrap().iter().any(|u| u.id == a.id));

    // Unique key and skeleton, whatever the id.
    let mut dup = user(&name);
    // Both the key and the skeleton collide: either may be reported.
    assert!(matches!(s.insert_user(&dup).await, Err(StoreError::Conflict("username" | "skeleton"))));
    dup.username_key = format!("other{}", rand_suffix());
    assert_eq!(s.insert_user(&dup).await, Err(StoreError::Conflict("skeleton")));
    let mut same_id = user(&format!("Bob{}", rand_suffix()));
    same_id.id = a.id;
    assert!(matches!(s.insert_user(&same_id).await, Err(StoreError::Conflict(_))));

    // Update everything but id and roles.
    a.display_name = "Alice Changed".into();
    a.active = false;
    a.username = format!("{name}X");
    a.username_key = a.username.to_lowercase();
    a.username_skeleton = format!("sk-{}", a.username_key);
    assert!(s.update_user(&a).await.unwrap());
    let got = s.user(a.id).await.unwrap().unwrap();
    assert_eq!(
        (got.display_name.as_str(), got.active, got.username.as_str()),
        ("Alice Changed", false, a.username.as_str())
    );
    assert_eq!(got.roles.len(), 2, "roles untouched by update");
    assert_eq!(s.user_by_key(&name.to_lowercase()).await.unwrap(), None, "old key gone");
    assert!(!s.update_user(&user("nobody")).await.unwrap());

    // A rename onto someone else's name conflicts.
    let b = user(&format!("Carol{}", rand_suffix()));
    s.insert_user(&b).await.unwrap();
    let mut clash = got.clone();
    clash.username_key = b.username_key.clone();
    assert_eq!(s.update_user(&clash).await, Err(StoreError::Conflict("username")));
    let mut clash = got.clone();
    clash.username_skeleton = b.username_skeleton.clone();
    assert_eq!(s.update_user(&clash).await, Err(StoreError::Conflict("skeleton")));

    assert!(s.set_roles(a.id, &["sales".into(), "sales".into(), "manager".into()]).await.unwrap());
    assert_eq!(s.user(a.id).await.unwrap().unwrap().roles, vec!["manager".to_string(), "sales".to_string()]);
    assert!(s.set_roles(a.id, &[]).await.unwrap());
    assert!(s.user(a.id).await.unwrap().unwrap().roles.is_empty());
    assert!(!s.set_roles(uuid(), &["x".into()]).await.unwrap());

    assert!(s.delete_user(b.id).await.unwrap());
    assert!(!s.delete_user(b.id).await.unwrap());
    assert_eq!(s.user(b.id).await.unwrap(), None);
}

async fn passwords<S: Store + ?Sized>(s: &S) {
    let u = user(&format!("Pw{}", rand_suffix()));
    let other = user(&format!("Pwo{}", rand_suffix()));
    s.insert_user(&u).await.unwrap();
    s.insert_user(&other).await.unwrap();
    s.set_password(other.id, "$argon2id$other", 1).await.unwrap();
    assert_eq!(s.password(u.id).await.unwrap(), None);
    s.set_password(u.id, "$argon2id$one", 1).await.unwrap();
    s.set_password(u.id, "$argon2id$two", 2).await.unwrap();
    assert_eq!(s.password(u.id).await.unwrap().as_deref(), Some("$argon2id$two"));
    assert!(!s.replace_password(u.id, "$argon2id$one", "$argon2id$three", 3).await.unwrap(), "stale old value");
    assert_eq!(s.password(u.id).await.unwrap().as_deref(), Some("$argon2id$two"));
    assert!(s.replace_password(u.id, "$argon2id$two", "$argon2id$three", 3).await.unwrap());
    assert_eq!(s.password(u.id).await.unwrap().as_deref(), Some("$argon2id$three"));
    assert!(s.remove_password(u.id).await.unwrap());
    assert!(!s.remove_password(u.id).await.unwrap());
    assert_eq!(s.password(u.id).await.unwrap(), None);
    assert!(!s.replace_password(u.id, "$argon2id$three", "x", 4).await.unwrap(), "no password to replace");
    assert!(s.set_password(uuid(), "$argon2id$x", 1).await.is_err(), "unknown user");
    assert_eq!(s.password(other.id).await.unwrap().as_deref(), Some("$argon2id$other"), "only the user's own");
}

async fn sessions<S: Store + ?Sized>(s: &S) {
    let u = user(&format!("Sess{}", rand_suffix()));
    s.insert_user(&u).await.unwrap();
    // Someone else's session, which nothing below may list or end.
    let other = user(&format!("Sesso{}", rand_suffix()));
    s.insert_user(&other).await.unwrap();
    let theirs = SessionRecord { idle_ms: None, max_ms: 1_000_000_000, ..session(other.id, 1_500) };
    s.insert_session(&theirs).await.unwrap();
    let a = session(u.id, 1_000);
    let mut b = session(u.id, 2_000);
    b.idle_ms = None;
    b.persistent = false;
    b.ip = None;
    b.user_agent = None;
    b.method = "passkey".into();
    s.insert_session(&a).await.unwrap();
    s.insert_session(&b).await.unwrap();
    assert_eq!(s.session_by_token(&a.token_hash).await.unwrap(), Some(a.clone()), "round trip");
    assert_eq!(s.session_by_token(&b.token_hash).await.unwrap(), Some(b.clone()), "round trip with nulls");
    assert_eq!(s.session_by_token(&hash32()).await.unwrap(), None);
    let mut dup = session(u.id, 3_000);
    dup.token_hash = a.token_hash;
    assert!(s.insert_session(&dup).await.is_err(), "token hashes are unique");
    assert!(s.insert_session(&session(uuid(), 1)).await.is_err(), "unknown user");

    let list = s.sessions_for_user(u.id).await.unwrap();
    assert_eq!(list.iter().map(|x| x.id).collect::<Vec<_>>(), vec![b.id, a.id], "newest first");

    s.touch_session(a.id, 1_500, Some("192.0.2.9")).await.unwrap();
    let new_hash = hash32();
    assert!(s.reauth_session(a.id, &new_hash, 1_400).await.unwrap());
    assert_eq!(s.session_by_token(&a.token_hash).await.unwrap(), None, "the old cookie no longer works");
    let got = s.session_by_token(&new_hash).await.unwrap().unwrap();
    assert_eq!((got.id, got.last_seen_ms, got.ip.as_deref(), got.auth_ms), (a.id, 1_500, Some("192.0.2.9"), 1_400));
    assert!(s.reauth_session(a.id, &b.token_hash, 1_401).await.is_err(), "token hashes stay unique");
    assert!(!s.reauth_session(uuid(), &hash32(), 1).await.unwrap());
    let a = SessionRecord { token_hash: new_hash, ..a };
    s.touch_session(a.id, 1_600, None).await.unwrap();
    assert_eq!(s.session_by_token(&a.token_hash).await.unwrap().unwrap().ip, None);

    // a: idle 1 000 from last seen 1 600 → ends at 2 600. b: max 10 000 from 2 000.
    assert_eq!(s.prune_sessions(2_599).await.unwrap(), 0);
    assert_eq!(s.prune_sessions(2_600).await.unwrap(), 1);
    assert_eq!(s.session_by_token(&a.token_hash).await.unwrap(), None);
    assert!(s.session_by_token(&b.token_hash).await.unwrap().is_some());
    assert_eq!(s.prune_sessions(12_000).await.unwrap(), 1);

    let c = session(u.id, 100);
    let d = session(u.id, 200);
    let e = session(u.id, 300);
    for x in [&c, &d, &e] {
        s.insert_session(x).await.unwrap();
    }
    assert_eq!(s.delete_sessions_for_user(u.id, Some(d.id)).await.unwrap(), 2);
    assert_eq!(s.sessions_for_user(u.id).await.unwrap().iter().map(|x| x.id).collect::<Vec<_>>(), vec![d.id]);
    assert!(s.delete_session(d.id).await.unwrap());
    assert!(!s.delete_session(d.id).await.unwrap());
    s.insert_session(&session(u.id, 400)).await.unwrap();
    assert_eq!(s.delete_sessions_for_user(u.id, None).await.unwrap(), 1);
    assert!(s.sessions_for_user(u.id).await.unwrap().is_empty());

    // Per-user queries and deletes touch only that user's sessions.
    let theirs_now = s.session_by_token(&theirs.token_hash).await.unwrap();
    assert_eq!(theirs_now.map(|x| x.id), Some(theirs.id), "someone else's session is untouched");
    assert_eq!(s.sessions_for_user(other.id).await.unwrap().iter().map(|x| x.id).collect::<Vec<_>>(), vec![theirs.id]);
    let mine = session(u.id, 500);
    s.insert_session(&mine).await.unwrap();
    assert_eq!(s.sessions_for_user(u.id).await.unwrap().iter().map(|x| x.id).collect::<Vec<_>>(), vec![mine.id]);
    assert_eq!(s.delete_sessions_for_user(other.id, None).await.unwrap(), 1);
    assert!(s.session_by_token(&mine.token_hash).await.unwrap().is_some());
    assert_eq!(s.delete_sessions_for_user(u.id, None).await.unwrap(), 1);
}

async fn remembered<S: Store + ?Sized>(s: &S) {
    let u = user(&format!("Rem{}", rand_suffix()));
    s.insert_user(&u).await.unwrap();
    let r =
        RememberedRecord { token_hash: hash32(), user_id: u.id, created_ms: 10, last_used_ms: 10, expires_ms: 1_000 };
    s.insert_remembered(&r).await.unwrap();
    assert_eq!(s.remembered(&r.token_hash).await.unwrap(), Some(r.clone()));
    // Inserting the same hash again replaces it.
    let again = RememberedRecord { created_ms: 20, last_used_ms: 20, expires_ms: 2_000, ..r.clone() };
    s.insert_remembered(&again).await.unwrap();
    assert_eq!(s.remembered(&r.token_hash).await.unwrap(), Some(again));
    s.touch_remembered(&r.token_hash, 50, 5_000).await.unwrap();
    let got = s.remembered(&r.token_hash).await.unwrap().unwrap();
    assert_eq!((got.last_used_ms, got.expires_ms), (50, 5_000));
    assert_eq!(s.prune_remembered(4_999).await.unwrap(), 0);
    assert_eq!(s.prune_remembered(5_000).await.unwrap(), 1);
    assert_eq!(s.remembered(&r.token_hash).await.unwrap(), None);

    let other = user(&format!("Remo{}", rand_suffix()));
    s.insert_user(&other).await.unwrap();
    let rec = |user_id: Uuid, created: i64| RememberedRecord {
        token_hash: hash32(),
        user_id,
        created_ms: created,
        last_used_ms: created,
        expires_ms: 9_999,
    };
    let theirs = rec(other.id, 1);
    s.insert_remembered(&theirs).await.unwrap();

    let x = rec(u.id, 1);
    let y = rec(u.id, 1);
    s.insert_remembered(&x).await.unwrap();
    s.insert_remembered(&y).await.unwrap();
    s.delete_remembered(&x.token_hash).await.unwrap();
    assert_eq!(s.remembered(&x.token_hash).await.unwrap(), None);
    assert_eq!(s.delete_remembered_for_user(u.id).await.unwrap(), 1);
    assert_eq!(s.remembered(&y.token_hash).await.unwrap(), None);
    assert!(s.remembered(&theirs.token_hash).await.unwrap().is_some(), "only the user's own are forgotten");

    // Keep the newest few.
    let five: Vec<RememberedRecord> = (1..=5).map(|i| rec(u.id, 100 * i)).collect();
    for r in &five {
        s.insert_remembered(r).await.unwrap();
    }
    assert_eq!(s.trim_remembered(u.id, 2).await.unwrap(), 3);
    for (i, r) in five.iter().enumerate() {
        assert_eq!(s.remembered(&r.token_hash).await.unwrap().is_some(), i >= 3, "the two newest stay ({i})");
    }
    assert_eq!(s.trim_remembered(u.id, 2).await.unwrap(), 0);
    assert!(s.remembered(&theirs.token_hash).await.unwrap().is_some(), "someone else's are untouched");
    assert_eq!(s.trim_remembered(u.id, 0).await.unwrap(), 2);
    assert_eq!(s.delete_remembered_for_user(other.id).await.unwrap(), 1);
}

async fn passkeys<S: Store + ?Sized>(s: &S) {
    let u = user(&format!("Pk{}", rand_suffix()));
    let other = user(&format!("Pko{}", rand_suffix()));
    s.insert_user(&u).await.unwrap();
    s.insert_user(&other).await.unwrap();
    let p = PasskeyRecord {
        id: uuid(),
        user_id: u.id,
        rp_id: "a.example".into(),
        cred_id: format!("cred-{}", rand_suffix()),
        passkey_json: "{\"v\":1}".into(),
        label: "Phone".into(),
        created_ms: 5,
        last_used_ms: None,
    };
    s.insert_passkey(&p).await.unwrap();
    let q = PasskeyRecord {
        id: uuid(),
        cred_id: format!("cred-{}", rand_suffix()),
        created_ms: 6,
        label: "Key".into(),
        ..p.clone()
    };
    s.insert_passkey(&q).await.unwrap();
    // The same credential can't be registered twice, even to someone else.
    let stolen = PasskeyRecord { id: uuid(), user_id: other.id, ..p.clone() };
    assert_eq!(s.insert_passkey(&stolen).await, Err(StoreError::Conflict("cred_id")));
    assert_eq!(s.passkeys_for_user(u.id).await.unwrap(), vec![p.clone(), q.clone()], "oldest first, round trip");
    assert!(s.passkeys_for_user(other.id).await.unwrap().is_empty());

    s.passkey_used(p.id, Some("{\"v\":2}"), 77).await.unwrap();
    s.passkey_used(q.id, None, 78).await.unwrap();
    let list = s.passkeys_for_user(u.id).await.unwrap();
    assert_eq!((list[0].passkey_json.as_str(), list[0].last_used_ms), ("{\"v\":2}", Some(77)));
    assert_eq!((list[1].passkey_json.as_str(), list[1].last_used_ms), ("{\"v\":1}", Some(78)));

    assert!(!s.rename_passkey(p.id, other.id, "Mine now").await.unwrap(), "only the owner renames");
    assert!(s.rename_passkey(p.id, u.id, "Work phone").await.unwrap());
    assert_eq!(s.passkeys_for_user(u.id).await.unwrap()[0].label, "Work phone");
    assert!(!s.delete_passkey(p.id, other.id).await.unwrap(), "only the owner removes");
    assert!(s.delete_passkey(p.id, u.id).await.unwrap());
    assert!(!s.delete_passkey(p.id, u.id).await.unwrap());
    assert_eq!(s.passkeys_for_user(u.id).await.unwrap().iter().map(|p| p.id).collect::<Vec<_>>(), vec![q.id]);
}

async fn events<S: Store + ?Sized>(s: &S) {
    let u = user(&format!("Ev{}", rand_suffix()));
    s.insert_user(&u).await.unwrap();
    let e = |at: i64, kind: &str| EventRecord {
        id: 0,
        at_ms: at,
        user_id: Some(u.id),
        kind: kind.into(),
        address: Some("https://a.example".into()),
        ip: Some("192.0.2.1".into()),
        detail: Some("{\"method\":\"password\"}".into()),
    };
    s.insert_event(&e(100, "sign_in")).await.unwrap();
    s.insert_event(&e(300, "passkey_added")).await.unwrap();
    s.insert_event(&e(200, "sign_out")).await.unwrap();
    s.insert_event(&EventRecord { user_id: None, address: None, ip: None, detail: None, ..e(250, "anonymous") })
        .await
        .unwrap();
    let other = user(&format!("Evo{}", rand_suffix()));
    s.insert_user(&other).await.unwrap();
    s.insert_event(&EventRecord { user_id: Some(other.id), ..e(150, "theirs") }).await.unwrap();
    let got = s.events_for_user(u.id, 10).await.unwrap();
    assert_eq!(got.iter().map(|x| x.kind.as_str()).collect::<Vec<_>>(), vec!["passkey_added", "sign_out", "sign_in"]);
    assert_eq!(got[2].detail.as_deref(), Some("{\"method\":\"password\"}"));
    assert!(got.iter().all(|x| x.id > 0));
    assert_eq!(s.events_for_user(u.id, 1).await.unwrap().len(), 1);
    assert!(s.prune_events(201).await.unwrap() >= 2);
    let left = s.events_for_user(u.id, 10).await.unwrap();
    assert_eq!(left.iter().map(|x| x.kind.as_str()).collect::<Vec<_>>(), vec!["passkey_added"]);
}

async fn deleting_a_user_takes_everything<S: Store + ?Sized>(s: &S) {
    let u = user(&format!("Del{}", rand_suffix()));
    s.insert_user(&u).await.unwrap();
    s.set_password(u.id, "$argon2id$x", 1).await.unwrap();
    let sess = session(u.id, 1);
    s.insert_session(&sess).await.unwrap();
    let rem =
        RememberedRecord { token_hash: hash32(), user_id: u.id, created_ms: 1, last_used_ms: 1, expires_ms: i64::MAX };
    s.insert_remembered(&rem).await.unwrap();
    let pk = PasskeyRecord {
        id: uuid(),
        user_id: u.id,
        rp_id: "a.example".into(),
        cred_id: format!("cred-{}", rand_suffix()),
        passkey_json: "{}".into(),
        label: "x".into(),
        created_ms: 1,
        last_used_ms: None,
    };
    s.insert_passkey(&pk).await.unwrap();
    s.insert_event(&EventRecord {
        id: 0,
        at_ms: i64::MAX - 1,
        user_id: Some(u.id),
        kind: "sign_in".into(),
        address: None,
        ip: None,
        detail: None,
    })
    .await
    .unwrap();

    assert!(s.delete_user(u.id).await.unwrap());
    assert_eq!(s.password(u.id).await.unwrap(), None);
    assert_eq!(s.session_by_token(&sess.token_hash).await.unwrap(), None);
    assert_eq!(s.remembered(&rem.token_hash).await.unwrap(), None);
    assert!(s.passkeys_for_user(u.id).await.unwrap().is_empty());
    assert!(s.events_for_user(u.id, 10).await.unwrap().is_empty(), "log lines lose the user id");
    // The credential id is free again.
    let again = PasskeyRecord {
        id: uuid(),
        user_id: {
            let v = user(&format!("Re{}", rand_suffix()));
            s.insert_user(&v).await.unwrap();
            v.id
        },
        ..pk
    };
    s.insert_passkey(&again).await.unwrap();
}
