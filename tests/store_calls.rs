//! How much store work requests cause: one store call for a signed-in
//! request, and none for an attempt the rate limit refuses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use async_trait::async_trait;
use common::*;
use doorward::store::*;
use doorward::{Doorward, Error, Limits, Uuid};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A MemoryStore that writes down which calls it gets.
#[derive(Default)]
struct Counting {
    inner: MemoryStore,
    calls: Mutex<Vec<&'static str>>,
}

impl Counting {
    fn note(&self, name: &'static str) {
        self.calls.lock().unwrap().push(name);
    }

    fn take(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

macro_rules! counted {
    ($( fn $name:ident(&self $(, $arg:ident: $ty:ty)*) -> $ret:ty; )*) => {
        #[async_trait]
        impl Store for Counting {
            $(
                async fn $name(&self $(, $arg: $ty)*) -> $ret {
                    self.note(stringify!($name));
                    self.inner.$name($($arg),*).await
                }
            )*
        }
    };
}

counted! {
        fn migrate(&self) -> Result<(), StoreError>;
        fn meta_get(&self, k: &str) -> Result<Option<String>, StoreError>;
        fn meta_set(&self, k: &str, v: &str) -> Result<(), StoreError>;
        fn insert_user(&self, u: &UserRecord) -> Result<(), StoreError>;
        fn user(&self, id: Uuid) -> Result<Option<UserRecord>, StoreError>;
        fn user_by_key(&self, k: &str) -> Result<Option<UserRecord>, StoreError>;
        fn users(&self) -> Result<Vec<UserRecord>, StoreError>;
        fn update_user(&self, u: &UserRecord) -> Result<bool, StoreError>;
        fn set_roles(&self, id: Uuid, r: &[String]) -> Result<bool, StoreError>;
        fn delete_user(&self, id: Uuid) -> Result<bool, StoreError>;
        fn password(&self, id: Uuid) -> Result<Option<String>, StoreError>;
        fn set_password(&self, id: Uuid, p: &str, t: i64) -> Result<(), StoreError>;
        fn replace_password(&self, id: Uuid, o: &str, n: &str, t: i64) -> Result<bool, StoreError>;
        fn remove_password(&self, id: Uuid) -> Result<bool, StoreError>;
        fn insert_session(&self, s: &SessionRecord) -> Result<(), StoreError>;
        fn session_by_token(&self, h: &[u8; 32]) -> Result<Option<SessionRecord>, StoreError>;
        fn session_with_user(&self, h: &[u8; 32]) -> Result<Option<(SessionRecord, Option<UserRecord>)>, StoreError>;
        fn touch_session(&self, id: Uuid, t: i64, ip: Option<&str>) -> Result<(), StoreError>;
        fn reauth_session(&self, id: Uuid, h: &[u8; 32], t: i64) -> Result<bool, StoreError>;
        fn delete_session(&self, id: Uuid) -> Result<bool, StoreError>;
        fn sessions_for_user(&self, u: Uuid) -> Result<Vec<SessionRecord>, StoreError>;
        fn delete_sessions_for_user(&self, u: Uuid, keep: Option<Uuid>) -> Result<u64, StoreError>;
        fn prune_sessions(&self, t: i64) -> Result<u64, StoreError>;
        fn insert_remembered(&self, r: &RememberedRecord) -> Result<(), StoreError>;
        fn remembered(&self, h: &[u8; 32]) -> Result<Option<RememberedRecord>, StoreError>;
        fn touch_remembered(&self, h: &[u8; 32], a: i64, b: i64) -> Result<(), StoreError>;
        fn delete_remembered(&self, h: &[u8; 32]) -> Result<(), StoreError>;
        fn delete_remembered_for_user(&self, u: Uuid) -> Result<u64, StoreError>;
        fn trim_remembered(&self, u: Uuid, keep: u32) -> Result<u64, StoreError>;
        fn prune_remembered(&self, t: i64) -> Result<u64, StoreError>;
        fn insert_passkey(&self, p: &PasskeyRecord) -> Result<(), StoreError>;
        fn passkeys_for_user(&self, u: Uuid) -> Result<Vec<PasskeyRecord>, StoreError>;
        fn passkey_used(&self, id: Uuid, j: Option<&str>, t: i64) -> Result<(), StoreError>;
        fn rename_passkey(&self, id: Uuid, u: Uuid, l: &str) -> Result<bool, StoreError>;
        fn delete_passkey(&self, id: Uuid, u: Uuid) -> Result<bool, StoreError>;
        fn insert_event(&self, e: &EventRecord) -> Result<(), StoreError>;
        fn events_for_user(&self, u: Uuid, l: u32) -> Result<Vec<EventRecord>, StoreError>;
        fn prune_events(&self, t: i64) -> Result<u64, StoreError>;
}

async fn counted_env(limits: Limits) -> (Doorward, Arc<Counting>, doorward::ManualClock) {
    let store = Arc::new(Counting::default());
    let clock = doorward::ManualClock::new(T0);
    let dw = Doorward::builder_shared(store.clone())
        .address(doorward::Address::new(LAN).unwrap())
        .hash_policy(doorward::password::HashPolicy { concurrency: 2, ..doorward::password::HashPolicy::floor() })
        .limits(limits)
        .clock(clock.clone())
        .build()
        .await
        .unwrap();
    dw.create_user(doorward::NewUser {
        username: "admin".into(),
        password: Some("correct horse battery".to_string().into()),
        ..Default::default()
    })
    .await
    .unwrap();
    (dw, store, clock)
}

#[tokio::test]
async fn a_signed_in_request_is_one_store_call() {
    let (dw, store, clock) = counted_env(Limits::default()).await;
    let mut b = Browser::lan();
    let s = dw.sign_in_password(&b.post(&dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    store.take();
    assert!(dw.authenticate(&b.get(&dw)).await.unwrap().is_some());
    assert_eq!(store.take(), ["session_with_user"]);
    // Once a minute the session's last use is written down too.
    clock.advance(Duration::from_secs(61));
    assert!(dw.authenticate(&b.get(&dw)).await.unwrap().is_some());
    assert_eq!(store.take(), ["session_with_user", "touch_session"]);
}

#[tokio::test]
async fn with_a_remembered_browser_any_other_name_takes_the_same_steps() {
    // An account holder's own device cookie: attempts at another real
    // account and at a name that doesn't exist look alike, admitted or not.
    let limits = Limits { visitor_burst: 3, visitor_refill: Duration::from_secs(3600), ..Limits::default() };
    let (dw, store, _clock) = counted_env(limits).await;
    dw.create_user(doorward::NewUser {
        username: "other".into(),
        password: Some("a second long secret".to_string().into()),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut b = Browser::lan();
    let s = dw.sign_in_password(&b.post(&dw), "admin", "correct horse battery", false).await.unwrap();
    b.take(&s.cookies);
    b.jar.remove("__Host-doorward");
    let mut steps = Vec::new();
    for name in ["other", "nobody", "other", "nobody"] {
        store.take();
        let r = dw.sign_in_password(&b.post(&dw), name, "wrong", false).await.unwrap_err();
        steps.push((r.code(), store.take()));
    }
    assert_eq!(steps[0], steps[1], "admitted: {steps:?}");
    assert_eq!(steps[2], steps[3], "refused: {steps:?}");
    assert_eq!(steps[2].0, doorward::ErrorCode::TooManyAttempts);
    assert_eq!(steps[2].1, ["remembered", "user_by_key"]);
}

#[tokio::test]
async fn a_refused_attempt_costs_no_store_work() {
    let limits = Limits { visitor_burst: 1, visitor_refill: Duration::from_secs(3600), ..Limits::default() };
    let (dw, store, _clock) = counted_env(limits).await;
    let b = Browser::lan();
    assert!(matches!(dw.sign_in_password(&b.post(&dw), "admin", "wrong", false).await, Err(Error::InvalidCredentials)));
    store.take();
    for name in ["admin", "nobody", &"\u{fdfa}".repeat(300)] {
        assert!(matches!(
            dw.sign_in_password(&b.post(&dw), name, "wrong", false).await,
            Err(Error::TooManyAttempts { .. })
        ));
        assert!(store.take().is_empty(), "no store calls for {name:?}");
    }
}
