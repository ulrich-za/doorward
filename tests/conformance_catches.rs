//! The store conformance suite must catch a store that mixes users up: a
//! store whose per-user session queries ignore the user would let one user
//! end another's sessions.

#![cfg(feature = "test-util")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use async_trait::async_trait;
use doorward::Uuid;
use doorward::store::*;

struct IgnoresTheUser(MemoryStore);

#[async_trait]
impl Store for IgnoresTheUser {
    async fn migrate(&self) -> Result<(), StoreError> {
        self.0.migrate().await
    }
    async fn meta_get(&self, k: &str) -> Result<Option<String>, StoreError> {
        self.0.meta_get(k).await
    }
    async fn meta_set(&self, k: &str, v: &str) -> Result<(), StoreError> {
        self.0.meta_set(k, v).await
    }
    async fn insert_user(&self, u: &UserRecord) -> Result<(), StoreError> {
        self.0.insert_user(u).await
    }
    async fn user(&self, id: Uuid) -> Result<Option<UserRecord>, StoreError> {
        self.0.user(id).await
    }
    async fn user_by_key(&self, k: &str) -> Result<Option<UserRecord>, StoreError> {
        self.0.user_by_key(k).await
    }
    async fn users(&self) -> Result<Vec<UserRecord>, StoreError> {
        self.0.users().await
    }
    async fn update_user(&self, u: &UserRecord) -> Result<bool, StoreError> {
        self.0.update_user(u).await
    }
    async fn set_roles(&self, id: Uuid, r: &[String]) -> Result<bool, StoreError> {
        self.0.set_roles(id, r).await
    }
    async fn delete_user(&self, id: Uuid) -> Result<bool, StoreError> {
        self.0.delete_user(id).await
    }
    async fn password(&self, id: Uuid) -> Result<Option<String>, StoreError> {
        self.0.password(id).await
    }
    async fn set_password(&self, id: Uuid, p: &str, t: i64) -> Result<(), StoreError> {
        self.0.set_password(id, p, t).await
    }
    async fn replace_password(&self, id: Uuid, o: &str, n: &str, t: i64) -> Result<bool, StoreError> {
        self.0.replace_password(id, o, n, t).await
    }
    async fn remove_password(&self, id: Uuid) -> Result<bool, StoreError> {
        self.0.remove_password(id).await
    }
    async fn insert_session(&self, s: &SessionRecord) -> Result<(), StoreError> {
        self.0.insert_session(s).await
    }
    async fn session_by_token(&self, h: &[u8; 32]) -> Result<Option<SessionRecord>, StoreError> {
        self.0.session_by_token(h).await
    }
    async fn touch_session(&self, id: Uuid, t: i64, ip: Option<&str>) -> Result<(), StoreError> {
        self.0.touch_session(id, t, ip).await
    }
    async fn reauth_session(&self, id: Uuid, h: &[u8; 32], t: i64) -> Result<bool, StoreError> {
        self.0.reauth_session(id, h, t).await
    }
    async fn delete_session(&self, id: Uuid) -> Result<bool, StoreError> {
        self.0.delete_session(id).await
    }
    // Broken: both per-user session queries cover every user.
    async fn sessions_for_user(&self, _user: Uuid) -> Result<Vec<SessionRecord>, StoreError> {
        let mut all = Vec::new();
        for u in self.0.users().await? {
            all.extend(self.0.sessions_for_user(u.id).await?);
        }
        all.sort_by_key(|s| std::cmp::Reverse(s.created_ms));
        Ok(all)
    }
    async fn delete_sessions_for_user(&self, _user: Uuid, keep: Option<Uuid>) -> Result<u64, StoreError> {
        let mut n = 0;
        for u in self.0.users().await? {
            n += self.0.delete_sessions_for_user(u.id, keep).await?;
        }
        Ok(n)
    }
    async fn prune_sessions(&self, t: i64) -> Result<u64, StoreError> {
        self.0.prune_sessions(t).await
    }
    async fn insert_remembered(&self, r: &RememberedRecord) -> Result<(), StoreError> {
        self.0.insert_remembered(r).await
    }
    async fn remembered(&self, h: &[u8; 32]) -> Result<Option<RememberedRecord>, StoreError> {
        self.0.remembered(h).await
    }
    async fn touch_remembered(&self, h: &[u8; 32], a: i64, b: i64) -> Result<(), StoreError> {
        self.0.touch_remembered(h, a, b).await
    }
    async fn delete_remembered(&self, h: &[u8; 32]) -> Result<(), StoreError> {
        self.0.delete_remembered(h).await
    }
    async fn delete_remembered_for_user(&self, u: Uuid) -> Result<u64, StoreError> {
        self.0.delete_remembered_for_user(u).await
    }
    async fn trim_remembered(&self, u: Uuid, keep: u32) -> Result<u64, StoreError> {
        self.0.trim_remembered(u, keep).await
    }
    async fn prune_remembered(&self, t: i64) -> Result<u64, StoreError> {
        self.0.prune_remembered(t).await
    }
    async fn insert_passkey(&self, p: &PasskeyRecord) -> Result<(), StoreError> {
        self.0.insert_passkey(p).await
    }
    async fn passkeys_for_user(&self, u: Uuid) -> Result<Vec<PasskeyRecord>, StoreError> {
        self.0.passkeys_for_user(u).await
    }
    async fn passkey_used(&self, id: Uuid, j: Option<&str>, t: i64) -> Result<(), StoreError> {
        self.0.passkey_used(id, j, t).await
    }
    async fn rename_passkey(&self, id: Uuid, u: Uuid, l: &str) -> Result<bool, StoreError> {
        self.0.rename_passkey(id, u, l).await
    }
    async fn delete_passkey(&self, id: Uuid, u: Uuid) -> Result<bool, StoreError> {
        self.0.delete_passkey(id, u).await
    }
    async fn insert_event(&self, e: &EventRecord) -> Result<(), StoreError> {
        self.0.insert_event(e).await
    }
    async fn events_for_user(&self, u: Uuid, l: u32) -> Result<Vec<EventRecord>, StoreError> {
        self.0.events_for_user(u, l).await
    }
    async fn prune_events(&self, t: i64) -> Result<u64, StoreError> {
        self.0.prune_events(t).await
    }
}

#[tokio::test]
#[should_panic]
async fn a_store_that_mixes_users_up_fails() {
    doorward::testing::conformance::run(&IgnoresTheUser(MemoryStore::new())).await;
}

#[tokio::test]
async fn the_memory_store_passes() {
    doorward::testing::conformance::run(&MemoryStore::new()).await;
}
