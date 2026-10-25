//! An in-memory [`Store`], for tests and examples. Everything is lost when
//! the process ends.

use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use uuid::Uuid;

use super::{EventRecord, PasskeyRecord, RememberedRecord, SessionRecord, Store, StoreError, UserRecord};

#[derive(Default)]
struct State {
    meta: HashMap<String, String>,
    users: BTreeMap<Uuid, UserRecord>,
    passwords: HashMap<Uuid, String>,
    sessions: HashMap<Uuid, SessionRecord>,
    remembered: HashMap<[u8; 32], RememberedRecord>,
    passkeys: BTreeMap<Uuid, PasskeyRecord>,
    events: Vec<EventRecord>,
    next_event: i64,
}

/// Keeps everything in memory.
#[derive(Default)]
pub struct MemoryStore {
    state: Mutex<State>,
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStore").finish_non_exhaustive()
    }
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Every change below is a single step, so a poisoned lock never
        // guards a half-made change.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn sorted_roles(roles: &[String]) -> Vec<String> {
    let mut r = roles.to_vec();
    r.sort();
    r.dedup();
    r
}

#[async_trait]
impl Store for MemoryStore {
    async fn migrate(&self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn meta_get(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.lock().meta.get(key).cloned())
    }

    async fn meta_set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.lock().meta.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn insert_user(&self, user: &UserRecord) -> Result<(), StoreError> {
        let mut s = self.lock();
        if s.users.contains_key(&user.id) {
            return Err(StoreError::Conflict("id"));
        }
        if s.users.values().any(|u| u.username_key == user.username_key) {
            return Err(StoreError::Conflict("username"));
        }
        if s.users.values().any(|u| u.username_skeleton == user.username_skeleton) {
            return Err(StoreError::Conflict("skeleton"));
        }
        let mut u = user.clone();
        u.roles = sorted_roles(&u.roles);
        s.users.insert(u.id, u);
        Ok(())
    }

    async fn user(&self, id: Uuid) -> Result<Option<UserRecord>, StoreError> {
        Ok(self.lock().users.get(&id).cloned())
    }

    async fn user_by_key(&self, key: &str) -> Result<Option<UserRecord>, StoreError> {
        Ok(self.lock().users.values().find(|u| u.username_key == key).cloned())
    }

    async fn users(&self) -> Result<Vec<UserRecord>, StoreError> {
        let mut v: Vec<UserRecord> = self.lock().users.values().cloned().collect();
        v.sort_by(|a, b| a.username_key.cmp(&b.username_key));
        Ok(v)
    }

    async fn update_user(&self, user: &UserRecord) -> Result<bool, StoreError> {
        let mut s = self.lock();
        if !s.users.contains_key(&user.id) {
            return Ok(false);
        }
        if s.users.values().any(|u| u.id != user.id && u.username_key == user.username_key) {
            return Err(StoreError::Conflict("username"));
        }
        if s.users.values().any(|u| u.id != user.id && u.username_skeleton == user.username_skeleton) {
            return Err(StoreError::Conflict("skeleton"));
        }
        if let Some(u) = s.users.get_mut(&user.id) {
            u.username = user.username.clone();
            u.username_key = user.username_key.clone();
            u.username_skeleton = user.username_skeleton.clone();
            u.display_name = user.display_name.clone();
            u.active = user.active;
        }
        Ok(true)
    }

    async fn set_roles(&self, user_id: Uuid, roles: &[String]) -> Result<bool, StoreError> {
        let mut s = self.lock();
        match s.users.get_mut(&user_id) {
            Some(u) => {
                u.roles = sorted_roles(roles);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool, StoreError> {
        let mut s = self.lock();
        if s.users.remove(&id).is_none() {
            return Ok(false);
        }
        s.passwords.remove(&id);
        s.sessions.retain(|_, x| x.user_id != id);
        s.remembered.retain(|_, x| x.user_id != id);
        s.passkeys.retain(|_, x| x.user_id != id);
        for e in s.events.iter_mut().filter(|e| e.user_id == Some(id)) {
            e.user_id = None;
        }
        Ok(true)
    }

    async fn password(&self, user_id: Uuid) -> Result<Option<String>, StoreError> {
        Ok(self.lock().passwords.get(&user_id).cloned())
    }

    async fn set_password(&self, user_id: Uuid, phc: &str, _at_ms: i64) -> Result<(), StoreError> {
        let mut s = self.lock();
        if !s.users.contains_key(&user_id) {
            return Err(StoreError::Backend("no such user".into()));
        }
        s.passwords.insert(user_id, phc.to_string());
        Ok(())
    }

    async fn replace_password(&self, user_id: Uuid, old: &str, new: &str, _at_ms: i64) -> Result<bool, StoreError> {
        let mut s = self.lock();
        match s.passwords.get_mut(&user_id) {
            Some(p) if p == old => {
                *p = new.to_string();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn remove_password(&self, user_id: Uuid) -> Result<bool, StoreError> {
        Ok(self.lock().passwords.remove(&user_id).is_some())
    }

    async fn insert_session(&self, session: &SessionRecord) -> Result<(), StoreError> {
        let mut s = self.lock();
        if !s.users.contains_key(&session.user_id) {
            return Err(StoreError::Backend("no such user".into()));
        }
        if s.sessions.contains_key(&session.id) || s.sessions.values().any(|x| x.token_hash == session.token_hash) {
            return Err(StoreError::Conflict("session"));
        }
        s.sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn session_by_token(&self, token_hash: &[u8; 32]) -> Result<Option<SessionRecord>, StoreError> {
        Ok(self.lock().sessions.values().find(|x| &x.token_hash == token_hash).cloned())
    }

    async fn touch_session(&self, id: Uuid, last_seen_ms: i64, ip: Option<&str>) -> Result<(), StoreError> {
        if let Some(x) = self.lock().sessions.get_mut(&id) {
            x.last_seen_ms = last_seen_ms;
            x.ip = ip.map(String::from);
        }
        Ok(())
    }

    async fn reauth_session(&self, id: Uuid, token_hash: &[u8; 32], auth_ms: i64) -> Result<bool, StoreError> {
        let mut s = self.lock();
        if s.sessions.values().any(|x| &x.token_hash == token_hash) {
            return Err(StoreError::Conflict("session"));
        }
        match s.sessions.get_mut(&id) {
            Some(x) => {
                x.token_hash = *token_hash;
                x.auth_ms = auth_ms;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_session(&self, id: Uuid) -> Result<bool, StoreError> {
        Ok(self.lock().sessions.remove(&id).is_some())
    }

    async fn sessions_for_user(&self, user_id: Uuid) -> Result<Vec<SessionRecord>, StoreError> {
        let mut v: Vec<SessionRecord> =
            self.lock().sessions.values().filter(|x| x.user_id == user_id).cloned().collect();
        v.sort_by(|a, b| b.created_ms.cmp(&a.created_ms).then(a.id.cmp(&b.id)));
        Ok(v)
    }

    async fn delete_sessions_for_user(&self, user_id: Uuid, keep: Option<Uuid>) -> Result<u64, StoreError> {
        let mut s = self.lock();
        let before = s.sessions.len();
        s.sessions.retain(|id, x| x.user_id != user_id || Some(*id) == keep);
        Ok((before - s.sessions.len()) as u64)
    }

    async fn prune_sessions(&self, now_ms: i64) -> Result<u64, StoreError> {
        let mut s = self.lock();
        let before = s.sessions.len();
        s.sessions.retain(|_, x| x.expires_ms() > now_ms);
        Ok((before - s.sessions.len()) as u64)
    }

    async fn insert_remembered(&self, r: &RememberedRecord) -> Result<(), StoreError> {
        let mut s = self.lock();
        if !s.users.contains_key(&r.user_id) {
            return Err(StoreError::Backend("no such user".into()));
        }
        s.remembered.insert(r.token_hash, r.clone());
        Ok(())
    }

    async fn remembered(&self, token_hash: &[u8; 32]) -> Result<Option<RememberedRecord>, StoreError> {
        Ok(self.lock().remembered.get(token_hash).cloned())
    }

    async fn touch_remembered(
        &self,
        token_hash: &[u8; 32],
        last_used_ms: i64,
        expires_ms: i64,
    ) -> Result<(), StoreError> {
        if let Some(r) = self.lock().remembered.get_mut(token_hash) {
            r.last_used_ms = last_used_ms;
            r.expires_ms = expires_ms;
        }
        Ok(())
    }

    async fn delete_remembered(&self, token_hash: &[u8; 32]) -> Result<(), StoreError> {
        self.lock().remembered.remove(token_hash);
        Ok(())
    }

    async fn delete_remembered_for_user(&self, user_id: Uuid) -> Result<u64, StoreError> {
        let mut s = self.lock();
        let before = s.remembered.len();
        s.remembered.retain(|_, r| r.user_id != user_id);
        Ok((before - s.remembered.len()) as u64)
    }

    async fn trim_remembered(&self, user_id: Uuid, keep: u32) -> Result<u64, StoreError> {
        let mut s = self.lock();
        let mut mine: Vec<(i64, [u8; 32])> =
            s.remembered.values().filter(|r| r.user_id == user_id).map(|r| (r.created_ms, r.token_hash)).collect();
        mine.sort_unstable_by(|a, b| b.cmp(a));
        let forget: Vec<[u8; 32]> = mine.into_iter().skip(keep as usize).map(|(_, h)| h).collect();
        for h in &forget {
            s.remembered.remove(h);
        }
        Ok(forget.len() as u64)
    }

    async fn prune_remembered(&self, now_ms: i64) -> Result<u64, StoreError> {
        let mut s = self.lock();
        let before = s.remembered.len();
        s.remembered.retain(|_, r| r.expires_ms > now_ms);
        Ok((before - s.remembered.len()) as u64)
    }

    async fn insert_passkey(&self, p: &PasskeyRecord) -> Result<(), StoreError> {
        let mut s = self.lock();
        if !s.users.contains_key(&p.user_id) {
            return Err(StoreError::Backend("no such user".into()));
        }
        if s.passkeys.values().any(|x| x.cred_id == p.cred_id) {
            return Err(StoreError::Conflict("cred_id"));
        }
        if s.passkeys.contains_key(&p.id) {
            return Err(StoreError::Conflict("id"));
        }
        s.passkeys.insert(p.id, p.clone());
        Ok(())
    }

    async fn passkeys_for_user(&self, user_id: Uuid) -> Result<Vec<PasskeyRecord>, StoreError> {
        let mut v: Vec<PasskeyRecord> =
            self.lock().passkeys.values().filter(|p| p.user_id == user_id).cloned().collect();
        v.sort_by(|a, b| a.created_ms.cmp(&b.created_ms).then(a.id.cmp(&b.id)));
        Ok(v)
    }

    async fn passkey_used(&self, id: Uuid, passkey_json: Option<&str>, at_ms: i64) -> Result<(), StoreError> {
        if let Some(p) = self.lock().passkeys.get_mut(&id) {
            p.last_used_ms = Some(at_ms);
            if let Some(j) = passkey_json {
                p.passkey_json = j.to_string();
            }
        }
        Ok(())
    }

    async fn rename_passkey(&self, id: Uuid, user_id: Uuid, label: &str) -> Result<bool, StoreError> {
        match self.lock().passkeys.get_mut(&id) {
            Some(p) if p.user_id == user_id => {
                p.label = label.to_string();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn delete_passkey(&self, id: Uuid, user_id: Uuid) -> Result<bool, StoreError> {
        let mut s = self.lock();
        match s.passkeys.get(&id) {
            Some(p) if p.user_id == user_id => {
                s.passkeys.remove(&id);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn insert_event(&self, e: &EventRecord) -> Result<(), StoreError> {
        let mut s = self.lock();
        s.next_event += 1;
        let mut e = e.clone();
        e.id = s.next_event;
        s.events.push(e);
        Ok(())
    }

    async fn events_for_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<EventRecord>, StoreError> {
        let s = self.lock();
        let mut v: Vec<EventRecord> = s.events.iter().filter(|e| e.user_id == Some(user_id)).cloned().collect();
        v.sort_by(|a, b| b.at_ms.cmp(&a.at_ms).then(b.id.cmp(&a.id)));
        v.truncate(limit as usize);
        Ok(v)
    }

    async fn prune_events(&self, before_ms: i64) -> Result<u64, StoreError> {
        let mut s = self.lock();
        let before = s.events.len();
        s.events.retain(|e| e.at_ms >= before_ms);
        Ok((before - s.events.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn memory_store_conforms() {
        super::super::conformance::run(&super::MemoryStore::new()).await;
    }
}
