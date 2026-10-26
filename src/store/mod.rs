//! Where doorward keeps users, credentials, sessions and the security log.
//!
//! doorward talks to storage through the [`Store`] trait. Three come ready:
//! [`MemoryStore`] here (for tests and examples), and the `doorward-sqlite`
//! and `doorward-postgres` crates. Each keeps its own tables, prefixed
//! `auth_`, and upgrades them itself without touching the app's.
//!
//! Secrets are never stored in a usable form: passwords as Argon2id hashes,
//! session and remembered-browser tokens as their SHA-256.

mod memory;

#[cfg(any(test, feature = "test-util"))]
pub mod conformance;

use async_trait::async_trait;
use uuid::Uuid;

pub use memory::MemoryStore;

/// A store operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// A unique value is already taken; the field is named (for example
    /// `"username"`, `"skeleton"`, `"cred_id"`).
    #[error("{0} already exists")]
    Conflict(&'static str),
    /// The database failed. The text is for the log only.
    #[error("{0}")]
    Backend(String),
}

/// A user account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    /// Random and permanent; also the passkey user handle.
    pub id: Uuid,
    /// The name as written (normalised).
    pub username: String,
    /// Lowercase lookup key, unique.
    pub username_key: String,
    /// Look-alike skeleton, unique.
    pub username_skeleton: String,
    /// A name to show.
    pub display_name: String,
    /// Disabled accounts can't sign in and their sessions don't work.
    pub active: bool,
    /// When the account was made (ms since the Unix epoch).
    pub created_ms: i64,
    /// Roles, sorted and unique. Their meaning belongs to the app.
    pub roles: Vec<String>,
}

/// A signed-in session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    /// Random public id, used to list and end sessions (never the cookie).
    pub id: Uuid,
    /// SHA-256 of the cookie value.
    pub token_hash: [u8; 32],
    /// Whose session it is.
    pub user_id: Uuid,
    /// The origin it was made on; it works nowhere else.
    pub address: String,
    /// When it began.
    pub created_ms: i64,
    /// The last request that used it.
    pub last_seen_ms: i64,
    /// The last time the user proved who they are (sign-in or confirmation).
    pub auth_ms: i64,
    /// Idle limit in ms, if any.
    pub idle_ms: Option<i64>,
    /// Longest life in ms.
    pub max_ms: i64,
    /// Whether the cookie persists across browser restarts.
    pub persistent: bool,
    /// `"password"` or `"passkey"`.
    pub method: String,
    /// The visitor's address at the last request.
    pub ip: Option<String>,
    /// The browser's User-Agent at sign-in (cut short).
    pub user_agent: Option<String>,
}

impl SessionRecord {
    /// When the session ends if it isn't used again.
    pub fn expires_ms(&self) -> i64 {
        let absolute = self.created_ms.saturating_add(self.max_ms);
        match self.idle_ms {
            Some(idle) => absolute.min(self.last_seen_ms.saturating_add(idle)),
            None => absolute,
        }
    }
}

/// A remembered browser: the device cookie that lets a browser that signed
/// in before skip the per-address slow-down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RememberedRecord {
    /// SHA-256 of the cookie value.
    pub token_hash: [u8; 32],
    /// The user it was issued to.
    pub user_id: Uuid,
    /// When it was issued.
    pub created_ms: i64,
    /// When it was last used.
    pub last_used_ms: i64,
    /// When it stops working.
    pub expires_ms: i64,
}

/// A registered passkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyRecord {
    /// Random public id.
    pub id: Uuid,
    /// Whose it is.
    pub user_id: Uuid,
    /// The name it belongs to (the relying party id), such as `pc.lan`.
    pub rp_id: String,
    /// The credential id, base64url; unique across all users.
    pub cred_id: String,
    /// The credential as serialised by webauthn-rs (public key, counter…).
    pub passkey_json: String,
    /// A label the user chose.
    pub label: String,
    /// When it was added.
    pub created_ms: i64,
    /// When it last signed in.
    pub last_used_ms: Option<i64>,
}

/// One line of the security log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    /// Assigned by the store (ignored on insert).
    pub id: i64,
    /// When it happened.
    pub at_ms: i64,
    /// Whom it concerns, when known.
    pub user_id: Option<Uuid>,
    /// What happened, such as `"sign_in"` or `"passkey_added"`.
    pub kind: String,
    /// The origin it happened on.
    pub address: Option<String>,
    /// The visitor's address.
    pub ip: Option<String>,
    /// A little more detail as JSON (never secrets).
    pub detail: Option<String>,
}

/// Storage for doorward. Implementations must be safe to share between
/// threads and tasks; every method is one short operation.
#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Create or upgrade doorward's tables. Safe to run on every start and
    /// from several copies of the app at once.
    async fn migrate(&self) -> Result<(), StoreError>;

    /// A setting doorward keeps for itself (such as the hash policy).
    async fn meta_get(&self, key: &str) -> Result<Option<String>, StoreError>;
    /// Save a setting.
    async fn meta_set(&self, key: &str, value: &str) -> Result<(), StoreError>;

    /// Add a user (with roles). [`StoreError::Conflict`] names the taken field.
    async fn insert_user(&self, user: &UserRecord) -> Result<(), StoreError>;
    /// A user by id.
    async fn user(&self, id: Uuid) -> Result<Option<UserRecord>, StoreError>;
    /// A user by lookup key.
    async fn user_by_key(&self, key: &str) -> Result<Option<UserRecord>, StoreError>;
    /// All users, by username key.
    async fn users(&self) -> Result<Vec<UserRecord>, StoreError>;
    /// Change name, display name and active flag (roles and id stay). `false`
    /// when there is no such user.
    async fn update_user(&self, user: &UserRecord) -> Result<bool, StoreError>;
    /// Replace a user's roles.
    async fn set_roles(&self, user_id: Uuid, roles: &[String]) -> Result<bool, StoreError>;
    /// Remove a user and everything that is theirs (password, passkeys,
    /// sessions, remembered browsers). Their log lines lose the user id.
    async fn delete_user(&self, id: Uuid) -> Result<bool, StoreError>;

    /// A user's password hash.
    async fn password(&self, user_id: Uuid) -> Result<Option<String>, StoreError>;
    /// Set or replace a user's password hash.
    async fn set_password(&self, user_id: Uuid, phc: &str, at_ms: i64) -> Result<(), StoreError>;
    /// Replace the hash only if it is still `old` (for rehashing after
    /// sign-in without overwriting a password changed meanwhile).
    async fn replace_password(&self, user_id: Uuid, old: &str, new: &str, at_ms: i64) -> Result<bool, StoreError>;
    /// Remove a user's password.
    async fn remove_password(&self, user_id: Uuid) -> Result<bool, StoreError>;

    /// Add a session.
    async fn insert_session(&self, session: &SessionRecord) -> Result<(), StoreError>;
    /// A session by the hash of its cookie.
    async fn session_by_token(&self, token_hash: &[u8; 32]) -> Result<Option<SessionRecord>, StoreError>;
    /// A session by the hash of its cookie, with its user (`None` when the
    /// user is gone). This is the lookup behind every signed-in request:
    /// stores that can do it in one step (one query, one trip to a blocking
    /// thread) should override this default, which makes two calls.
    async fn session_with_user(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<(SessionRecord, Option<UserRecord>)>, StoreError> {
        let Some(s) = self.session_by_token(token_hash).await? else { return Ok(None) };
        let u = self.user(s.user_id).await?;
        Ok(Some((s, u)))
    }
    /// Record a request on a session.
    async fn touch_session(&self, id: Uuid, last_seen_ms: i64, ip: Option<&str>) -> Result<(), StoreError>;
    /// The user proved who they are again: give the session a new cookie
    /// (its hash) and record the time. `false` when there is no such session.
    async fn reauth_session(&self, id: Uuid, token_hash: &[u8; 32], auth_ms: i64) -> Result<bool, StoreError>;
    /// End a session. `false` when there was none.
    async fn delete_session(&self, id: Uuid) -> Result<bool, StoreError>;
    /// A user's sessions, newest first.
    async fn sessions_for_user(&self, user_id: Uuid) -> Result<Vec<SessionRecord>, StoreError>;
    /// End a user's sessions, except `keep`. Returns how many ended.
    async fn delete_sessions_for_user(&self, user_id: Uuid, keep: Option<Uuid>) -> Result<u64, StoreError>;
    /// Remove sessions that have expired by `now_ms`.
    async fn prune_sessions(&self, now_ms: i64) -> Result<u64, StoreError>;

    /// Add or replace a remembered browser.
    async fn insert_remembered(&self, r: &RememberedRecord) -> Result<(), StoreError>;
    /// A remembered browser by the hash of its cookie.
    async fn remembered(&self, token_hash: &[u8; 32]) -> Result<Option<RememberedRecord>, StoreError>;
    /// Record a use of a remembered browser and extend it.
    async fn touch_remembered(
        &self,
        token_hash: &[u8; 32],
        last_used_ms: i64,
        expires_ms: i64,
    ) -> Result<(), StoreError>;
    /// Forget one remembered browser.
    async fn delete_remembered(&self, token_hash: &[u8; 32]) -> Result<(), StoreError>;
    /// Forget all of a user's remembered browsers.
    async fn delete_remembered_for_user(&self, user_id: Uuid) -> Result<u64, StoreError>;
    /// Keep a user's `keep` newest remembered browsers (by `created_ms`) and
    /// forget the rest. Returns how many were forgotten.
    async fn trim_remembered(&self, user_id: Uuid, keep: u32) -> Result<u64, StoreError>;
    /// Remove remembered browsers that have expired by `now_ms`.
    async fn prune_remembered(&self, now_ms: i64) -> Result<u64, StoreError>;

    /// Add a passkey. [`StoreError::Conflict`] with `"cred_id"` when the
    /// credential is already registered to anyone.
    async fn insert_passkey(&self, p: &PasskeyRecord) -> Result<(), StoreError>;
    /// A user's passkeys, oldest first.
    async fn passkeys_for_user(&self, user_id: Uuid) -> Result<Vec<PasskeyRecord>, StoreError>;
    /// Record a sign-in with a passkey, and its updated state if any.
    async fn passkey_used(&self, id: Uuid, passkey_json: Option<&str>, at_ms: i64) -> Result<(), StoreError>;
    /// Rename one of `user_id`'s passkeys.
    async fn rename_passkey(&self, id: Uuid, user_id: Uuid, label: &str) -> Result<bool, StoreError>;
    /// Remove one of `user_id`'s passkeys.
    async fn delete_passkey(&self, id: Uuid, user_id: Uuid) -> Result<bool, StoreError>;

    /// Add a line to the security log.
    async fn insert_event(&self, e: &EventRecord) -> Result<(), StoreError>;
    /// A user's most recent log lines, newest first.
    async fn events_for_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<EventRecord>, StoreError>;
    /// Remove log lines older than `before_ms`.
    async fn prune_events(&self, before_ms: i64) -> Result<u64, StoreError>;
}
