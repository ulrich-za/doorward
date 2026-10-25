//! SQLite storage for [doorward](https://docs.rs/doorward).
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let store = doorward_sqlite::SqliteStore::open("/var/lib/myapp/myapp.db")?;
//! let dw = doorward::Doorward::builder(store)
//!     .address(doorward::Address::new("https://myapp.example")?)
//!     .build()
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! doorward's tables are prefixed `auth_` and upgraded by doorward, so they
//! can live in the app's own database file next to its tables. The file is
//! opened in WAL mode with foreign keys on and `secure_delete` on (deleted
//! rows are overwritten). A file this crate creates is readable by its owner
//! only (on Unix).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use doorward::store::{EventRecord, PasskeyRecord, RememberedRecord, SessionRecord, Store, StoreError, UserRecord};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// The newest schema version this crate knows.
const SCHEMA: i64 = 1;

const V1: &str = r#"
CREATE TABLE auth_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE auth_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    username_key TEXT NOT NULL UNIQUE,
    username_skeleton TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    active INTEGER NOT NULL,
    created_ms INTEGER NOT NULL
);
CREATE TABLE auth_user_roles (
    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    PRIMARY KEY (user_id, role)
);
CREATE TABLE auth_passwords (
    user_id TEXT PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
    phc TEXT NOT NULL,
    updated_ms INTEGER NOT NULL
);
CREATE TABLE auth_sessions (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    auth_ms INTEGER NOT NULL,
    idle_ms INTEGER,
    max_ms INTEGER NOT NULL,
    persistent INTEGER NOT NULL,
    method TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE INDEX auth_sessions_user ON auth_sessions(user_id);
CREATE TABLE auth_remembered (
    token_hash BLOB PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    created_ms INTEGER NOT NULL,
    last_used_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL
);
CREATE INDEX auth_remembered_user ON auth_remembered(user_id);
CREATE TABLE auth_passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    rp_id TEXT NOT NULL,
    cred_id TEXT NOT NULL UNIQUE,
    passkey TEXT NOT NULL,
    label TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    last_used_ms INTEGER
);
CREATE INDEX auth_passkeys_user ON auth_passkeys(user_id);
CREATE TABLE auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms INTEGER NOT NULL,
    user_id TEXT REFERENCES auth_users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    address TEXT,
    ip TEXT,
    detail TEXT
);
CREATE INDEX auth_events_user ON auth_events(user_id, at_ms);
CREATE INDEX auth_events_at ON auth_events(at_ms);
"#;

/// doorward's storage in an SQLite database.
#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

fn backend(e: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// Turn a unique-constraint failure into [`StoreError::Conflict`] naming
/// the field; anything else is a backend error.
fn map_err(e: rusqlite::Error) -> StoreError {
    if let rusqlite::Error::SqliteFailure(f, Some(msg)) = &e
        && f.code == rusqlite::ErrorCode::ConstraintViolation
        && msg.starts_with("UNIQUE constraint failed")
    {
        let field = if msg.contains("username_key") {
            "username"
        } else if msg.contains("username_skeleton") {
            "skeleton"
        } else if msg.contains("cred_id") {
            "cred_id"
        } else if msg.contains("auth_sessions") {
            "session"
        } else {
            "id"
        };
        return StoreError::Conflict(field);
    }
    backend(e)
}

impl SqliteStore {
    /// Open (or create) the database file at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<SqliteStore, StoreError> {
        let path = path.as_ref();
        let existed = path.exists();
        let conn = Connection::open(path).map_err(backend)?;
        if !existed {
            restrict(path)?;
        }
        SqliteStore::from_connection(conn)
    }

    /// A private database in memory, for tests.
    pub fn open_in_memory() -> Result<SqliteStore, StoreError> {
        SqliteStore::from_connection(Connection::open_in_memory().map_err(backend)?)
    }

    /// Use a connection the app opened. doorward sets WAL mode, foreign keys,
    /// `secure_delete` and a five-second busy timeout on it.
    pub fn from_connection(conn: Connection) -> Result<SqliteStore, StoreError> {
        conn.busy_timeout(std::time::Duration::from_secs(5)).map_err(backend)?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;").map_err(backend)?;
        // WAL is refused for in-memory databases; that is fine.
        let _ = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0));
        let fk: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).map_err(backend)?;
        if fk != 1 {
            return Err(backend("SQLite foreign keys can't be turned on"));
        }
        Ok(SqliteStore { conn: Arc::new(Mutex::new(conn)) })
    }

    async fn run<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            // A panic inside a statement can't leave the connection mid-
            // transaction (rusqlite rolls back on drop), so a poisoned lock is
            // still usable.
            let mut c = conn.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut c)
        })
        .await
        .map_err(backend)?
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(backend)
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

fn uuid_col(r: &Row<'_>, i: usize) -> rusqlite::Result<Uuid> {
    let s: String = r.get(i)?;
    Uuid::parse_str(&s)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Text, Box::new(e)))
}

fn hash_col(r: &Row<'_>, i: usize) -> rusqlite::Result<[u8; 32]> {
    let v: Vec<u8> = r.get(i)?;
    v.try_into().map_err(|_| rusqlite::Error::InvalidColumnType(i, "token_hash".into(), rusqlite::types::Type::Blob))
}

const USER_COLS: &str = "id, username, username_key, username_skeleton, display_name, active, created_ms";

fn user_row(r: &Row<'_>) -> rusqlite::Result<UserRecord> {
    Ok(UserRecord {
        id: uuid_col(r, 0)?,
        username: r.get(1)?,
        username_key: r.get(2)?,
        username_skeleton: r.get(3)?,
        display_name: r.get(4)?,
        active: r.get::<_, i64>(5)? != 0,
        created_ms: r.get(6)?,
        roles: Vec::new(),
    })
}

fn with_roles(c: &Connection, mut u: UserRecord) -> Result<UserRecord, StoreError> {
    let mut st =
        c.prepare_cached("SELECT role FROM auth_user_roles WHERE user_id = ?1 ORDER BY role").map_err(map_err)?;
    u.roles =
        st.query_map([u.id.to_string()], |r| r.get(0)).map_err(map_err)?.collect::<Result<_, _>>().map_err(map_err)?;
    Ok(u)
}

const SESSION_COLS: &str = "id, token_hash, user_id, address, created_ms, last_seen_ms, auth_ms, idle_ms, max_ms, persistent, method, ip, user_agent";

fn session_row(r: &Row<'_>) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        id: uuid_col(r, 0)?,
        token_hash: hash_col(r, 1)?,
        user_id: uuid_col(r, 2)?,
        address: r.get(3)?,
        created_ms: r.get(4)?,
        last_seen_ms: r.get(5)?,
        auth_ms: r.get(6)?,
        idle_ms: r.get(7)?,
        max_ms: r.get(8)?,
        persistent: r.get::<_, i64>(9)? != 0,
        method: r.get(10)?,
        ip: r.get(11)?,
        user_agent: r.get(12)?,
    })
}

fn remembered_row(r: &Row<'_>) -> rusqlite::Result<RememberedRecord> {
    Ok(RememberedRecord {
        token_hash: hash_col(r, 0)?,
        user_id: uuid_col(r, 1)?,
        created_ms: r.get(2)?,
        last_used_ms: r.get(3)?,
        expires_ms: r.get(4)?,
    })
}

fn passkey_row(r: &Row<'_>) -> rusqlite::Result<PasskeyRecord> {
    Ok(PasskeyRecord {
        id: uuid_col(r, 0)?,
        user_id: uuid_col(r, 1)?,
        rp_id: r.get(2)?,
        cred_id: r.get(3)?,
        passkey_json: r.get(4)?,
        label: r.get(5)?,
        created_ms: r.get(6)?,
        last_used_ms: r.get(7)?,
    })
}

fn set_roles_tx(tx: &Connection, user: Uuid, roles: &[String]) -> Result<(), StoreError> {
    let id = user.to_string();
    tx.execute("DELETE FROM auth_user_roles WHERE user_id = ?1", [&id]).map_err(map_err)?;
    let mut st =
        tx.prepare_cached("INSERT OR IGNORE INTO auth_user_roles (user_id, role) VALUES (?1, ?2)").map_err(map_err)?;
    for r in roles {
        st.execute(params![id, r]).map_err(map_err)?;
    }
    Ok(())
}

#[async_trait]
impl Store for SqliteStore {
    async fn migrate(&self) -> Result<(), StoreError> {
        self.run(|c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(map_err)?;
            tx.execute_batch("CREATE TABLE IF NOT EXISTS auth_schema (version INTEGER NOT NULL)").map_err(map_err)?;
            let v: Option<i64> = tx.query_row("SELECT MAX(version) FROM auth_schema", [], |r| r.get(0)).map_err(map_err)?;
            let v = v.unwrap_or(0);
            if v > SCHEMA {
                return Err(backend(format!(
                    "the database has doorward schema {v}, newer than this version knows ({SCHEMA}); upgrade doorward-sqlite"
                )));
            }
            if v < 1 {
                tx.execute_batch(V1).map_err(map_err)?;
                tx.execute("INSERT INTO auth_schema (version) VALUES (1)", []).map_err(map_err)?;
            }
            tx.commit().map_err(map_err)
        })
        .await
    }

    async fn meta_get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let key = key.to_string();
        self.run(move |c| {
            c.query_row("SELECT value FROM auth_meta WHERE key = ?1", [key], |r| r.get(0)).optional().map_err(map_err)
        })
        .await
    }

    async fn meta_set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let (key, value) = (key.to_string(), value.to_string());
        self.run(move |c| {
            c.execute(
                "INSERT INTO auth_meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn insert_user(&self, u: &UserRecord) -> Result<(), StoreError> {
        let u = u.clone();
        self.run(move |c| {
            let tx = c.transaction().map_err(map_err)?;
            tx.execute(
                &format!("INSERT INTO auth_users ({USER_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
                params![
                    u.id.to_string(),
                    u.username,
                    u.username_key,
                    u.username_skeleton,
                    u.display_name,
                    u.active as i64,
                    u.created_ms
                ],
            )
            .map_err(map_err)?;
            set_roles_tx(&tx, u.id, &u.roles)?;
            tx.commit().map_err(map_err)
        })
        .await
    }

    async fn user(&self, id: Uuid) -> Result<Option<UserRecord>, StoreError> {
        self.run(move |c| {
            let u = c
                .query_row(&format!("SELECT {USER_COLS} FROM auth_users WHERE id = ?1"), [id.to_string()], user_row)
                .optional()
                .map_err(map_err)?;
            u.map(|u| with_roles(c, u)).transpose()
        })
        .await
    }

    async fn user_by_key(&self, key: &str) -> Result<Option<UserRecord>, StoreError> {
        let key = key.to_string();
        self.run(move |c| {
            let u = c
                .query_row(&format!("SELECT {USER_COLS} FROM auth_users WHERE username_key = ?1"), [key], user_row)
                .optional()
                .map_err(map_err)?;
            u.map(|u| with_roles(c, u)).transpose()
        })
        .await
    }

    async fn users(&self) -> Result<Vec<UserRecord>, StoreError> {
        self.run(|c| {
            let mut st =
                c.prepare(&format!("SELECT {USER_COLS} FROM auth_users ORDER BY username_key")).map_err(map_err)?;
            let users: Vec<UserRecord> =
                st.query_map([], user_row).map_err(map_err)?.collect::<Result<_, _>>().map_err(map_err)?;
            users.into_iter().map(|u| with_roles(c, u)).collect()
        })
        .await
    }

    async fn update_user(&self, u: &UserRecord) -> Result<bool, StoreError> {
        let u = u.clone();
        self.run(move |c| {
            let n = c
                .execute(
                    "UPDATE auth_users SET username = ?2, username_key = ?3, username_skeleton = ?4, display_name = ?5, active = ?6 WHERE id = ?1",
                    params![u.id.to_string(), u.username, u.username_key, u.username_skeleton, u.display_name, u.active as i64],
                )
                .map_err(map_err)?;
            Ok(n > 0)
        })
        .await
    }

    async fn set_roles(&self, user_id: Uuid, roles: &[String]) -> Result<bool, StoreError> {
        let roles = roles.to_vec();
        self.run(move |c| {
            let tx = c.transaction().map_err(map_err)?;
            let exists: Option<i64> = tx
                .query_row("SELECT 1 FROM auth_users WHERE id = ?1", [user_id.to_string()], |r| r.get(0))
                .optional()
                .map_err(map_err)?;
            if exists.is_none() {
                return Ok(false);
            }
            set_roles_tx(&tx, user_id, &roles)?;
            tx.commit().map_err(map_err)?;
            Ok(true)
        })
        .await
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool, StoreError> {
        self.run(move |c| Ok(c.execute("DELETE FROM auth_users WHERE id = ?1", [id.to_string()]).map_err(map_err)? > 0))
            .await
    }

    async fn password(&self, user_id: Uuid) -> Result<Option<String>, StoreError> {
        self.run(move |c| {
            c.query_row("SELECT phc FROM auth_passwords WHERE user_id = ?1", [user_id.to_string()], |r| r.get(0))
                .optional()
                .map_err(map_err)
        })
        .await
    }

    async fn set_password(&self, user_id: Uuid, phc: &str, at_ms: i64) -> Result<(), StoreError> {
        let phc = phc.to_string();
        self.run(move |c| {
            c.execute(
                "INSERT INTO auth_passwords (user_id, phc, updated_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT(user_id) DO UPDATE SET phc = excluded.phc, updated_ms = excluded.updated_ms",
                params![user_id.to_string(), phc, at_ms],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn replace_password(&self, user_id: Uuid, old: &str, new: &str, at_ms: i64) -> Result<bool, StoreError> {
        let (old, new) = (old.to_string(), new.to_string());
        self.run(move |c| {
            let n = c
                .execute(
                    "UPDATE auth_passwords SET phc = ?3, updated_ms = ?4 WHERE user_id = ?1 AND phc = ?2",
                    params![user_id.to_string(), old, new, at_ms],
                )
                .map_err(map_err)?;
            Ok(n > 0)
        })
        .await
    }

    async fn remove_password(&self, user_id: Uuid) -> Result<bool, StoreError> {
        self.run(move |c| {
            Ok(c.execute("DELETE FROM auth_passwords WHERE user_id = ?1", [user_id.to_string()]).map_err(map_err)? > 0)
        })
        .await
    }

    async fn insert_session(&self, s: &SessionRecord) -> Result<(), StoreError> {
        let s = s.clone();
        self.run(move |c| {
            c.execute(
                &format!("INSERT INTO auth_sessions ({SESSION_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"),
                params![
                    s.id.to_string(),
                    s.token_hash.as_slice(),
                    s.user_id.to_string(),
                    s.address,
                    s.created_ms,
                    s.last_seen_ms,
                    s.auth_ms,
                    s.idle_ms,
                    s.max_ms,
                    s.persistent as i64,
                    s.method,
                    s.ip,
                    s.user_agent
                ],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn session_by_token(&self, token_hash: &[u8; 32]) -> Result<Option<SessionRecord>, StoreError> {
        let h = *token_hash;
        self.run(move |c| {
            c.query_row(
                &format!("SELECT {SESSION_COLS} FROM auth_sessions WHERE token_hash = ?1"),
                [h.as_slice()],
                session_row,
            )
            .optional()
            .map_err(map_err)
        })
        .await
    }

    async fn touch_session(&self, id: Uuid, last_seen_ms: i64, ip: Option<&str>) -> Result<(), StoreError> {
        let ip = ip.map(String::from);
        self.run(move |c| {
            c.execute(
                "UPDATE auth_sessions SET last_seen_ms = ?2, ip = ?3 WHERE id = ?1",
                params![id.to_string(), last_seen_ms, ip],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn set_session_auth(&self, id: Uuid, auth_ms: i64) -> Result<(), StoreError> {
        self.run(move |c| {
            c.execute("UPDATE auth_sessions SET auth_ms = ?2 WHERE id = ?1", params![id.to_string(), auth_ms])
                .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn delete_session(&self, id: Uuid) -> Result<bool, StoreError> {
        self.run(move |c| {
            Ok(c.execute("DELETE FROM auth_sessions WHERE id = ?1", [id.to_string()]).map_err(map_err)? > 0)
        })
        .await
    }

    async fn sessions_for_user(&self, user_id: Uuid) -> Result<Vec<SessionRecord>, StoreError> {
        self.run(move |c| {
            let mut st = c
                .prepare_cached(&format!(
                    "SELECT {SESSION_COLS} FROM auth_sessions WHERE user_id = ?1 ORDER BY created_ms DESC, id"
                ))
                .map_err(map_err)?;
            st.query_map([user_id.to_string()], session_row)
                .map_err(map_err)?
                .collect::<Result<_, _>>()
                .map_err(map_err)
        })
        .await
    }

    async fn delete_sessions_for_user(&self, user_id: Uuid, keep: Option<Uuid>) -> Result<u64, StoreError> {
        self.run(move |c| {
            let n = c
                .execute(
                    "DELETE FROM auth_sessions WHERE user_id = ?1 AND (?2 IS NULL OR id <> ?2)",
                    params![user_id.to_string(), keep.map(|k| k.to_string())],
                )
                .map_err(map_err)?;
            Ok(n as u64)
        })
        .await
    }

    async fn prune_sessions(&self, now_ms: i64) -> Result<u64, StoreError> {
        self.run(move |c| {
            let n = c
                .execute(
                    "DELETE FROM auth_sessions WHERE created_ms <= ?1 - max_ms
                     OR (idle_ms IS NOT NULL AND last_seen_ms <= ?1 - idle_ms)",
                    [now_ms],
                )
                .map_err(map_err)?;
            Ok(n as u64)
        })
        .await
    }

    async fn insert_remembered(&self, r: &RememberedRecord) -> Result<(), StoreError> {
        let r = r.clone();
        self.run(move |c| {
            c.execute(
                "INSERT INTO auth_remembered (token_hash, user_id, created_ms, last_used_ms, expires_ms) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(token_hash) DO UPDATE SET user_id = excluded.user_id, created_ms = excluded.created_ms,
                 last_used_ms = excluded.last_used_ms, expires_ms = excluded.expires_ms",
                params![r.token_hash.as_slice(), r.user_id.to_string(), r.created_ms, r.last_used_ms, r.expires_ms],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn remembered(&self, token_hash: &[u8; 32]) -> Result<Option<RememberedRecord>, StoreError> {
        let h = *token_hash;
        self.run(move |c| {
            c.query_row(
                "SELECT token_hash, user_id, created_ms, last_used_ms, expires_ms FROM auth_remembered WHERE token_hash = ?1",
                [h.as_slice()],
                remembered_row,
            )
            .optional()
            .map_err(map_err)
        })
        .await
    }

    async fn touch_remembered(
        &self,
        token_hash: &[u8; 32],
        last_used_ms: i64,
        expires_ms: i64,
    ) -> Result<(), StoreError> {
        let h = *token_hash;
        self.run(move |c| {
            c.execute(
                "UPDATE auth_remembered SET last_used_ms = ?2, expires_ms = ?3 WHERE token_hash = ?1",
                params![h.as_slice(), last_used_ms, expires_ms],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn delete_remembered(&self, token_hash: &[u8; 32]) -> Result<(), StoreError> {
        let h = *token_hash;
        self.run(move |c| {
            c.execute("DELETE FROM auth_remembered WHERE token_hash = ?1", [h.as_slice()]).map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn delete_remembered_for_user(&self, user_id: Uuid) -> Result<u64, StoreError> {
        self.run(move |c| {
            Ok(c.execute("DELETE FROM auth_remembered WHERE user_id = ?1", [user_id.to_string()]).map_err(map_err)?
                as u64)
        })
        .await
    }

    async fn prune_remembered(&self, now_ms: i64) -> Result<u64, StoreError> {
        self.run(move |c| {
            Ok(c.execute("DELETE FROM auth_remembered WHERE expires_ms <= ?1", [now_ms]).map_err(map_err)? as u64)
        })
        .await
    }

    async fn insert_passkey(&self, p: &PasskeyRecord) -> Result<(), StoreError> {
        let p = p.clone();
        self.run(move |c| {
            c.execute(
                "INSERT INTO auth_passkeys (id, user_id, rp_id, cred_id, passkey, label, created_ms, last_used_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    p.id.to_string(),
                    p.user_id.to_string(),
                    p.rp_id,
                    p.cred_id,
                    p.passkey_json,
                    p.label,
                    p.created_ms,
                    p.last_used_ms
                ],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn passkeys_for_user(&self, user_id: Uuid) -> Result<Vec<PasskeyRecord>, StoreError> {
        self.run(move |c| {
            let mut st = c
                .prepare_cached(
                    "SELECT id, user_id, rp_id, cred_id, passkey, label, created_ms, last_used_ms FROM auth_passkeys
                     WHERE user_id = ?1 ORDER BY created_ms, id",
                )
                .map_err(map_err)?;
            st.query_map([user_id.to_string()], passkey_row)
                .map_err(map_err)?
                .collect::<Result<_, _>>()
                .map_err(map_err)
        })
        .await
    }

    async fn passkey_used(&self, id: Uuid, passkey_json: Option<&str>, at_ms: i64) -> Result<(), StoreError> {
        let json = passkey_json.map(String::from);
        self.run(move |c| {
            c.execute(
                "UPDATE auth_passkeys SET last_used_ms = ?2, passkey = COALESCE(?3, passkey) WHERE id = ?1",
                params![id.to_string(), at_ms, json],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn rename_passkey(&self, id: Uuid, user_id: Uuid, label: &str) -> Result<bool, StoreError> {
        let label = label.to_string();
        self.run(move |c| {
            let n = c
                .execute(
                    "UPDATE auth_passkeys SET label = ?3 WHERE id = ?1 AND user_id = ?2",
                    params![id.to_string(), user_id.to_string(), label],
                )
                .map_err(map_err)?;
            Ok(n > 0)
        })
        .await
    }

    async fn delete_passkey(&self, id: Uuid, user_id: Uuid) -> Result<bool, StoreError> {
        self.run(move |c| {
            let n = c
                .execute(
                    "DELETE FROM auth_passkeys WHERE id = ?1 AND user_id = ?2",
                    params![id.to_string(), user_id.to_string()],
                )
                .map_err(map_err)?;
            Ok(n > 0)
        })
        .await
    }

    async fn insert_event(&self, e: &EventRecord) -> Result<(), StoreError> {
        let e = e.clone();
        self.run(move |c| {
            c.execute(
                "INSERT INTO auth_events (at_ms, user_id, kind, address, ip, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![e.at_ms, e.user_id.map(|u| u.to_string()), e.kind, e.address, e.ip, e.detail],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
    }

    async fn events_for_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<EventRecord>, StoreError> {
        self.run(move |c| {
            let mut st = c
                .prepare_cached(
                    "SELECT id, at_ms, user_id, kind, address, ip, detail FROM auth_events
                     WHERE user_id = ?1 ORDER BY at_ms DESC, id DESC LIMIT ?2",
                )
                .map_err(map_err)?;
            st.query_map(params![user_id.to_string(), limit as i64], |r| {
                let user: Option<String> = r.get(2)?;
                Ok(EventRecord {
                    id: r.get(0)?,
                    at_ms: r.get(1)?,
                    user_id: user.and_then(|u| Uuid::parse_str(&u).ok()),
                    kind: r.get(3)?,
                    address: r.get(4)?,
                    ip: r.get(5)?,
                    detail: r.get(6)?,
                })
            })
            .map_err(map_err)?
            .collect::<Result<_, _>>()
            .map_err(map_err)
        })
        .await
    }

    async fn prune_events(&self, before_ms: i64) -> Result<u64, StoreError> {
        self.run(move |c| {
            Ok(c.execute("DELETE FROM auth_events WHERE at_ms < ?1", [before_ms]).map_err(map_err)? as u64)
        })
        .await
    }
}
