//! PostgreSQL storage for [doorward](https://docs.rs/doorward), through sqlx.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let pool = sqlx::PgPool::connect("postgres://app@localhost/app").await?;
//! let dw = doorward::Doorward::builder(doorward_postgres::PostgresStore::new(pool))
//!     .address(doorward::Address::new("https://repairs.example")?)
//!     .build()
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! doorward's tables are prefixed `auth_` and upgraded by doorward (under an
//! advisory lock, so several copies of the app can start at once). The app
//! can reference `auth_users(id)` (a `uuid`) from its own tables. The pool
//! is the app's: it decides the TLS settings and connection limits.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use doorward::store::{EventRecord, PasskeyRecord, RememberedRecord, SessionRecord, Store, StoreError, UserRecord};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

/// The newest schema version this crate knows.
const SCHEMA: i64 = 1;
/// The advisory lock taken while upgrading the schema.
const MIGRATION_LOCK: i64 = 0x646f_6f72_7761_7264; // "doorward"

const V1: &[&str] = &[
    "CREATE TABLE auth_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE auth_users (
        id UUID PRIMARY KEY,
        username TEXT NOT NULL,
        username_key TEXT NOT NULL,
        username_skeleton TEXT NOT NULL,
        display_name TEXT NOT NULL,
        active BOOLEAN NOT NULL,
        created_ms BIGINT NOT NULL,
        CONSTRAINT auth_users_username_key_unique UNIQUE (username_key),
        CONSTRAINT auth_users_username_skeleton_unique UNIQUE (username_skeleton)
    )",
    "CREATE TABLE auth_user_roles (
        user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        PRIMARY KEY (user_id, role)
    )",
    "CREATE TABLE auth_passwords (
        user_id UUID PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
        phc TEXT NOT NULL,
        updated_ms BIGINT NOT NULL
    )",
    "CREATE TABLE auth_sessions (
        id UUID PRIMARY KEY,
        token_hash BYTEA NOT NULL,
        user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        address TEXT NOT NULL,
        created_ms BIGINT NOT NULL,
        last_seen_ms BIGINT NOT NULL,
        auth_ms BIGINT NOT NULL,
        idle_ms BIGINT,
        max_ms BIGINT NOT NULL,
        persistent BOOLEAN NOT NULL,
        method TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        CONSTRAINT auth_sessions_token_unique UNIQUE (token_hash)
    )",
    "CREATE INDEX auth_sessions_user ON auth_sessions(user_id)",
    "CREATE TABLE auth_remembered (
        token_hash BYTEA PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        created_ms BIGINT NOT NULL,
        last_used_ms BIGINT NOT NULL,
        expires_ms BIGINT NOT NULL
    )",
    "CREATE INDEX auth_remembered_user ON auth_remembered(user_id)",
    "CREATE TABLE auth_passkeys (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        rp_id TEXT NOT NULL,
        cred_id TEXT NOT NULL,
        passkey TEXT NOT NULL,
        label TEXT NOT NULL,
        created_ms BIGINT NOT NULL,
        last_used_ms BIGINT,
        CONSTRAINT auth_passkeys_cred_id_unique UNIQUE (cred_id)
    )",
    "CREATE INDEX auth_passkeys_user ON auth_passkeys(user_id)",
    "CREATE TABLE auth_events (
        id BIGSERIAL PRIMARY KEY,
        at_ms BIGINT NOT NULL,
        user_id UUID REFERENCES auth_users(id) ON DELETE SET NULL,
        kind TEXT NOT NULL,
        address TEXT,
        ip TEXT,
        detail TEXT
    )",
    "CREATE INDEX auth_events_user ON auth_events(user_id, at_ms)",
    "CREATE INDEX auth_events_at ON auth_events(at_ms)",
];

/// doorward's storage in a PostgreSQL database.
#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresStore").finish_non_exhaustive()
    }
}

impl PostgresStore {
    /// Use the app's connection pool.
    pub fn new(pool: PgPool) -> PostgresStore {
        PostgresStore { pool }
    }

    /// The pool, for the app's own queries.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn map_err(e: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(db) = &e
        && db.code().as_deref() == Some("23505")
    {
        let field = match db.constraint() {
            Some("auth_users_username_key_unique") => "username",
            Some("auth_users_username_skeleton_unique") => "skeleton",
            Some("auth_passkeys_cred_id_unique") => "cred_id",
            Some("auth_sessions_token_unique" | "auth_sessions_pkey") => "session",
            _ => "id",
        };
        return StoreError::Conflict(field);
    }
    StoreError::Backend(e.to_string())
}

fn hash_of(r: &PgRow, col: &str) -> Result<[u8; 32], sqlx::Error> {
    let v: Vec<u8> = r.try_get(col)?;
    v.try_into().map_err(|_| sqlx::Error::Decode(format!("{col} is not 32 bytes").into()))
}

fn user_of(r: &PgRow) -> Result<UserRecord, sqlx::Error> {
    Ok(UserRecord {
        id: r.try_get("id")?,
        username: r.try_get("username")?,
        username_key: r.try_get("username_key")?,
        username_skeleton: r.try_get("username_skeleton")?,
        display_name: r.try_get("display_name")?,
        active: r.try_get("active")?,
        created_ms: r.try_get("created_ms")?,
        roles: r.try_get::<Option<Vec<String>>, _>("roles")?.unwrap_or_default(),
    })
}

// Macros rather than constants, so every query stays a string literal
// (sqlx accepts only those for SQL text; values always go in as binds).
macro_rules! user_select {
    () => {
        "SELECT u.id, u.username, u.username_key, u.username_skeleton, u.display_name, u.active, u.created_ms,
         ARRAY(SELECT role FROM auth_user_roles r WHERE r.user_id = u.id ORDER BY role) AS roles FROM auth_users u"
    };
}

fn session_of(r: &PgRow) -> Result<SessionRecord, sqlx::Error> {
    Ok(SessionRecord {
        id: r.try_get("id")?,
        token_hash: hash_of(r, "token_hash")?,
        user_id: r.try_get("user_id")?,
        address: r.try_get("address")?,
        created_ms: r.try_get("created_ms")?,
        last_seen_ms: r.try_get("last_seen_ms")?,
        auth_ms: r.try_get("auth_ms")?,
        idle_ms: r.try_get("idle_ms")?,
        max_ms: r.try_get("max_ms")?,
        persistent: r.try_get("persistent")?,
        method: r.try_get("method")?,
        ip: r.try_get("ip")?,
        user_agent: r.try_get("user_agent")?,
    })
}

macro_rules! session_select {
    () => {
        "SELECT id, token_hash, user_id, address, created_ms, last_seen_ms, auth_ms, idle_ms, max_ms,
         persistent, method, ip, user_agent FROM auth_sessions"
    };
}

fn passkey_of(r: &PgRow) -> Result<PasskeyRecord, sqlx::Error> {
    Ok(PasskeyRecord {
        id: r.try_get("id")?,
        user_id: r.try_get("user_id")?,
        rp_id: r.try_get("rp_id")?,
        cred_id: r.try_get("cred_id")?,
        passkey_json: r.try_get("passkey")?,
        label: r.try_get("label")?,
        created_ms: r.try_get("created_ms")?,
        last_used_ms: r.try_get("last_used_ms")?,
    })
}

async fn set_roles_tx(tx: &mut Transaction<'_, Postgres>, user: Uuid, roles: &[String]) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM auth_user_roles WHERE user_id = $1").bind(user).execute(&mut **tx).await?;
    for r in roles {
        sqlx::query("INSERT INTO auth_user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(user)
            .bind(r)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

#[async_trait]
impl Store for PostgresStore {
    async fn migrate(&self) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(MIGRATION_LOCK)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS auth_schema (version BIGINT NOT NULL)")
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        let v: Option<i64> =
            sqlx::query_scalar("SELECT MAX(version) FROM auth_schema").fetch_one(&mut *tx).await.map_err(map_err)?;
        let v = v.unwrap_or(0);
        if v > SCHEMA {
            return Err(StoreError::Backend(format!(
                "the database has doorward schema {v}, newer than this version knows ({SCHEMA}); upgrade doorward-postgres"
            )));
        }
        if v < 1 {
            for stmt in V1 {
                sqlx::query(*stmt).execute(&mut *tx).await.map_err(map_err)?;
            }
            sqlx::query("INSERT INTO auth_schema (version) VALUES (1)").execute(&mut *tx).await.map_err(map_err)?;
        }
        tx.commit().await.map_err(map_err)
    }

    async fn meta_get(&self, key: &str) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar("SELECT value FROM auth_meta WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)
    }

    async fn meta_set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO auth_meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn insert_user(&self, u: &UserRecord) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        sqlx::query(
            "INSERT INTO auth_users (id, username, username_key, username_skeleton, display_name, active, created_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(u.id)
        .bind(&u.username)
        .bind(&u.username_key)
        .bind(&u.username_skeleton)
        .bind(&u.display_name)
        .bind(u.active)
        .bind(u.created_ms)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        set_roles_tx(&mut tx, u.id, &u.roles).await.map_err(map_err)?;
        tx.commit().await.map_err(map_err)
    }

    async fn user(&self, id: Uuid) -> Result<Option<UserRecord>, StoreError> {
        let row = sqlx::query(concat!(user_select!(), " WHERE u.id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        row.map(|r| user_of(&r)).transpose().map_err(map_err)
    }

    async fn user_by_key(&self, key: &str) -> Result<Option<UserRecord>, StoreError> {
        let row = sqlx::query(concat!(user_select!(), " WHERE u.username_key = $1"))
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        row.map(|r| user_of(&r)).transpose().map_err(map_err)
    }

    async fn users(&self) -> Result<Vec<UserRecord>, StoreError> {
        let rows = sqlx::query(concat!(user_select!(), " ORDER BY u.username_key"))
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?;
        rows.iter().map(user_of).collect::<Result<_, _>>().map_err(map_err)
    }

    async fn update_user(&self, u: &UserRecord) -> Result<bool, StoreError> {
        let r = sqlx::query(
            "UPDATE auth_users SET username = $2, username_key = $3, username_skeleton = $4, display_name = $5, active = $6
             WHERE id = $1",
        )
        .bind(u.id)
        .bind(&u.username)
        .bind(&u.username_key)
        .bind(&u.username_skeleton)
        .bind(&u.display_name)
        .bind(u.active)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(r.rows_affected() > 0)
    }

    async fn set_roles(&self, user_id: Uuid, roles: &[String]) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM auth_users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        if exists.is_none() {
            return Ok(false);
        }
        set_roles_tx(&mut tx, user_id, roles).await.map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool, StoreError> {
        let r =
            sqlx::query("DELETE FROM auth_users WHERE id = $1").bind(id).execute(&self.pool).await.map_err(map_err)?;
        Ok(r.rows_affected() > 0)
    }

    async fn password(&self, user_id: Uuid) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar("SELECT phc FROM auth_passwords WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)
    }

    async fn set_password(&self, user_id: Uuid, phc: &str, at_ms: i64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO auth_passwords (user_id, phc, updated_ms) VALUES ($1, $2, $3)
             ON CONFLICT (user_id) DO UPDATE SET phc = EXCLUDED.phc, updated_ms = EXCLUDED.updated_ms",
        )
        .bind(user_id)
        .bind(phc)
        .bind(at_ms)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn replace_password(&self, user_id: Uuid, old: &str, new: &str, at_ms: i64) -> Result<bool, StoreError> {
        let r = sqlx::query("UPDATE auth_passwords SET phc = $3, updated_ms = $4 WHERE user_id = $1 AND phc = $2")
            .bind(user_id)
            .bind(old)
            .bind(new)
            .bind(at_ms)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected() > 0)
    }

    async fn remove_password(&self, user_id: Uuid) -> Result<bool, StoreError> {
        let r = sqlx::query("DELETE FROM auth_passwords WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected() > 0)
    }

    async fn insert_session(&self, s: &SessionRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO auth_sessions (id, token_hash, user_id, address, created_ms, last_seen_ms, auth_ms, idle_ms, max_ms,
             persistent, method, ip, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(s.id)
        .bind(s.token_hash.as_slice())
        .bind(s.user_id)
        .bind(&s.address)
        .bind(s.created_ms)
        .bind(s.last_seen_ms)
        .bind(s.auth_ms)
        .bind(s.idle_ms)
        .bind(s.max_ms)
        .bind(s.persistent)
        .bind(&s.method)
        .bind(&s.ip)
        .bind(&s.user_agent)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn session_by_token(&self, token_hash: &[u8; 32]) -> Result<Option<SessionRecord>, StoreError> {
        let row = sqlx::query(concat!(session_select!(), " WHERE token_hash = $1"))
            .bind(token_hash.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        row.map(|r| session_of(&r)).transpose().map_err(map_err)
    }

    async fn touch_session(&self, id: Uuid, last_seen_ms: i64, ip: Option<&str>) -> Result<(), StoreError> {
        sqlx::query("UPDATE auth_sessions SET last_seen_ms = $2, ip = $3 WHERE id = $1")
            .bind(id)
            .bind(last_seen_ms)
            .bind(ip)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn reauth_session(&self, id: Uuid, token_hash: &[u8; 32], auth_ms: i64) -> Result<bool, StoreError> {
        let r = sqlx::query("UPDATE auth_sessions SET token_hash = $2, auth_ms = $3 WHERE id = $1")
            .bind(id)
            .bind(token_hash.as_slice())
            .bind(auth_ms)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected() > 0)
    }

    async fn delete_session(&self, id: Uuid) -> Result<bool, StoreError> {
        let r = sqlx::query("DELETE FROM auth_sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected() > 0)
    }

    async fn sessions_for_user(&self, user_id: Uuid) -> Result<Vec<SessionRecord>, StoreError> {
        let rows = sqlx::query(concat!(session_select!(), " WHERE user_id = $1 ORDER BY created_ms DESC, id"))
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?;
        rows.iter().map(session_of).collect::<Result<_, _>>().map_err(map_err)
    }

    async fn delete_sessions_for_user(&self, user_id: Uuid, keep: Option<Uuid>) -> Result<u64, StoreError> {
        let r = sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1 AND ($2::uuid IS NULL OR id <> $2)")
            .bind(user_id)
            .bind(keep)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected())
    }

    async fn prune_sessions(&self, now_ms: i64) -> Result<u64, StoreError> {
        // Written as subtractions so large values can't overflow BIGINT.
        let r = sqlx::query(
            "DELETE FROM auth_sessions WHERE created_ms <= $1 - max_ms
             OR (idle_ms IS NOT NULL AND last_seen_ms <= $1 - idle_ms)",
        )
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(r.rows_affected())
    }

    async fn insert_remembered(&self, r: &RememberedRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO auth_remembered (token_hash, user_id, created_ms, last_used_ms, expires_ms) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (token_hash) DO UPDATE SET user_id = EXCLUDED.user_id, created_ms = EXCLUDED.created_ms,
             last_used_ms = EXCLUDED.last_used_ms, expires_ms = EXCLUDED.expires_ms",
        )
        .bind(r.token_hash.as_slice())
        .bind(r.user_id)
        .bind(r.created_ms)
        .bind(r.last_used_ms)
        .bind(r.expires_ms)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn remembered(&self, token_hash: &[u8; 32]) -> Result<Option<RememberedRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT token_hash, user_id, created_ms, last_used_ms, expires_ms FROM auth_remembered WHERE token_hash = $1",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        row.map(|r| -> Result<RememberedRecord, sqlx::Error> {
            Ok(RememberedRecord {
                token_hash: hash_of(&r, "token_hash")?,
                user_id: r.try_get("user_id")?,
                created_ms: r.try_get("created_ms")?,
                last_used_ms: r.try_get("last_used_ms")?,
                expires_ms: r.try_get("expires_ms")?,
            })
        })
        .transpose()
        .map_err(map_err)
    }

    async fn touch_remembered(
        &self,
        token_hash: &[u8; 32],
        last_used_ms: i64,
        expires_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE auth_remembered SET last_used_ms = $2, expires_ms = $3 WHERE token_hash = $1")
            .bind(token_hash.as_slice())
            .bind(last_used_ms)
            .bind(expires_ms)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn delete_remembered(&self, token_hash: &[u8; 32]) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM auth_remembered WHERE token_hash = $1")
            .bind(token_hash.as_slice())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn delete_remembered_for_user(&self, user_id: Uuid) -> Result<u64, StoreError> {
        let r = sqlx::query("DELETE FROM auth_remembered WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected())
    }

    async fn prune_remembered(&self, now_ms: i64) -> Result<u64, StoreError> {
        let r = sqlx::query("DELETE FROM auth_remembered WHERE expires_ms <= $1")
            .bind(now_ms)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected())
    }

    async fn insert_passkey(&self, p: &PasskeyRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO auth_passkeys (id, user_id, rp_id, cred_id, passkey, label, created_ms, last_used_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(p.id)
        .bind(p.user_id)
        .bind(&p.rp_id)
        .bind(&p.cred_id)
        .bind(&p.passkey_json)
        .bind(&p.label)
        .bind(p.created_ms)
        .bind(p.last_used_ms)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn passkeys_for_user(&self, user_id: Uuid) -> Result<Vec<PasskeyRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, user_id, rp_id, cred_id, passkey, label, created_ms, last_used_ms FROM auth_passkeys
             WHERE user_id = $1 ORDER BY created_ms, id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        rows.iter().map(passkey_of).collect::<Result<_, _>>().map_err(map_err)
    }

    async fn passkey_used(&self, id: Uuid, passkey_json: Option<&str>, at_ms: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE auth_passkeys SET last_used_ms = $2, passkey = COALESCE($3, passkey) WHERE id = $1")
            .bind(id)
            .bind(at_ms)
            .bind(passkey_json)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn rename_passkey(&self, id: Uuid, user_id: Uuid, label: &str) -> Result<bool, StoreError> {
        let r = sqlx::query("UPDATE auth_passkeys SET label = $3 WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .bind(label)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected() > 0)
    }

    async fn delete_passkey(&self, id: Uuid, user_id: Uuid) -> Result<bool, StoreError> {
        let r = sqlx::query("DELETE FROM auth_passkeys WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected() > 0)
    }

    async fn insert_event(&self, e: &EventRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO auth_events (at_ms, user_id, kind, address, ip, detail) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(e.at_ms)
        .bind(e.user_id)
        .bind(&e.kind)
        .bind(&e.address)
        .bind(&e.ip)
        .bind(&e.detail)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn events_for_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<EventRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, at_ms, user_id, kind, address, ip, detail FROM auth_events
             WHERE user_id = $1 ORDER BY at_ms DESC, id DESC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        rows.iter()
            .map(|r| -> Result<EventRecord, sqlx::Error> {
                Ok(EventRecord {
                    id: r.try_get("id")?,
                    at_ms: r.try_get("at_ms")?,
                    user_id: r.try_get("user_id")?,
                    kind: r.try_get("kind")?,
                    address: r.try_get("address")?,
                    ip: r.try_get("ip")?,
                    detail: r.try_get("detail")?,
                })
            })
            .collect::<Result<_, _>>()
            .map_err(map_err)
    }

    async fn prune_events(&self, before_ms: i64) -> Result<u64, StoreError> {
        let r = sqlx::query("DELETE FROM auth_events WHERE at_ms < $1")
            .bind(before_ms)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(r.rows_affected())
    }
}
