//! Needs a Postgres server: set `DOORWARD_TEST_POSTGRES` to a connection URL
//! (for example `postgres://doorward:doorward-test@localhost/doorward_test`).
//! Each test runs in its own new schema, dropped afterwards. Without the
//! variable the tests are skipped (and say so).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use doorward::store::Store;
use doorward_postgres::PostgresStore;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;

struct Schema {
    admin: sqlx::PgPool,
    name: String,
    pool: sqlx::PgPool,
}

async fn schema() -> Option<Schema> {
    let Ok(url) = std::env::var("DOORWARD_TEST_POSTGRES") else {
        eprintln!("DOORWARD_TEST_POSTGRES not set; skipping");
        return None;
    };
    let admin = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    let name = format!("t_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {name}"))).execute(&admin).await.unwrap();
    let opts = PgConnectOptions::from_str(&url).unwrap().options([("search_path", name.as_str())]);
    let pool = PgPoolOptions::new().max_connections(8).connect_with(opts).await.unwrap();
    Some(Schema { admin, name, pool })
}

impl Schema {
    async fn drop(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {} CASCADE", self.name)))
            .execute(&self.admin)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn conforms_twice() {
    let Some(s) = schema().await else { return };
    let store = PostgresStore::new(s.pool.clone());
    doorward::testing::conformance::run(&store).await;
    doorward::testing::conformance::run(&store).await;
    s.drop().await;
}

#[tokio::test]
async fn concurrent_migrations_are_safe() {
    let Some(s) = schema().await else { return };
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let store = PostgresStore::new(s.pool.clone());
        tasks.push(tokio::spawn(async move { store.migrate().await }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_schema").fetch_one(&s.pool).await.unwrap();
    assert_eq!(n, 1);
    s.drop().await;
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let Some(s) = schema().await else { return };
    let store = PostgresStore::new(s.pool.clone());
    store.migrate().await.unwrap();
    sqlx::query("INSERT INTO auth_schema (version) VALUES (99)").execute(&s.pool).await.unwrap();
    let err = store.migrate().await.unwrap_err();
    assert!(err.to_string().contains("newer"), "{err}");
    s.drop().await;
}

#[tokio::test]
async fn doorward_runs_on_postgres() {
    use doorward::{Address, Doorward, NewUser, RequestInfo};
    let Some(s) = schema().await else { return };
    let dw = Doorward::builder(PostgresStore::new(s.pool.clone()))
        .address(Address::new("https://repairs.example").unwrap())
        .hash_policy(doorward::password::HashPolicy::floor())
        .build()
        .await
        .unwrap();
    let u = dw
        .create_user(NewUser {
            username: "tech1".into(),
            roles: vec!["tech".into()],
            password: Some("a long passphrase".to_string().into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut h = http::HeaderMap::new();
    h.insert("host", "repairs.example".parse().unwrap());
    let v = dw
        .visit(&RequestInfo {
            peer: "192.0.2.1".parse().unwrap(),
            method: &http::Method::POST,
            host: None,
            headers: &h,
        })
        .unwrap();
    let signed = dw.sign_in_password(&v, "Tech1", "a long passphrase", false).await.unwrap();
    assert!(signed.session.user.has_role("tech"));
    // Postgres refuses a NUL in text; such a name is never sent to it, and the
    // answer is the ordinary one, not an internal error.
    let err = dw.sign_in_password(&v, "tech1\u{0}", "a long passphrase", false).await.unwrap_err();
    assert_eq!(err.code(), doorward::ErrorCode::InvalidCredentials);
    // The app can reference doorward's users from its own tables.
    sqlx::query("CREATE TABLE jobs (id SERIAL PRIMARY KEY, tech UUID NOT NULL REFERENCES auth_users(id))")
        .execute(&s.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO jobs (tech) VALUES ($1)").bind(u.id).execute(&s.pool).await.unwrap();
    s.drop().await;
}
