#![allow(clippy::unwrap_used, clippy::expect_used)]

use doorward::store::Store;
use doorward_sqlite::SqliteStore;

#[tokio::test]
async fn conforms_in_memory() {
    let s = SqliteStore::open_in_memory().unwrap();
    doorward::testing::conformance::run(&s).await;
}

#[tokio::test]
async fn conforms_on_disk_twice_and_files_are_private() {
    let dir = std::env::temp_dir().join(format!("doorward-sqlite-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("auth.db");
    let _ = std::fs::remove_file(&path);
    {
        let s = SqliteStore::open(&path).unwrap();
        doorward::testing::conformance::run(&s).await;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "only the owner can read the database");
    }
    // Reopened, with the data from the first run still there.
    let s = SqliteStore::open(&path).unwrap();
    doorward::testing::conformance::run(&s).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let dir = std::env::temp_dir().join(format!("doorward-sqlite-newer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("auth.db");
    let _ = std::fs::remove_file(&path);
    SqliteStore::open(&path).unwrap().migrate().await.unwrap();
    // Pretend a newer doorward-sqlite upgraded this database.
    rusqlite::Connection::open(&path).unwrap().execute("INSERT INTO auth_schema (version) VALUES (99)", []).unwrap();
    let err = SqliteStore::open(&path).unwrap().migrate().await.unwrap_err();
    assert!(err.to_string().contains("newer"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_apps_own_tables_are_left_alone() {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch(
        "CREATE TABLE targets (id INTEGER PRIMARY KEY, host TEXT); INSERT INTO targets (host) VALUES ('1.1.1.1');",
    )
    .unwrap();
    let s = SqliteStore::from_connection(c).unwrap();
    doorward::testing::conformance::run(&s).await;
}

#[tokio::test]
async fn doorward_runs_on_sqlite() {
    use doorward::{Address, Doorward, NewUser, RequestInfo};
    let s = SqliteStore::open_in_memory().unwrap();
    let dw = Doorward::builder(s)
        .address(Address::new("https://app.example").unwrap())
        .hash_policy(doorward::password::HashPolicy::floor())
        .build()
        .await
        .unwrap();
    dw.create_user(NewUser {
        username: "admin".into(),
        password: Some("a long passphrase".to_string().into()),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut h = http::HeaderMap::new();
    h.insert("host", "app.example".parse().unwrap());
    let v = dw
        .visit(&RequestInfo {
            peer: "192.0.2.1".parse().unwrap(),
            method: &http::Method::POST,
            host: None,
            headers: &h,
        })
        .unwrap();
    let signed = dw.sign_in_password(&v, "ADMIN", "a long passphrase", true).await.unwrap();
    let token = signed.cookies[0].as_str().split(';').next().unwrap().to_string();
    h.insert("cookie", token.parse().unwrap());
    let v = dw
        .visit(&RequestInfo { peer: "192.0.2.1".parse().unwrap(), method: &http::Method::GET, host: None, headers: &h })
        .unwrap();
    assert_eq!(dw.authenticate(&v).await.unwrap().unwrap().user.username, "admin");
}
