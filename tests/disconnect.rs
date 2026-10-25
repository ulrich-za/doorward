//! A visitor who hangs up in the middle of a password check. The check goes
//! on (it has already started), so it must keep its place in the queue,
//! keeping the memory used for hashing bounded, and the guess must still be
//! counted and logged.

#![cfg(all(feature = "axum", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use doorward::password::HashPolicy;
use doorward::store::MemoryStore;
use doorward::{Address, Doorward, NewUser};
use std::io::Write;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The most memory this process has used so far, in MiB.
fn peak_mib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = s.lines().find(|l| l.starts_with("VmHWM:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() / 1024
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hanging_up_neither_frees_the_turn_nor_skips_the_count() {
    // 128 MiB per check, one check at a time.
    let policy = HashPolicy { m_kib: 128 * 1024, t: 3, p: 1, concurrency: 1, ..HashPolicy::floor() };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let dw = Doorward::builder(MemoryStore::new())
        .address(Address::localhost_for_development(&format!("http://localhost:{port}")).unwrap())
        .hash_policy(policy)
        .build()
        .await
        .unwrap();
    let admin = dw
        .create_user(NewUser {
            username: "admin".into(),
            password: Some("blue tractor umbrella".to_string().into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let app = axum::Router::new().nest("/auth", doorward::axum::routes()).with_state(dw.clone());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });

    let before = peak_mib();
    let body = r#"{"username":"admin","password":"guess"}"#;
    let req = format!(
        "POST /auth/sign-in HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    // Five guesses (before any slow-down), each abandoned after 30 ms.
    for _ in 0..5 {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(s);
    }
    // Every guess is still checked, one after another, and logged.
    let started = Instant::now();
    loop {
        let failed = dw.store().events_for_user(admin.id, 100).await.unwrap();
        let n = failed.iter().filter(|e| e.kind == "sign_in_failed").count();
        if n == 5 {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(60), "only {n} of 5 guesses were counted");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let grew = peak_mib().saturating_sub(before);
    assert!(grew < 100, "checks ran side by side: the peak grew by {grew} MiB");
}
