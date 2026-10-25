//! A minimal app with password and passkey sign-in, for trying doorward in
//! a browser on this machine:
//!
//! ```text
//! cargo run --example minimal --features axum,passkeys
//! ```
//!
//! then open <http://localhost:3000>. It prints the admin password (or uses
//! `DEMO_PASSWORD`). Everything lives in memory and is lost on exit; swap
//! `MemoryStore` for `doorward_sqlite::SqliteStore::open(...)` to keep it.
//!
//! Plain HTTP is allowed only because the address is `localhost`, which
//! browsers treat as secure. A real deployment uses `Address::new("https://…")`.

use axum::Router;
use axum::http::header;
use axum::response::Html;
use axum::routing::get;
use doorward::axum::{Authenticated, Recent};
use doorward::store::MemoryStore;
use doorward::{Address, Doorward, NewUser};
use std::net::SocketAddr;
use std::time::Duration;

const PAGE: &str = include_str!("minimal/index.html");
const SCRIPT: &str = include_str!("minimal/app.js");

async fn whoami(me: Authenticated) -> String {
    format!("{} ({})", me.session.user.username, me.session.user.roles.join(", "))
}

async fn sensitive(Recent(me): Recent) -> String {
    format!("{} confirmed it's them recently", me.session.user.username)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,doorward=debug".into()))
        .init();
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3000);

    let dw = Doorward::builder(MemoryStore::new())
        .address(Address::localhost_for_development(&format!("http://localhost:{port}"))?.passkeys(true))
        .app_name("doorward demo")
        .build()
        .await?;

    let password = match std::env::var("DEMO_PASSWORD") {
        Ok(p) => p,
        Err(_) => {
            let mut b = [0u8; 12];
            getrandom::fill(&mut b).map_err(|e| format!("random: {e}"))?;
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
    };
    dw.create_user(NewUser {
        username: "admin".into(),
        display_name: Some("Demo Admin".into()),
        roles: vec!["admin".into()],
        password: Some(password.clone().into()),
    })
    .await?;
    println!("Open http://localhost:{port} and sign in as admin with password {password}");

    dw.spawn_upkeep(Duration::from_secs(600));
    let admin_only = Router::new()
        .route("/api/admin", get(|| async { "admin area" }))
        .route_layer(axum::middleware::from_fn_with_state((dw.clone(), "admin"), doorward::axum::require_role));
    let app = Router::new()
        .route("/", get(|| async { (security_headers(), Html(PAGE)) }))
        .route("/app.js", get(|| async { ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], SCRIPT) }))
        .route("/api/whoami", get(whoami))
        .route("/api/sensitive", get(sensitive))
        .merge(admin_only)
        .nest("/auth", doorward::axum::routes())
        .with_state(dw);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

fn security_headers() -> [(header::HeaderName, &'static str); 4] {
    [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
    ]
}
