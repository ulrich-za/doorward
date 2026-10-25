# doorward

Headless sign-in for Rust web apps. doorward is the doorkeeper: it answers
"who is this request, and may they?" and leaves every screen to the app.

The name is the old English word for a doorkeeper, the job Háma holds at the
doors of Théoden's hall.

## What it does

- **Passwords** hashed with Argon2id sized to the machine (19–256 MiB, about a
  third of a second per check, never below OWASP's minimum), checked against
  the 5,000 most common passwords, with no composition rules.
- **Passkeys** (WebAuthn through webauthn-rs) per address, with user
  verification always required, discoverable sign-in (no username needed),
  and browser autofill.
- **Addresses** the app answers on, each with its own sign-in methods and
  session lengths. A LAN name and a public name behind cloudflared can
  behave differently, and a LAN device that claims the public name gets
  nothing.
- **Sessions** stored only as hashes, bound to the address they were made
  on, with idle and absolute limits, `__Host-` cookies, a new cookie at every
  sign-in and confirmation, and a list the user can end sessions from.
- **Recent sign-in** before sensitive actions, confirmed with the password
  or a passkey.
- **Rate limits nobody can use to lock you out:** each visitor (an IPv4
  address or IPv6 /64) has its own budget, accounts are never locked, and a
  browser that signed in before has its own budget and a reserved
  password-check slot, so a flood from elsewhere — even from your own
  address — can't stop you.
- **A security log** of sign-ins, failures and changes, per user and on its
  own `tracing` target.
- **axum integration:** extractors (`Authenticated`, `Recent`), role
  middleware, and ready-made JSON endpoints for sign-in, sessions and
  passkeys.
- **Storage** behind a trait: in memory (tests), SQLite (`doorward-sqlite`)
  and Postgres (`doorward-postgres`), each passing the same conformance suite.

No `unsafe` code. No server secret to leak or rotate.

## A taste

```rust
use axum::{Router, routing::get};
use doorward::axum::{Authenticated, routes};
use doorward::{Address, Doorward};

async fn dashboard(me: Authenticated) -> String {
    format!("hello {}", me.session.user.display_name)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dw = Doorward::builder(doorward_sqlite::SqliteStore::open("app.db")?)
        .address(Address::new("https://app.example")?.passkeys(true))
        .app_name("my app")
        .build()
        .await?;
    let app = Router::new()
        .route("/api/dashboard", get(dashboard))
        .nest("/auth", routes())
        .with_state(dw);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8443").await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    Ok(())
}
```

Try it in a browser with the example:

```text
cargo run --example minimal --features axum,passkeys
```

## Crates

| Crate | What |
|---|---|
| `doorward` | The core: hashing, sign-in, sessions, limits, passkeys (`passkeys`), axum (`axum`) |
| `doorward-sqlite` | SQLite storage through rusqlite (shares SQLite with apps on rusqlite 0.40–0.41) |
| `doorward-postgres` | Postgres storage through sqlx 0.9 (the app's pool and TLS) |

`doorward-postgres` is a workspace of its own: Cargo won't resolve rusqlite
and sqlx in one dependency graph, even when one of them is unused.

## Features of `doorward`

| Feature | Default | What it adds |
|---|---|---|
| `detect-memory` | yes | Memory detection on systems other than Linux, through `sysinfo` |
| `passkeys` | | Passkeys through webauthn-rs 0.5 (uses OpenSSL) |
| `vendored-openssl` | | Builds OpenSSL into the program |
| `axum` | | Extractors, middleware and JSON endpoints for axum 0.8 |
| `test-util` | | The store conformance suite and a software passkey authenticator |

## Documentation

- [Integration guide](docs/integration.md), including moving pingrail 0.3's
  accounts and passkeys across.
- [Threat model](docs/threat-model.md): what is defended, how, and where it
  stops.
- [OWASP ASVS 5.0 checklist](docs/asvs.md): each requirement and the test
  that checks it.
- [CHANGELOG](CHANGELOG.md).

## Testing

```text
cargo test --workspace --all-features
DOORWARD_TEST_POSTGRES=postgres://… cargo test --manifest-path doorward-postgres/Cargo.toml
python3 tests/browser/passkeys.py   # with the example running; needs Playwright
cargo deny check
```

Thorough testing is not an independent audit. Have one done before a public,
multi-user site goes live.

## Licence

Copyright 2026 Ulrich Holtzhausen. Licensed under the
[Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for the
common-password list's licence.

Report security problems as described in [SECURITY.md](SECURITY.md).
