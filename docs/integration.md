# Putting doorward in an app

This guide follows an axum app such as pingrail. A runnable version is in
`examples/minimal.rs` (with its page in `examples/minimal/`).

## 1. Dependencies

```toml
[dependencies]
doorward = { version = "0.1", features = ["axum", "passkeys", "vendored-openssl"] }
doorward-sqlite = "0.1"      # or doorward-postgres = "0.1"
```

`vendored-openssl` builds OpenSSL into the program, so nothing has to be
installed next to it (webauthn-rs 0.5 needs OpenSSL; 0.6 will drop it).

## 2. Build the doorkeeper at start-up

```rust
use doorward::{Address, Doorward, IpNet, SessionLengths};
use std::time::Duration;

let store = doorward_sqlite::SqliteStore::open(&db_path)?;   // the app's own file is fine
let dw = Doorward::builder(store)
    // The LAN address: passwords, no passkeys, a week without idling out.
    .address(
        Address::new("https://pc.lan:8040")?
            .sessions(SessionLengths::new(None, Duration::from_secs(7 * 86_400), true))
            .remembered(None),
    )
    // The public address through cloudflared: passkeys, short sessions.
    .address(
        Address::new("https://pingrail-admin.example.com")?
            .via_proxy()
            .passkeys(true)
            .sessions(SessionLengths::new(Some(Duration::from_secs(30 * 60)), Duration::from_secs(12 * 3600), false))
            .remembered(None),
    )
    .trusted_proxies([IpNet::parse("127.0.0.1")?, IpNet::parse("::1")?])
    .trust_cf_connecting_ip(true)   // only cloudflared forwards to this app
    .app_name("pingrail")
    .refuse_password_words(["pingrail"])
    .build()
    .await?;          // times password hashing on the first start (a second or two)
dw.spawn_upkeep(Duration::from_secs(600));
```

**Addresses come from the machine, never from the web UI.** Read them from
the app's config file or command line.

**Every address has its own passkeys**, because the browser ties a passkey to
the name in its address bar. A passkey made at `pc.lan` doesn't work
at `pingrail-admin.example.com`. Until one-time links arrive (a later release),
the first passkey at an address is added after signing in there with the
password; turn passwords off at that address (`.passwords(false)`) only once
it has a passkey. doorward refuses to remove the last passkey at an address
without passwords.

**Proxied addresses** match only requests from a trusted proxy that say whom
they forward for (`X-Forwarded-For`) and were forwarded over HTTPS
(`X-Forwarded-Proto: https`). cloudflared sends all of these. A direct
address never matches a forwarded request.

**`CF-Connecting-IP`** is ignored unless `trust_cf_connecting_ip(true)`. Turn
it on only when every trusted proxy is Cloudflare's (cloudflared, or
Cloudflare's own addresses in front of the app): Cloudflare overwrites the
header, but nginx, Caddy and Traefik pass it through as the visitor wrote
it, which would let visitors choose their own rate-limit budget. Without it,
the address comes from `X-Forwarded-For`, which Cloudflare also sends.

## 3. Serve with the peer address

doorward needs the connection's address. With `axum::serve`:

```rust
axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
```

With a hand-made hyper loop (as pingrail has), insert the address into each
request's extensions as `doorward::axum::Peer(ip)` (or axum's `ConnectInfo`).

## 4. Routes

```rust
use doorward::axum::{Authenticated, Recent, routes};

let app = Router::new()
    .route("/api/targets", get(list_targets))       // takes `me: Authenticated`
    .route("/api/settings", post(change_settings))  // takes `Recent(me): Recent`
    .nest("/auth", routes())
    .with_state(dw.clone());
```

- `Authenticated` refuses with 401 `not_signed_in` (clearing a stale cookie),
  and with 403 `cross_origin` for a write from another site.
- `Recent` also needs a sign-in from the last ten minutes (403
  `needs_recent_sign_in`); the page then asks for the password or a passkey
  (`POST /auth/confirm` or `/auth/passkey/confirm/…`) and retries.
- `me.require_role("admin")?` checks a role inside a handler; the
  `require_role` middleware guards a whole router.

If the app's state is a struct, implement `FromRef<AppState> for Doorward`
(or derive `FromRef`).

## 5. The sign-in page

`GET /auth/session` says whether the visitor is signed in and what the
address offers (`passwords`, `passkeys`, `remember`), so the page shows only
what works there. `examples/minimal/app.js` has the browser side: password
sign-in, passkey sign-in (button and autofill), adding a passkey, confirming,
and turning error codes into the app's own words.

Error responses are `{"error": "<code>"}` (plus `retry_after` and a
`Retry-After` header when rate-limited). The codes are listed in
`doorward::ErrorCode`.

Each passkey sign-in the page starts (including one for autofill, on every
visit to the sign-in page) counts against the visitor's budget and stays
open for two minutes unless finished. A visitor (one address, or an IPv6
/64) may have 8 open at once, so start them only when needed: once for
autofill when the page loads, or when the button is clicked, never on a
timer.

## 6. Recovery on the machine

Physical access to the server is the root of trust. Give the app a command
line such as:

```rust
dw.set_password(user.id, &new_password).await?;   // ends every session, forgets remembered browsers
dw.remove_all_passkeys(user.id).await?;            // `passkeys reset`
dw.end_all_sessions(user.id).await?;
```

## 7. Logging

Security events go to the `tracing` target `doorward::security` (and to the
store, readable per user through `events`). Route that target to its own file
or service: it gets every event, while the store rations failed attempts
(per account 50 at once, then one every five minutes; without an account
100, then one every 30 seconds) and records what it skipped (how many,
when, from where) in a `failures_not_stored` row at each upkeep. Nothing doorward logs contains a
password, token or cookie.

## 8. Speed

doorward's own work is small next to a password check: about 1 µs to read a
request, a few µs to look up a session in memory, and around 0.1–0.2 ms of
CPU around each sign-in. The third of a second each password check takes is
deliberate (see the threat model). [performance.md](performance.md) has the
measurements and the cost of each operation.

- **SQLite:** doorward-sqlite keeps one connection; every write waits for the
  disk (`synchronous = FULL`), which is what makes a sign-out survive a power
  cut. Leave it unless you accept that trade.
- **Large hashing memory on Linux:** with 64 MiB or more per check, running
  the app with `GLIBC_TUNABLES=glibc.malloc.hugetlb=1` lets glibc use huge
  pages for the hashing memory, so each check spends less time on page
  faults and calibration fits more passes into the same time.
- **Sessions:** a user has at most 50 at once by default
  (`Builder::max_sessions_per_user`); a sign-in beyond that ends the oldest.

## 9. Moving pingrail 0.3's accounts across (pingrail 0.4)

pingrail 0.3 already uses the same Argon2id PHC strings and webauthn-rs
`Passkey` JSON, so its users keep their passwords and passkeys:

1. For each row of pingrail's `users`, insert a `UserRecord` through
   `dw.store().insert_user(..)` with **`id` = the row's `uuid`** (the passkey
   user handle), the username parsed by `doorward::Username::parse`, and
   `roles: vec!["admin".into()]`.
2. Copy the `phc` with `store.set_password(id, phc, now)`. Hashes made with
   other settings are upgraded at their next sign-in.
3. Copy each `passkeys` row with `store.insert_passkey(..)`: `rp_id`,
   `cred_id` (already base64url), `passkey` JSON and `label` as they are.
4. Leave pingrail's old sessions behind: everyone signs in once.

Do it once, in a transaction on the app's side, and mark it done (for
example with `store.meta_set("pingrail.migrated", "1")`).

## 10. Before going public

- Use HTTPS everywhere (`Address::new` refuses `http://` except for
  `localhost` in development).
- Keep a strict Content Security Policy on the app's pages: script injection
  in the app is the one thing doorward can't defend against.
- Run several copies only with sticky sessions until shared rate-limit and
  passkey storage arrive.
- If anyone can sign up, limit sign-ups: each account brings its own small
  budgets (see "Many accounts, many budgets" in the threat model).
- Have an independent review done before going live with many users.
