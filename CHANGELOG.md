# Changelog

All notable changes to doorward are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (below 1.0, a minor version may
break the API).

## [0.2.0] - unreleased

The sign-in core: everything pingrail 0.4 needs to move its sign-in into
doorward, plus configurable addresses and the store crates.

### Added

- `Doorward`, set up with `Doorward::builder(store)`: users, password
  sign-in, sessions, recent-sign-in checks, accounts for admin screens, and
  a security log (`events`, and the `doorward::security` tracing target).
- `Address`: the origins the app answers on, each with its own sign-in
  methods (`passwords`, `passkeys`), routing (`Via::Direct` or
  `Via::Proxy`) and `SessionLengths`. Requests to other names, and requests
  that claim an address without coming the right way, are refused.
- Sessions: 256-bit random cookies stored as SHA-256, bound to their
  address, idle and absolute limits, `__Host-` cookies with `Secure`,
  `HttpOnly` and `SameSite=Strict`, a new cookie at every sign-in and
  confirmation, listing and ending sessions.
- Rate limits: per-visitor budgets (IPv4 address or IPv6 /64), slow-down
  then refusal after repeated failures, no account lockout, remembered
  browsers (a device cookie) with their own budget and a reserved
  password-check slot.
- Usernames: Unicode NFKC, case-insensitive keys, look-alikes refused (UTS
  #39 skeletons), one script per name (Unicode's "highly restrictive").
- Password rules: length limits, the 5,000 most common passwords refused,
  the username and app-chosen words refused, no composition rules.
- Passkeys (`passkeys` feature, webauthn-rs 0.5): per-address relying
  parties, discoverable sign-in, confirmation, registration with resident
  keys preferred, single-use two-minute requests capped per visitor and per
  session, credential ids unique across accounts, counters checked,
  refusal to remove the last way in.
- axum integration (`axum` feature): `Visitor`, `Authenticated` and `Recent`
  extractors, `require_signed_in` and `require_role` middleware, and JSON
  endpoints (`routes()`).
- `store::Store` trait with `MemoryStore`, and a conformance suite
  (`test-util`) that every store must pass.
- `doorward-sqlite` and `doorward-postgres` crates.
- `testing::TestAuthenticator` (`test-util`): a software passkey device for
  tests without a browser.
- `examples/minimal` and a real-browser check with Chromium's virtual
  passkey device (`tests/browser/passkeys.py`).
- Property tests over every parser that sees network input, cargo-fuzz
  targets (`fuzz/`), `deny.toml`, a threat model and an OWASP ASVS 5.0
  checklist.

### Changed

- `serde` and `tokio` are no longer optional features; the sign-in core
  needs both.

### Changed from pingrail 0.3's sign-in

- The visitor's address behind a proxy comes from `CF-Connecting-IP` or the
  right-most untrusted `X-Forwarded-For` entry (pingrail took the left-most,
  which the visitor can write).
- Rate limits are per visitor, not one budget shared by everyone.
- Unknown usernames take the same store steps as known ones.
- A request with two copies of the session cookie is treated as signed out.
- A browser's Origin must match exactly, including the port; writes from
  another port on the same host are refused.
- Changing the password needs the current one, and re-authenticating issues a
  new cookie.

## [0.1.0] - 2026-10-25

First release: Argon2id password hashing sized to the machine, extracted from
pingrail 0.3.

### Added

- `password::HashPolicy`: chooses memory per check (2 % of total or 10 % of
  free memory, 19–256 MiB, one or two checks at a time) and times the passes
  for about 350 ms per check, never below OWASP's minimum. Saved and loaded as
  JSON by the app (`load_or_tune`, `to_json`, `from_json`); retuned when total
  memory changes by more than a fifth.
- `password::detect_memory`: reads `/proc/meminfo` and the tightest cgroup v1
  or v2 limit on Linux; other systems use `sysinfo` (`detect-memory` feature).
- `password::Hasher`: hashes with a fresh salt, verifies with each saved
  hash's own settings, reports when a rehash is due, checks a stand-in hash for
  unknown users, and limits concurrent checks to the policy's one or two
  (`tokio` feature).
- `Error` and `ErrorCode`: stable codes for the app to word itself.

### Changed from pingrail 0.3

- No `unsafe` code: memory on Windows and macOS is read through `sysinfo`
  instead of direct system calls.
- Saved hashes are also refused when they ask for more than 32 passes, more
  than 16 lanes, or more than 4 GiB-passes of work in total (pingrail checked
  memory only), and when they aren't Argon2 at all.
- Passwords over 1 KiB are refused before hashing.
- Hashes with a short salt or a non-default output length are reported as
  needing a rehash.
- A `cgroup` path that tries to climb out of `/sys/fs/cgroup` is ignored.
- Typed errors instead of `anyhow`; the app decides where the policy is saved.

[0.2.0]: https://github.com/ulrich-za/doorward/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ulrich-za/doorward/releases/tag/v0.1.0
