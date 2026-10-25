# Changelog

All notable changes to doorward are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions count up
by the last number (0.1.1, 0.1.2, …) unless stated otherwise. Below 1.0, a
release may change the API: read the notes before upgrading.

## [0.1.0] - 2026-10-25

First release: headless sign-in for Rust web apps, starting with what
pingrail 0.4 needs to move its sign-in into doorward, plus configurable
addresses and storage for SQLite and Postgres.

### Added

- `password`: Argon2id hashing sized to the machine, extracted from pingrail
  0.3. Memory per check is 2 % of total or 10 % of free memory (19–256 MiB,
  one or two checks at a time); passes are timed for about 350 ms per check,
  never below OWASP's minimum. The policy is saved and loaded as JSON and
  retuned when total memory changes by more than a fifth. Memory is read from
  `/proc/meminfo` and the tightest cgroup limit on Linux, and through
  `sysinfo` elsewhere (`detect-memory` feature). Saved hashes verify with
  their own settings and are reported for rehashing; unknown users are
  checked against a stand-in hash.
- `Doorward`, set up with `Doorward::builder(store)`: users, password
  sign-in, sessions, recent-sign-in checks, accounts for admin screens, and
  a security log (`events`, and the `doorward::security` tracing target).
- `Address`: the origins the app answers on, each with its own sign-in
  methods (`passwords`, `passkeys`), routing (`Via::Direct` or
  `Via::Proxy`) and `SessionLengths`. Requests to other names, and requests
  that claim an address without coming the right way, are refused.
- Sessions: 256-bit random cookies stored as SHA-256, bound to their
  address, idle and absolute limits, `__Host-` cookies with `Secure`,
  `HttpOnly` and `SameSite=Strict`, a new cookie at every sign-in and every
  re-authentication, listing and ending sessions.
- Rate limits: per-visitor budgets (IPv4 address or IPv6 /64), slow-down
  then refusal after repeated failures, no account lockout, remembered
  browsers (a device cookie, five per account) with their account's own
  budget for attempts at that account, skipping the visitors' queue for
  password checks. Refused visitors are never forgotten to make room. A
  visitor who hangs up mid-check still has the guess counted, and the check
  keeps its turn until it ends.
- Answers to wrong passwords and unknown usernames are held back until a
  check with the current hashing settings would have finished, so older,
  cheaper hashes don't stand out.
- Usernames: Unicode NFKC, case-insensitive keys, look-alikes refused (UTS
  #39 skeletons of the name as written and lowercased), one script per name
  (Unicode's "highly restrictive").
- Password rules: length limits, the 5,000 most common passwords refused,
  the username and app-chosen words refused, no composition rules; changing
  a password needs the current one.
- Passkeys (`passkeys` feature, webauthn-rs 0.5): per-address relying
  parties, discoverable sign-in, confirmation, registration with resident
  keys preferred, single-use two-minute requests (starting one counts
  against the visitor's budget; capped per visitor, per network, per account
  and in all), credential ids unique across accounts, counters checked,
  refusal to remove the last way in.
- axum integration (`axum` feature): `Visitor`, `Authenticated` and `Recent`
  extractors, `require_signed_in` and `require_role` middleware, and JSON
  endpoints (`routes()`), every response `Cache-Control: no-store`.
- `Builder::trust_cf_connecting_ip`: `CF-Connecting-IP` is believed only when
  the trusted proxies are Cloudflare's (off by default).
- Changing, resetting or removing a password, and disabling an account,
  forget the account's remembered browsers (a change keeps the current one,
  with a new cookie).
- `store::Store` trait with `MemoryStore`, and a conformance suite
  (`test-util`) that every store must pass, including that per-user queries
  never touch another user's rows.
- `doorward-sqlite` and `doorward-postgres` crates.
- `testing::TestAuthenticator` (`test-util`): a software passkey device for
  tests without a browser.
- `Error` and `ErrorCode`: stable codes for the app to word itself.
- `examples/minimal` and a real-browser check with Chromium's virtual
  passkey device (`tests/browser/passkeys.py`).
- Property tests over every parser that sees network input, cargo-fuzz
  targets (`fuzz/`), `deny.toml`, a threat model and an OWASP ASVS 5.0
  checklist.
- An independent review before release; its findings are fixed and kept as
  regression tests (listed in the threat model).

### Changed from pingrail 0.3's sign-in

- No `unsafe` code: memory on Windows and macOS is read through `sysinfo`
  instead of direct system calls.
- Saved hashes are also refused when they ask for more than 32 passes, more
  than 16 lanes, or more than 4 GiB-passes of work in total (pingrail checked
  memory only), and when they aren't Argon2 at all. Passwords over 1 KiB are
  refused before hashing.
- The visitor's address behind a proxy comes from the right-most untrusted
  `X-Forwarded-For` entry (pingrail took the left-most, which the visitor can
  write), or from `CF-Connecting-IP` when the app says its proxy is
  Cloudflare's.
- Rate limits are per visitor, not one budget shared by everyone.
- Unknown usernames take the same store steps as known ones.
- A request with two copies of the session cookie is treated as signed out.
- A browser's Origin must match exactly, including the port; writes from
  another port on the same host are refused.
- Changing the password needs the current one, and re-authenticating issues a
  new cookie.

[0.1.0]: https://github.com/ulrich-za/doorward/releases/tag/v0.1.0
