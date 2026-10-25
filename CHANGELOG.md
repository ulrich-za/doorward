# Changelog

All notable changes to doorward are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (below 1.0, a minor version may
break the API).

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

[0.1.0]: https://github.com/ulrich-za/doorward/releases/tag/v0.1.0
