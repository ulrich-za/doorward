# doorward performance

What each operation costs, in Big-O terms and measured, and what was changed
for 0.1.1 after an independent analysis of 0.1.0. Some costs are deliberate
security features, not inefficiencies; they are marked as such and were left
alone.

## How it was measured

- **Who:** an agent that hadn't seen the code being written analysed 0.1.0
  (commit `86e367b`), using benchmarks of its own on the real code paths.
  The changes were then measured again with the same benchmarks, back to
  back with 0.1.0, and a second independent agent reviewed them for
  security. That review found that the first version of the new padding
  let older hashes answer sooner than unknown names by 5–40 ms; the floor
  was raised and made to follow load before release, with a test that
  fails on the first version.
- **Where:** a cloud VM with 2 vCPUs (Xeon @ 2.1 GHz, constant TSC), Rust
  1.97, release builds. Postgres 16 ran on the same 2 vCPUs. SQLite used a
  WAL file with `synchronous = FULL`.
- **Units:** CPU cycles from the TSC (reference cycles at 2.1 GHz, so wall
  clock), median of 40–60 samples (criterion), with the measuring thread
  pinned for micro-benchmarks. Instruction counts and call-graph profiles
  come from callgrind, allocations from dhat. Separate runs on this shared
  VM differ by ±10–30 %, so only differences larger than that, measured back
  to back, are claimed.

## The deliberate costs

These are what doorward is for, and they dominate everything else:

| Cost | Why |
|---|---|
| Argon2id, about 350 ms and 19–256 MiB per password check | Makes stolen hashes slow to guess. It is 99.9 % of a sign-in's instructions. |
| One or two checks at a time, and a separate queue for visitors without a remembered browser | Bounds memory under a flood, and keeps a slot for remembered browsers. |
| Unknown usernames checked against a stand-in hash, and every answer held to a floor above a normal check (a quarter over the slowest check timed at start, following the machine's load) | Sign-in can't tell anyone which names exist, even for accounts whose saved hash has older, cheaper settings. |
| Every password check in a task of its own | A visitor who hangs up still pays for the guess. |
| Bounded rate-limit and passkey tables, single-use passkey requests | Memory stays bounded and nobody can push out a sign-in in progress. |
| SQLite `synchronous = FULL` | A sign-out or ended session survives a power cut. |

## Big O

Symbols:

- **Request:** H = header bytes, C = Cookie bytes, X = X-Forwarded-For bytes.
- **Store:** S = all sessions, k = one user's sessions (≤ 50 by default),
  U = users, E = log rows, P = one user's passkeys (≤ 100).
- **In memory:** V = tracked visitors (≤ 100,000, up to twice that while
  refused), Q = open passkey requests (≤ 3 × 10,000).
- **Inputs:** L = typed username bytes (≤ 1 KiB).

| Operation | Time | Space | Notes |
|---|---|---|---|
| `visit` (read a request) | O(H) | O(1) kept | Cookie header read once per cookie name; X-Forwarded-For only from a trusted proxy |
| `authenticate`, valid session | SQL: O(log S + log U); memory store: O(S) | O(1) | One store call (`session_with_user`); a write at most once a minute per session |
| `authenticate`, no or malformed cookie | O(1) | O(1) | Never reaches the store |
| `sign_in_password` | O(L) + one Argon2 check (Θ(m·t) time, Θ(m) memory) + O(log S) store work | Θ(m) while hashing | A refused visitor without a remembered browser: O(1), no store work |
| `lookup_key`, `Username::parse` | O(min(L, 65 characters after NFKC)) | O(1) | Normalising stops one character past the limit |
| `check_new_password` | O(p + w·p) for w refused words | O(p) | Common-password lookup is O(p) hashing |
| Limiter `admit` / `failed` | O(1) expected | ≤ 2 × `tracked_max` entries | A full table is scanned for room once per tenth of its size: amortised O(1) |
| Passkey `keep` / `take` | O(1); a sweep of O(Q) at most once a second | ≤ 30,000 requests | |
| `sessions`, `end_session` | O(k log k) | O(k) | k ≤ 50 by default |
| Security log write | O(log E) | Failures rationed per account and without one | Every event still reaches the log target |
| `upkeep` | O(S + R + expired events + V + Q) | O(1) | Session and remembered-browser pruning scans those tables |

## Measured

### 0.1.0 and 0.1.1 side by side

Medians, measured back to back on the same machine. Cycles are TSC
reference cycles at 2.1 GHz.

| What | 0.1.0 | 0.1.1 |
|---|---|---|
| New visitor when the rate-limit table (100,000) is full of refused visitors | 1.27 M cycles (605 µs) | 696 cycles (0.33 µs) |
| The same with 10,000 tracked | 78.6 K cycles (37 µs) | 919 cycles (0.44 µs) |
| Signed-in request, SQLite, 10,000 sessions | 231 K cycles (110 µs) | 104 K cycles (49 µs) |
| Reading a request plus a signed-in check, SQLite | 217 K cycles (103 µs) | 126 K cycles (60 µs) |
| Signed-in request that also writes the session's last use, SQLite | 695 K cycles (331 µs) | 540 K cycles (257 µs) |
| Signed-in request, Postgres, 10,000 sessions | 535 K cycles (255 µs) | 296 K cycles (141 µs) |
| Signed-in request that also writes the session's last use, Postgres | 1.38 M cycles (656 µs) | 940 K cycles (448 µs) |
| A sign-in attempt the rate limit refuses, SQLite (wall time) | 45–53 µs | 1–2 µs |
| Looking up a 1 KiB username that normalises to 18 times its length | 243 K cycles (116 µs) | 3.5 K cycles (1.7 µs) |
| Looking up a 1 KiB ASCII username | 37 K cycles (18 µs) | 4.0 K cycles (1.9 µs) |
| Single SQLite calls (user by id, session by token, log insert) | 57 / 50 / 284 µs | 42 / 38 / 238 µs |
| Flood of wrong passkey answers from 20,000 /64s against SQLite: failures handled per second | 2,104 (limited by log writes) | 18,396 |
| Signed-in latency on SQLite during that flood, p50 / p90 | 241 / 600 µs | 72 / 126 µs |
| Password check with the settings tuned for this machine | 80 MiB × 4–5 passes, 241–272 ms, answered after about 372 ms | 80 MiB × 4–7 passes, medians 241–422 ms, answered after 0.45–0.53 s |
| Password sign-in with the minimum settings (19 MiB × 2), wall time | 34–37 ms | 37–39 ms |

Calibration no longer charges the one-off cost of getting the memory to
every pass, and checks its choice with one real hash, so it picks as many
passes as fit about 350 ms. On this shared VM the machine's speed changed by
up to a third between runs, so five tunings picked 4 to 7 passes; a
dedicated machine varies far less. Answers now wait for a floor a quarter
above the slowest check timed at start, which costs about 0.1 s per
password answer compared with 0.1.0. That margin is what keeps accounts
with older, cheaper hashes from answering sooner than unknown names (see
"How it was measured").

Unchanged within the noise: reading a request (about 1 µs), rate-limit
calls (70–110 ns), and short usernames (0.4–2 µs to look up, 2–17 µs to
check a new one). The in-memory store's session lookup is a linear scan
whose time depends on where the session falls in a randomly seeded hash
order, so it isn't comparable from run to run; it is meant for tests.

### Where a request's time goes (0.1.1)

Rows for code that didn't change come from the 0.1.0 measurements.

| Operation | Median |
|---|---|
| Read a request (`visit`), typical browser headers | 1.0–1.5 µs |
| A rate-limit decision for a known visitor | 77 ns |
| Keep and take a passkey request with 10,000 open | 0.5 µs |
| Look up a typed username (ASCII / e-mail / accented Latin / CJK) | 0.6 / 2.0 / 0.8 / 0.6 µs |
| Make and hash a session token | 0.8 µs / 0.3 µs |
| Signed-in request: SQLite / in memory (1,000 sessions) | 49 µs / 1–3 µs |
| doorward's own CPU around a password sign-in (everything except the hash) | 0.15–0.32 ms |
| The password check itself (tuned, deliberate) | about 350 ms |

On SQLite most of a signed-in request is the hop to SQLite's thread and the
query; on Postgres it is the round trip.

### Allocations (measured on 0.1.0; the changes add none on these paths)

| Operation | In memory | SQLite (Rust side) |
|---|---|---|
| Signed-in request (`visit` + `authenticate`) | 22 allocations, 629 bytes | 35 allocations, 2.4 KB |
| Request without a session | 6 allocations, 262 bytes | the same |
| Successful sign-in, not counting the hash's memory | 111 allocations, 10.6 KB | 142 allocations, 15.7 KB |
| The hash's memory, per check | one block of 19 MiB (minimum) to 256 MiB, freed after | the same |

### Profile of a realistic mix (0.1.0)

20,000 signed-in requests (10 % writes), 2,500 requests without a session,
200 account pages, 10 sign-ins, 40 wrong passwords and 2,000 wrong passkey
answers, with the minimum hash settings:

- **Argon2:** 82 % of all instructions on the in-memory store, 63 % on
  SQLite. Zeroing the hash's fresh memory is a further 12 %; reusing that
  memory would need doorward to verify hashes itself, so it was left.
- **SQLite:** parsing SQL was 44 % of everything that wasn't Argon2. 0.1.1
  parses each statement once.
- **Requests:** reading requests, looking up sessions and hashing tokens
  together were under 10 %.

## Left as they are

| Item | Why |
|---|---|
| The Cookie header is read once per cookie name | About 0.5 µs a request; a 32 KiB header costs about 0.2 ms, and HTTP servers cap header sizes |
| X-Forwarded-For is collected before it is read from the right | Only from a trusted proxy; 37 µs for a 32 KiB header |
| doorward-sqlite has one connection, and cleanup scans the session table | Reads wait for writes (each about 0.2 ms with `synchronous = FULL`); cleanup takes about 13 ms per 100,000 sessions, once per upkeep. Extra read connections and an expiry index can come later |
| The in-memory store scans linearly | It is the test store; about 0.5 ms per lookup at 100,000 sessions |
| Argon2 memory isn't reused between checks | About 15 % per check at 80 MiB, but doorward would have to verify hashes itself; the huge-pages setting in the integration guide gets most of the gain safely |

## Measuring again

The benchmarks (criterion with a TSC clock, callgrind and dhat runs, and a
flood test) aren't part of the repository yet. They reach doorward's
internals through a feature that only the benchmark build turns on.
