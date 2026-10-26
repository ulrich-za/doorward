# doorward threat model

This is what doorward defends, against whom, how, and where its protection
stops. Each defence names the test that checks it. It covers doorward 0.1.1,
including the fixes from the review before 0.1.0 (each finding is now a
regression test, listed under "Reviewed before release") and from the
performance analysis for 0.1.1 ([performance.md](performance.md)).

## What is protected

- **Accounts:** the right to act as a user. Passwords (stored as Argon2id
  hashes), passkeys (stored as public keys), roles.
- **Sessions:** the cookies that stand for a signed-in user.
- **Getting in:** the owner's ability to sign in, even while someone attacks.
- **Who has an account:** sign-in shouldn't reveal which usernames exist.
- **The security log:** a record of sign-ins, failures and changes.

## The pieces and who trusts whom

```
browser ──HTTPS──▶ [cloudflared / reverse proxy] ──HTTPS──▶ app (doorward inside) ──▶ database
```

- **The machine's configuration is trusted:** the address list, the trusted
  proxies, the cookie names. It is set in code or config on the machine, never
  through the web UI, so a stolen session can't add an address of its own.
- **A trusted proxy is believed** about the visitor's address and the scheme,
  but only when the connection really comes from it.
- **The browser is not trusted.** Every header, cookie and body is input.
- **The database is semi-trusted.** It holds nothing usable to sign in (only
  hashes), and values read back are bounded so a tampered row can't make the
  server do unbounded work.

## Attackers

| | Who | Can |
|---|---|---|
| A1 | Anyone on the internet | Reach public addresses through the proxy; guess passwords; flood; relay a phishing page; run their own site in the victim's browser |
| A2 | Someone on the LAN | Reach the app directly; send any Host and forwarding headers |
| A3 | A site open in the user's browser | Make the browser send requests to the app, with its cookies when SameSite allows |
| A4 | Someone with a copy of the database | Read every stored value, offline |
| A5 | Someone who stole a session cookie | Send requests as that session |
| A6 | Someone sharing the user's IP address | Use up per-address budgets |
| A7 | Someone with an account of their own | Sign in, collect device cookies, start passkey requests as a signed-in user |

## Threats and defences

### Guessing passwords (A1, A2, A6, A7)

- Argon2id sized to the machine: 19–256 MiB and about 350 ms per check, never
  below OWASP's minimum. `password::tests`, `policy::tests`.
- Each visitor (IPv4 address or IPv6 /64) has its own budget: 20 attempts,
  then one per 3 seconds; slowed after 5 failures; refused for 15 minutes
  after 20 failures in 15 minutes. `limits::tests`,
  `sign_in::floods_slow_only_the_flooder_and_remembered_browsers_get_through`.
- A remembered browser's own budget only counts attempts at its own account.
  Guesses at anyone else's account, or at names that don't exist, count
  against the visitor whatever device cookies they carry, and collecting
  device cookies (one per sign-in) buys no extra guesses.
  `sign_in::new_remembered_cookies_give_no_extra_guesses`.
- A guess is counted even when the visitor hangs up mid-check: the check and
  its counting run on their own, and finish. `disconnect` (a real server).
- A visitor without a remembered-browser cookie is checked against its
  budget before any other work, so a refused attempt costs no store lookup
  (with such a cookie, the cookie is looked up first, and any name other
  than the cookie owner's takes the same steps), and usernames are
  normalised only up to the length limit.
  `store_calls::a_refused_attempt_costs_no_store_work`,
  `store_calls::with_a_remembered_browser_any_other_name_takes_the_same_steps`.
- Accounts are never locked (a lock anyone can trigger is a denial of
  service). Same test as the flood above.
- New passwords: at least 8 characters by default (apps can ask for 15), none
  of the 5,000 most common, not containing the username or the app's refused
  words, no composition rules, at least 64 characters allowed.
  `sign_in::easy_passwords_are_refused`.
- Passkeys need no secret on the server and require user verification.

### Locking the owner out (A1, A6)

- A flood from one visitor only slows that visitor. `limits::tests`.
- A remembered browser (one that signed in before) has its own budget, shared
  by its account's remembered browsers, and skips the per-visitor slow-down,
  so a flood from the owner's own address can't stop them.
  `sign_in::floods_slow_only_the_flooder…`,
  `sign_in::a_remembered_browser_counts_only_for_its_own_user`.
- Only one or two password checks run at once (bounded memory), and visitors
  without a remembered browser take turns at one of them. With two at once,
  one is always free for remembered browsers; with one at once, a remembered
  browser waits for at most the visitor check under way. A turn is held until
  the hashing really ends, even when the visitor hangs up.
  `doorward::tests::remembered_browsers_skip_the_visitor_queue`,
  `sign_in::an_account_holder_cant_starve_remembered_browsers`,
  `password::tests::a_dropped_check_keeps_its_turn_until_the_hashing_ends`,
  `disconnect`.
- Each account keeps its five most recently used remembered browsers; older
  ones are forgotten. `sign_in::new_remembered_cookies_give_no_extra_guesses`.
- Starting a passkey sign-in counts against the visitor's (or remembered
  browser's) budget. Open passkey requests are capped per visitor (8), per
  network around it (an IPv4 /24 or IPv6 /48: 64), per account from its
  remembered browsers (8) and per signed-in account (4), and in all (10,000
  each for visitors, remembered browsers and signed-in users). A full table
  refuses new requests instead of dropping old ones, so nobody can push out a
  sign-in in progress, and visitors can't fill the tables remembered
  browsers and signed-in users use. `passkey::tests`,
  `passkeys::open_requests_are_capped_per_visitor`,
  `passkeys::open_requests_are_capped_per_network`,
  `passkeys::starting_a_passkey_sign_in_counts_against_the_budget`,
  `passkeys::account_holders_cant_block_the_owners_passkey_sign_in`.
- The tables that track visitors are bounded. A visitor that is being
  refused is never forgotten to make room while others can be, so a flood of
  fresh addresses (even failing ones) can't wash it out; only past twice the
  table's size are the refusals that end soonest forgotten. A table full of
  refusals is scanned for room once per tenth of its size, not for every
  newcomer, so such a flood can't make each request slow.
  `limits::tests::a_table_full_of_refusals_is_scanned_once_per_tenth`.
  `limits::tests::a_failing_flood_cant_wash_out_a_refused_visitor`,
  `limits::tests::refused_entries_stay_bounded`,
  `sign_in::a_failing_flood_cant_wash_out_a_refused_visitor`.

### Learning who has an account (A1, A7)

- Unknown usernames and wrong passwords give the same error, take the same
  store steps, and check a stand-in hash made with the current settings. A
  real user's hash may still have older, cheaper settings (until their next
  sign-in, for example after a retune), so every answer is held back to a
  floor above a normal check: a quarter more than the slowest of the
  calibrated time and two checks timed at start, raised to a tenth more
  than the slowest of the last 16 current-settings checks when the machine
  is busy. Answers for unknown names and for older hashes then both come at
  the floor. `sign_in::wrong_password_and_unknown_user_look_the_same`,
  `sign_in::unknown_names_take_as_long_after_the_hashing_is_retuned`,
  `password::tests::answers_never_come_sooner_than_a_current_check`,
  `password::tests::older_hashes_answer_no_sooner_than_unknown_names`,
  `password::tests::the_floor_follows_slow_checks_up_to_a_cap`.
- An account holder's own remembered browser doesn't help: attempts at names
  that don't exist count against the same budget as attempts at other
  people's accounts. `sign_in::an_own_remembered_browser_reveals_no_usernames`.
- Usernames are compared case-insensitively after Unicode normalisation, and
  two names with the same UTS #39 skeleton can't both exist, so a look-alike
  of a real user that Unicode's confusables data knows about can't be
  registered. The skeleton is taken of the name as written and again after
  lowercasing, so case-dependent look-alikes ("PayPaI" with a capital I)
  collide too. `username::tests`, `sign_in::accounts_and_names`,
  `sign_in::look_alikes_that_depend_on_case_are_refused`.
- How far this goes: UTS #39 lists characters that look alike, not every pair
  of names a person might confuse, and an app's own screens may show names in
  a font where other pairs look alike.

### Pretending to be another address (A2)

- Every request must be sent to one of the app's addresses.
  `sign_in::addresses_are_checked`.
- A proxied address matches only requests that came from a trusted proxy,
  said whom they forward for, and were forwarded over HTTPS. A LAN device that
  merely claims the public name gets nothing, and requests through the
  proxy can't reach a LAN-only name. Same test.
- The visitor's address comes from the right-most untrusted
  `X-Forwarded-For` entry, only from a trusted proxy (pingrail 0.3 took the
  left-most, which the visitor writes). `CF-Connecting-IP` is believed only
  when the app says its trusted proxies are Cloudflare's
  (`trust_cf_connecting_ip`), since other proxies pass it through as the
  visitor wrote it. `net::tests::forwarded_for_is_read_from_the_right`,
  `net::tests::cf_connecting_ip_is_believed_only_from_cloudflare`,
  `sign_in::cf_connecting_ip_is_believed_only_when_the_proxy_is_cloudflare`.

### Requests forged by another site (A3)

- Cookies are `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Strict`,
  `Path=/`. `sign_in::sign_in_sign_out`, browser check.
- Writes (anything but GET, HEAD, OPTIONS) with a session must come from the
  address's own origin (`Sec-Fetch-Site` or `Origin`); this also covers
  another port on the same host, which `SameSite` doesn't.
  `doorward::tests::origin_checks`, `sign_in::cross_site_requests_are_refused`,
  `http::cross_site_writes_are_refused`, browser check
  (`tests/browser/passkeys.py`).
- Sign-in itself checks the origin too, so a site can't sign a victim in to
  the attacker's account. `sign_in::cross_site_requests_are_refused`.
- The endpoints that take a body accept only `application/json`, which a
  cross-site form can't send without the browser asking first; the ones
  without a body rely on the origin check above.
  `http::refusals_have_the_right_status_and_headers`.

### Phishing and relayed passkeys (A1)

- A passkey is bound to its address's name and exact origin (port included);
  webauthn-rs checks the origin in the signed client data, the relying party
  hash, the challenge, user verification and the counter.
  `passkeys::forged_answers_are_refused`, `passkeys::passkeys_work_only_where_they_were_made`.
- A cloned security key is caught when its counter goes backwards.
  `passkeys::a_cloned_security_key_is_caught_by_its_counter`.
- A credential id can be registered to one account only.
  `passkeys::the_same_passkey_cant_be_registered_twice`, store conformance.
- Passkey requests are single-use, expire after two minutes, and are tied to
  the address (and for adding or confirming, the session) they began on.
  `passkeys::requests_are_single_use_and_tied_to_their_address_and_session`.

### A stolen session cookie (A5)

- The cookie can't be read by scripts (`HttpOnly`) and only travels over
  HTTPS to the exact host (`__Host-`).
- A session works only on the address it was made on.
  `sign_in::sessions_belong_to_their_address`.
- Idle and absolute limits per address. `sign_in::sessions_expire`.
- Sensitive actions need a sign-in from the last 10 minutes, and confirming
  issues a new cookie. `sign_in::recent_sign_in_and_confirming`,
  `passkeys::confirming_with_a_passkey`.
- Changing the password needs the current one, ends every other session,
  forgets the account's other remembered browsers and issues new cookies.
  An admin reset, removing the password, or disabling the account ends the
  sessions and forgets every remembered browser.
  `sign_in::changing_a_password_needs_the_current_one`,
  `sign_in::changing_a_password_ends_other_sessions`,
  `sign_in::disabling_an_account_forgets_its_remembered_browsers`.
- Adding or removing a passkey ends every other session.
  `passkeys::adding_a_passkey_needs_a_recent_sign_in_and_ends_other_sessions`.
- A user has at most 50 sessions (`max_sessions_per_user`); a sign-in
  beyond that ends the oldest. `sign_in::sign_ins_beyond_the_session_limit_end_the_oldest`.
- Every sign-in gets a new cookie and ends the one the browser had, so a
  planted cookie can't ride along (session fixation).
  `sign_in::a_new_sign_in_replaces_a_planted_cookie`.
- The user can list their sessions and end any of them.
  `sign_in::ending_sessions`.

### A copy of the database (A4)

- Passwords: Argon2id with a fresh salt each.
- Session and remembered-browser cookies: stored as SHA-256 of 256 random
  bits, so the database can't be used to sign in, and there is no server
  secret to steal. `token::tests`, store conformance.
- Passkeys: public keys only.
- doorward-sqlite creates its file readable by its owner only, and sets
  `secure_delete` so deleted rows are overwritten.

### A tampered database (A6)

- A saved hash asking for more than 1 GiB, 32 passes, 16 lanes or 4 GiB-passes
  in total is refused rather than tried.
  `password::tests::absurd_saved_settings_are_refused`.
- Unreadable rows (a passkey that won't decode) are skipped and logged.

### Leaking secrets through logs and errors

- Error responses carry only a code (`{"error": "…"}`); details go to the log.
  `http::refusals_have_the_right_status_and_headers`.
- Passwords, tokens and cookies never appear in logs or errors, nor in the
  `Debug` output of doorward's types (`RequestInfo` hides the `Cookie` and
  `Authorization` headers; `NewUser`, `SetCookie`, `Visit` and `SignedIn`
  hide their secrets). `sign_in::sign_in_sign_out`,
  `sign_in::debug_output_hides_secrets`, `password::tests::debug_shows_no_hash`.
- Every response from the ready-made endpoints, errors included, says
  `Cache-Control: no-store`. `http::nothing_is_cacheable`.
- Security events go to their own log target (`doorward::security`) and to
  the store, with who, when, where and what.
- Every event reaches the log target. In the store, failed attempts are
  rationed (per account 50 at once, then one every five minutes; without an
  account 100 at once, then one every 30 seconds) and the rest are reported
  in a `failures_not_stored` row at the next upkeep, with the count, the
  first and last time and the first few addresses, so a flood of cheap
  failures (a wrong passkey answer costs no hashing) can't fill the
  database or crowd out its writes. Someone who knows a username can use
  up that account's 50 stored rows with junk; later failures are then only
  counted in the store (and fully on the log target). `_refused` events,
  which need a valid credential, are never rationed. `limits::tests::stored_failures_are_rationed_per_account_and_without_one`,
  `sign_in::failures_kept_in_the_store_are_rationed`,
  `passkeys::failures_with_no_account_are_rationed_in_the_store`.

## Where protection stops

doorward is tested thoroughly, but **testing is not an independent audit**.
Have one done before a public, multi-user site goes live.

- **Cross-site scripting in the app defeats much of this.** A script running
  in the app's own pages can make requests as the user (it can't read the
  cookie). Recent-sign-in checks still demand the password or a passkey.
  The app must keep its own pages free of injection (a strict Content
  Security Policy helps; the example sets one).
- **A large distributed flood** of password guesses from many addresses can
  keep the visitors' password-check turn busy, so visitors *without* a
  remembered browser may be told "busy". Likewise, requests from many
  networks can fill the visitors' passkey table (10,000 open requests, so at
  least 157 networks of 64 each), and visitors without a remembered browser
  are then asked to retry. Remembered browsers and signed-in users keep
  working throughout.
- **Many accounts, many budgets.** Each account's remembered browsers have a
  budget for that account (10 attempts, then one every 6 seconds), and each
  account may hold 8 passkey requests through them and 4 as a signed-in user.
  Someone holding many accounts can use all of their budgets to keep the
  password checks busy. doorward never makes accounts on its own: an app
  that lets anyone sign up should limit sign-ups.
- **IPv6 /64 grouping** gives an attacker with many /64s many budgets. Their
  guesses are still slowed by the Argon2 cost and the global check limit.
- **Visitors behind one address** (an office, or a mobile carrier's shared
  addresses) share a budget and 8 open passkey requests. A busy sign-in page
  behind one address may see "too many attempts"; its remembered browsers
  don't.
- **Rate-limit state and passkey requests live in memory**, per process. A
  restart resets the counters; several copies of the app behind a load
  balancer need sticky sessions until shared storage is added (planned
  before the public site).
- **The clock is trusted.** Large jumps of the system clock move session
  expiry and rate-limit windows.
- **Sessions' idle time is recorded at most once a minute**, so an idle limit
  can end up to a minute early.
- **Not built yet:** one-time links, trusted devices, recovery codes, the
  notification hook, and data export and deletion for POPIA/GDPR. Until the
  notification hook exists, the app tells users about new sign-ins and
  changes itself, from the security log.
- **An admin can choose a user's password** (`set_password`). ASVS level 3
  asks that admins only start a reset; one-time links will allow that.
- **Platform code that couldn't be run here:** memory detection on Windows
  and macOS is compiled and checked in CI on those systems.

## Reviewed before release

An independent review of 0.1.0 before its release found the problems below.
All are fixed, and each one's proof is now a regression test.

| Finding | Fix | Regression test |
|---|---|---|
| A visitor who hung up mid-check freed its hashing turn while the hashing went on (unbounded memory) and skipped the failure count | Turns and the visitor gate are held until the hashing ends; the check and its counting run on their own | `disconnect`, `password::tests::a_dropped_check_keeps_its_turn_until_the_hashing_ends` |
| Passkey request tables could be filled: starting wasn't rate-limited, IPv6 /64s were cheap, and an account holder could mint remembered-browser cookies | Starting counts against the budget; caps per network and per account; tables swept at most once a second | `passkeys::open_requests_are_capped_per_network`, `passkeys::account_holders_cant_block_the_owners_passkey_sign_in` |
| An account holder could mint unlimited remembered-browser cookies, each with a fresh budget, and spend them on guesses that skipped the visitor queue | Budgets belong to the account, count only attempts at it, and an account keeps five remembered browsers | `sign_in::new_remembered_cookies_give_no_extra_guesses`, `sign_in::an_account_holder_cant_starve_remembered_browsers` |
| An own remembered browser told an account holder which usernames exist | Unknown names count like other people's accounts | `sign_in::an_own_remembered_browser_reveals_no_usernames` |
| `CF-Connecting-IP` was believed from any trusted proxy | Off unless `trust_cf_connecting_ip` | `sign_in::cf_connecting_ip_is_believed_only_when_the_proxy_is_cloudflare` |
| After retuning, unknown names took longer than real ones with older hashes | Answers padded to a current check | `sign_in::unknown_names_take_as_long_after_the_hashing_is_retuned` |
| Look-alikes that depend on case ("Ilse" and "llse") could both register | Skeletons of the name as written and lowercased | `sign_in::look_alikes_that_depend_on_case_are_refused` |
| `RequestInfo` and `NewUser` printed cookies and passwords in `Debug` output | Hidden | `sign_in::debug_output_hides_secrets` |
| Some endpoints lacked `Cache-Control: no-store` | Every response gets it | `http::nothing_is_cacheable` |
| A flood of failing addresses could wash out a refused visitor | Refused visitors are kept | `sign_in::a_failing_flood_cant_wash_out_a_refused_visitor` |
| A NUL in a typed username made Postgres fail (an internal error instead of "wrong") | Names no account can have aren't looked up | `sign_in::names_no_account_can_have_are_simply_wrong`, Postgres store test |
| The store conformance suite didn't check that per-user queries stay with their user | Checked for sessions, remembered browsers, passwords and the log | `conformance_catches::a_store_that_mixes_users_up_fails` |
| Remembered browsers were never forgotten after a password change, reset or disabling | Forgotten | `sign_in::changing_a_password_ends_other_sessions`, `sign_in::disabling_an_account_forgets_its_remembered_browsers` |
