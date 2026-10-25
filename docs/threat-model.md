# doorward threat model

This is what doorward defends, against whom, how, and where its protection
stops. Each defence names the test that checks it. It covers doorward 0.1.1.

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

## Threats and defences

### Guessing passwords (A1, A2, A6)

- Argon2id sized to the machine: 19–256 MiB and about 350 ms per check, never
  below OWASP's minimum. `password::tests`, `policy::tests`.
- Each visitor (IPv4 address or IPv6 /64) has its own budget: 20 attempts,
  then one per 3 seconds; slowed after 5 failures; refused for 15 minutes
  after 20 failures in 15 minutes. `limits::tests`,
  `sign_in::floods_slow_only_the_flooder_and_remembered_browsers_get_through`.
- Accounts are never locked (a lock anyone can trigger is a denial of
  service). Same test.
- New passwords: at least 8 characters by default (apps can ask for 15), none
  of the 5,000 most common, not containing the username or the app's refused
  words, no composition rules, at least 64 characters allowed.
  `sign_in::easy_passwords_are_refused`.
- Passkeys need no secret on the server and require user verification.

### Locking the owner out (A1, A6)

- A flood from one visitor only slows that visitor. `limits::tests`.
- A remembered browser (one that signed in before) has its own budget and
  skips the per-visitor slow-down, so a flood from the owner's own address
  can't stop them. `sign_in::floods_slow_only_the_flooder…`,
  `sign_in::a_remembered_browser_counts_only_for_its_own_user`.
- Only one or two password checks run at once (bounded memory), and visitors
  without a remembered browser get at most one of those slots, so remembered
  browsers always have one. `doorward::tests::remembered_browsers_skip_the_visitor_queue`.
- Open passkey requests are capped per visitor (32) and per session (4); a
  full table refuses new requests instead of dropping old ones, so nobody
  can push out a sign-in in progress. `passkey::tests`,
  `passkeys::open_requests_are_capped_per_visitor`.
- The tables that track visitors are bounded, and a flood of fresh addresses
  can't wash out a visitor that is being refused.
  `limits::tests::tables_stay_bounded_and_keep_the_ones_with_failures`.

### Learning who has an account (A1)

- Unknown usernames and wrong passwords give the same error, take the same
  store steps, and check a stand-in hash, so they take as long.
  `sign_in::wrong_password_and_unknown_user_look_the_same`,
  `password::tests::hash_check_and_rehash`.
- Usernames are compared case-insensitively after Unicode normalisation, and
  names that look alike (UTS #39 skeletons) can't both exist, so an attacker
  can't register a look-alike of a real user. `username::tests`,
  `sign_in::accounts_and_names`.

### Pretending to be another address (A2)

- Every request must be sent to one of the app's addresses.
  `sign_in::addresses_are_checked`.
- A proxied address matches only requests that came from a trusted proxy,
  said whom they forward for, and were forwarded over HTTPS. A LAN device that
  merely claims the public name gets nothing, and requests through the
  proxy can't reach a LAN-only name. Same test.
- The visitor's address comes from `CF-Connecting-IP` or the right-most
  untrusted `X-Forwarded-For` entry, only from a trusted proxy (pingrail 0.3
  took the left-most, which the visitor writes).
  `net::tests::forwarded_for_is_read_from_the_right`.

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
- The JSON endpoints accept only `application/json`, which a cross-site form
  can't send without the browser asking first.
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
- Changing the password needs the current one, ends every other session and
  issues a new cookie. `sign_in::changing_a_password_needs_the_current_one`.
- Adding or removing a passkey ends every other session.
  `passkeys::adding_a_passkey_needs_a_recent_sign_in_and_ends_other_sessions`.
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
- Passwords, tokens and cookies never appear in logs, errors or `Debug`
  output. `sign_in::sign_in_sign_out`, `password::tests::debug_shows_no_hash`.
- Security events go to their own log target (`doorward::security`) and to
  the store, with who, when, where and what.

## Where protection stops

doorward is tested thoroughly, but **testing is not an independent audit**.
Have one done before a public, multi-user site goes live.

- **Cross-site scripting in the app defeats much of this.** A script running
  in the app's own pages can make requests as the user (it can't read the
  cookie). Recent-sign-in checks still demand the password or a passkey.
  The app must keep its own pages free of injection (a strict Content
  Security Policy helps; the example sets one).
- **A large distributed flood** of password guesses from many addresses can
  keep the password-check slots busy, so visitors *without* a remembered
  browser may be told "busy". Remembered browsers and passkey sign-in keep
  working.
- **IPv6 /64 grouping** gives an attacker with many /64s many budgets. Their
  guesses are still slowed by the Argon2 cost and the global check limit.
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
