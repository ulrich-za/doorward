# OWASP ASVS 5.0 checklist

doorward measured against the authentication and session chapters of the
[OWASP Application Security Verification Standard 5.0.0](https://github.com/OWASP/ASVS/tree/master/5.0),
plus the related cookie, cryptography, caching and logging requirements.
Requirement numbers are ASVS 5.0's; L is the level that first asks for it.

Status: **Met** (with the test that checks it), **App** (the app's
responsibility; doorward gives it what it needs), **Partly**, or **Later**
(planned, with the release).

## V6 Authentication

| # | L | Requirement (short) | Status | Where it's checked |
|---|---|---|---|---|
| 6.1.1 | 1 | Rate limiting and anti-automation documented | Met | [threat-model.md](threat-model.md), "Guessing passwords" |
| 6.1.2 | 2 | Context-specific words documented | App | List them with `Builder::refuse_password_words` |
| 6.1.3 | 2 | All sign-in pathways documented | Met | [integration.md](integration.md): password, passkey, per address |
| 6.2.1 | 1 | Passwords at least 8 characters (15 recommended) | Met | `PasswordRules::min_chars` (default 8); `sign_in::easy_passwords_are_refused` |
| 6.2.2 | 1 | Users can change their password | Met | `change_password`; `sign_in::changing_a_password_needs_the_current_one` |
| 6.2.3 | 1 | Change needs current and new password | Met | Same test; passkey-only users need a recent sign-in instead |
| 6.2.4 | 1 | Checked against the top 3,000 passwords | Met | 5,000 most common of 8+ characters; `common::tests`, `sign_in::easy_passwords_are_refused` |
| 6.2.5 | 1 | No composition rules | Met | `sign_in::easy_passwords_are_refused` |
| 6.2.6 | 1 | `type=password` fields | App | The example's form does |
| 6.2.7 | 1 | Paste and password managers allowed | App | Nothing in doorward blocks them |
| 6.2.8 | 1 | Password verified exactly as entered | Met | No truncation or case change; `password::tests::unicode_passwords_are_byte_exact` |
| 6.2.9 | 2 | 64+ character passwords allowed | Met | Up to 256 characters by default; `sign_in::easy_passwords_are_refused` |
| 6.2.10 | 2 | No forced periodic rotation | Met | doorward never expires passwords |
| 6.2.11 | 2 | Context words refused | Met | `refuse_password_words`; same test |
| 6.2.12 | 2 | Checked against breached passwords | Later | Optional leaked-password check, before the public site |
| 6.3.1 | 1 | Brute-force controls implemented as documented | Met | `limits::tests`, `sign_in::floods_slow_only_the_flooder…` |
| 6.3.2 | 1 | No default accounts | Met | doorward makes no accounts (the demo's `admin` is the demo's) |
| 6.3.3 | 2 | MFA, or a combination of factors | Partly | Passkeys with user verification are multi-factor; password-only is the app's choice per address |
| 6.3.4 | 2 | No undocumented pathways; strength consistent | Met | Passwords and passkeys switched per address; `passkeys::passkeys_are_refused_where_turned_off` |
| 6.3.5 | 3 | Users told of suspicious attempts | Partly | Failed and successful sign-ins are in the user's security log (`events`); notifications come with the notification hook |
| 6.3.7 | 3 | Users told after credential changes | Partly | Logged (`password_changed`, `passkey_added`…); notifications with the hook |
| 6.3.8 | 3 | Valid users can't be deduced | Met | Same error, same steps, same budget, stand-in hash, answers padded to a current check; `sign_in::wrong_password_and_unknown_user_look_the_same`, `sign_in::unknown_names_take_as_long_after_the_hashing_is_retuned`, `sign_in::an_own_remembered_browser_reveals_no_usernames` |
| 6.4.1 | 1 | Initial secrets random, short-lived | Later | One-time links (pingrail 0.5 step) |
| 6.4.2 | 1 | No hints or secret questions | Met | None exist |
| 6.4.3 | 2 | Secure forgotten-password process | Later | Recovery codes, slower recovery (before the public site) |
| 6.4.6 | 3 | Admins start resets but don't choose passwords | Later | Today `set_password` lets an admin choose; one-time links will allow the stricter flow |
| 6.5.6 | 3 | Any factor can be revoked | Met | Remove a passkey, end sessions; `passkeys::the_last_way_in_cant_be_removed`, `sign_in::ending_sessions` |
| 6.7.2 | 3 | Challenge at least 64 bits, unique | Met | webauthn-rs uses 32 random bytes per ceremony |

## V7 Session management

| # | L | Requirement (short) | Status | Where it's checked |
|---|---|---|---|---|
| 7.1.1 | 2 | Timeouts documented and justified | Met | Session lengths in the plan and `SessionLengths`; apps set them per address |
| 7.1.2 | 2 | Concurrent sessions documented | Met | Up to 50 per account by default (`max_sessions_per_user`; a sign-in beyond ends the oldest); each listed and endable (`sessions`) |
| 7.2.1 | 1 | Tokens verified on the backend | Met | Reference tokens looked up by hash on every request |
| 7.2.2 | 1 | Dynamic tokens, not static secrets | Met | New random token per sign-in |
| 7.2.3 | 1 | Reference tokens from a CSPRNG, 128+ bits | Met | 256 bits from the OS; `token::tests` |
| 7.2.4 | 1 | New token on authentication and re-authentication | Met | `sign_in::a_new_sign_in_replaces_a_planted_cookie`, `sign_in::recent_sign_in_and_confirming`, `passkeys::confirming_with_a_passkey` |
| 7.3.1 | 2 | Inactivity timeout | Met | `SessionLengths::idle`; `sign_in::sessions_expire` |
| 7.3.2 | 2 | Absolute lifetime | Met | `SessionLengths::max`; same test |
| 7.4.1 | 1 | Terminated sessions can't be used | Met | Deleted server-side; `sign_in::sign_in_sign_out` |
| 7.4.2 | 1 | Disabling or deleting an account ends its sessions | Met | `sign_in::disabled_accounts` |
| 7.4.3 | 2 | Option to end other sessions after a factor change | Met | They always end, and other remembered browsers are forgotten; `sign_in::changing_a_password_ends_other_sessions` |
| 7.4.4 | 2 | Visible sign-out | App | `POST /sign-out`; the app shows the button |
| 7.4.5 | 2 | Admins can end a user's sessions | Met | `end_all_sessions` |
| 7.5.1 | 2 | Re-authentication before changing sign-in details | Met | Passkeys and password changes need a recent sign-in or the current password |
| 7.5.2 | 2 | Users view and end sessions, after re-authenticating | Met | `sessions`, `end_session` (recent sign-in for others); `sign_in::ending_sessions` |
| 7.5.3 | 3 | Extra authentication before very sensitive actions | App | `Recent` extractor / `require_recent` |
| 7.6.2 | 2 | Sessions only from an explicit user action | Met | Only sign-in creates sessions |

## Related requirements

| # | L | Requirement (short) | Status | Where it's checked |
|---|---|---|---|---|
| 3.3.1 | 1 | Cookies `Secure`, `__Host-`/`__Secure-` prefix | Met | Builder refuses other names; `sign_in::sign_in_sign_out`, browser check |
| 3.3.2 | 2 | `SameSite` set for the purpose | Met | `Strict` |
| 3.3.3 | 2 | `__Host-` prefix | Met | Same |
| 3.3.4 | 2 | `HttpOnly` for session cookies | Met | Browser check: `document.cookie` is empty |
| 3.3.5 | 3 | Cookie under 4,096 bytes | Met | Names ≤ 64, values 43 characters |
| 11.4.2 | 2 | Approved password hashing with current parameters | Met | Argon2id, OWASP floor, machine-sized |
| 11.5.1 | 2 | CSPRNG with 128+ bits for unguessable values | Met | Tokens 256 bits, request ids 128 bits, user ids UUID v4 from the OS |
| 14.3.2 | 2 | `Cache-Control: no-store` on sensitive responses | Met | Every response of the ready-made endpoints, errors included; `http::nothing_is_cacheable`. The app's own pages are the app's |
| 16.2.1 | 2 | Log entries say when, where, who, what | Met | `EventRecord`: time (UTC ms), address, IP, user, kind |
| 16.2.5 | 2 | Sensitive data not logged | Met | No passwords, tokens or cookies in logs or in doorward's `Debug` output; `sign_in::debug_output_hides_secrets` |
| 16.3.1 | 2 | All authentication logged, success and failure | Met | Every event on the `doorward::security` log target, even when the visitor hangs up mid-check; the store keeps every success and change and rations failures, counting the rest; `sign_in::wrong_password_and_unknown_user_look_the_same`, `disconnect`, `sign_in::failures_kept_in_the_store_are_rationed` |
| 16.3.3 | 2 | Attempts to bypass controls logged | Met | Cross-origin refusals, refused saved hashes, sessions on the wrong address |
