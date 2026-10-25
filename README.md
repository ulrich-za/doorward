# doorward

Headless sign-in for Rust web apps. doorward is the doorkeeper: it answers
"who is this request, and may they?" and leaves every screen to the app.

The name is the old English word for a doorkeeper, the job Háma holds at the
doors of Théoden's hall.

## This release

0.1.0 contains the first piece: **Argon2id password hashing sized to the
machine it runs on**. It is the hashing pingrail 0.3 uses, moved into a
library unchanged in behaviour.

- **Memory per check** is chosen from the machine: 2 % of total memory or
  10 % of free memory, whichever is smaller, split between two checks at a time
  when each still gets 32 MiB, and held to 19–256 MiB per check. On Linux the
  limits of a container or systemd service are honoured.
- **Passes** are timed on the machine so a check takes about a third of a
  second, never below OWASP's minimum (19 MiB with 2 passes, or 46 MiB with 1).
- **The chosen settings are saved by the app** and reused. They are timed again
  when total memory changes by more than a fifth, or on request.
- **Saved hashes keep working** after the settings change, and are reported as
  needing a rehash at their next successful sign-in.
- **Unknown users take as long** as real ones: a stand-in hash is checked.
- **One or two checks at a time** (with the `tokio` feature), so a flood of
  sign-ins can use at most 512 MiB, whatever happens.
- **Tampered or corrupt saved hashes** that ask for absurd work are refused
  rather than tried, and passwords over 1 KiB are refused before hashing.

```rust,no_run
use doorward::password::{HashPolicy, Hasher, Verdict};

fn main() -> Result<(), doorward::Error> {
    let saved: Option<String> = None; // wherever your app keeps settings

    // Reuse the saved policy, or time this machine (a second or two).
    let (policy, changed) = HashPolicy::load_or_tune(saved.as_deref(), false)?;
    if changed {
        // save policy.to_json()
    }
    println!("password hashing: {}", policy.describe());

    let hasher = Hasher::new(policy)?;
    let phc = hasher.hash("correct horse battery staple")?;
    match hasher.verify("correct horse battery staple", Some(&phc)) {
        Verdict::Good { rehash } => { /* signed in; if rehash, hash again and save */ }
        Verdict::Wrong => { /* refuse */ }
        Verdict::Busy => { /* not enough memory right now: ask to retry */ }
    }
    Ok(())
}
```

In an async server, use `Hasher::verify_async` and `Hasher::hash_async`: they
wait for a turn and run the check on a blocking thread.

## Features

| Feature | Default | What it adds |
|---|---|---|
| `serde` | yes | `HashPolicy::load_or_tune`, `to_json`, `from_json` |
| `tokio` | yes | `Hasher::turn`, `verify_async`, `hash_async` |
| `detect-memory` | yes | Memory detection on systems other than Linux (through `sysinfo`) |

doorward contains no `unsafe` code (`#![forbid(unsafe_code)]`).

## What comes next

Passkeys, sessions bound to the address they were made on, per-visitor rate
limits that nobody can use to lock you out, trusted devices and the rest of
sign-in. See the CHANGELOG for what each release contains.

## Licence

Copyright 2026 Ulrich Holtzhausen. Licensed under the
[Apache License, Version 2.0](LICENSE).

Report security problems as described in [SECURITY.md](SECURITY.md).
