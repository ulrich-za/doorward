# Security policy

doorward handles sign-in, so flaws in it matter. Thank you for reporting them
privately.

## Reporting a flaw

Report it privately through GitHub: on the repository's **Security** tab,
choose **Report a vulnerability**. Please include:

- the doorward version and features you use,
- what an attacker can do, and the steps to reproduce it,
- any proof-of-concept code or logs (with secrets removed).

Please don't open a public issue or pull request for a security flaw until a
fix has been released.

## What to expect

- An acknowledgement within 5 days.
- An assessment and a plan within 14 days.
- A fixed release as soon as one is ready, normally within 30 days for serious
  flaws, followed by a RustSec advisory where it applies.
- Credit in the CHANGELOG and advisory, unless you'd rather not be named.

## Supported versions

Only the latest release receives security fixes while doorward is below 1.0.

## Scope

In scope: anything in this repository, including how it uses its
dependencies. Flaws in a dependency itself should go to that project too; tell
us as well if doorward is affected.

Out of scope: problems that need an attacker who already controls the
server, its database or its configuration, unless doorward makes them worse
than they need to be.
