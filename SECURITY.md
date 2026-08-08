# Security Policy

## Scope

Auren is a **cooperative guardrail**, not an adversarial security boundary.
This policy covers defects that undermine the guarantees it *does* claim:

- **fail-closed gating**: turning Protection OFF requires a successful
  OS-native biometric/passcode check; a failed or cancelled check leaves
  protection ON;
- **the privacy invariant**: no biometric or credential data ever passes
  through Auren's process — it only consumes pass/fail results from OS APIs;
- **accidental collection or transmission of private data** (the activity log
  must never contain more than domain, timestamp, and outcome);
- **config handling**: the privileged daemon treats `config.json` as untrusted
  input and re-validates everything it reads.

It does **not** cover bypasses documented in the README's "What this does NOT
do yet" (e.g. an agent with root reconfiguring DNS or stopping the daemon, or
apps using their own DoH resolver) — those are accepted limitations, not
vulnerabilities.

## Reporting

Please report suspected issues privately before disclosing publicly. If this
project is published with a maintainer contact, that contact is the reporting
channel; until then, open an issue that omits any sensitive detail and ask for
a private channel.

Please include: affected version/commit, steps to reproduce, expected vs
actual behavior, and whether it involves biometric/credential data or the
biometric gate.

We aim to acknowledge within 3 business days and to ship a fix (or a documented
decision) promptly after that.

## Supported versions

Only the latest release is supported. Between releases, fixes land on `main`
and are backported only if a security issue demands it.

## Disclosure

We prefer coordinated disclosure: 30 days for standard issues before public
advisory, or longer if a fix needs more time. We'll credit reporters unless
they ask not to.
