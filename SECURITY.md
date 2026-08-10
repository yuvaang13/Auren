# Security Policy

## Scope

Auren is a **cooperative guardrail**, not an adversarial security boundary.
This policy covers defects that undermine the guarantees it *does* claim:

- **fail-closed gating**: turning Protection OFF requires a successful
  OS-native biometric/passcode check; a failed or cancelled check leaves
  protection ON, and the unlock itself waits out a 10-second cooldown.
  Documented exception: a **graceful quit** (Cmd+Q / menu quit) writes a
  signed `mode: off` config so the daemon restores DNS — this is intentional
  cooperative behavior, equivalent to an authenticated off, and it only runs
  on graceful quit (crash/force-quit still leaves the daemon fail-closed);
- **fail-closed tamper detection**: config tampering, an unreadable encrypted
  store, missing signing key, or a silent daemon (missed heartbeats) must
  result in deny-all enforcement and a visible degraded state, never silent
  open access;
- **centralized block state**: the canonical block list lives only in the main
  process (encrypted at rest, 0600 perms, verified at startup); no renderer or
  bridge component holds its own writable copy;
- **OS/terminal-level network blocking**: while Protection is ON the root
  daemon loads a dedicated pf anchor (`auren`) that blocks ICMP echo, outbound
  command ports (SSH/FTP/Telnet/SMB/…), and cloud-metadata IPs. The daemon
  must only ever touch its own anchor — never the main pf ruleset, never
  flushing a pre-existing pf configuration, never disabling pf on teardown —
  and must load the blocking rules when it cannot verify the signed config
  (fail-closed), matching the DNS deny-all posture;
- **the privacy invariant**: no biometric or credential data ever passes
  through Auren's process — it only consumes pass/fail results from OS APIs;
- **accidental collection or transmission of private data** (the activity log
  must never contain more than domain, timestamp, outcome, and a classifier
  type label — never the underlying values);
- **config handling**: the privileged daemon treats `config.json` as untrusted
  input, verifies the HMAC signature, and re-validates everything it reads.

It does **not** cover bypasses documented in the README's "What this does NOT
do yet" and "Storage, integrity, and fail-closed guarantees" (e.g. an agent
with root reconfiguring DNS or stopping the daemon, an admin removing the
OS-level hook outside the app, same-account read-all defeating at-rest
encryption, or apps using their own DoH resolver) — those are accepted
limitations, not vulnerabilities. The OS firewall is likewise a cooperative
layer with known limits: terminal `curl`/`wget` to HTTPS (port 443) is
indistinguishable from browsing and is not blocked, and network-free local code
execution (`rm -rf`, `osascript`, compiled binaries) is outside Auren's reach
— stopping that requires the agent itself to run in a sandbox.

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
