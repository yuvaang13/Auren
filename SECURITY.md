# Security Policy

## Scope

Auren is a **cooperative guardrail**, not an adversarial security boundary.
This policy covers defects that undermine the guarantees it *does* claim:

- **fail-closed gating**: turning Protection OFF requires a successful
  OS-native biometric/passcode check; a failed or cancelled check leaves
  protection ON, and the unlock itself waits out a 10-second cooldown.
  Quitting the app while Protection is ON (or fail-closed) is gated the same
  way: quitting would lift protection, so it requires the same OS-native
  check; a failed or cancelled check cancels the quit and protection stays
  ON. A verified unlock cooldown still in flight counts as authenticated. A
  crash or force-quit (SIGKILL) skips the gate but also skips the `mode: off`
  write, leaving protection ON (deny-all), never open access;
- **fail-closed tamper detection**: config tampering, an unreadable encrypted
  store, missing signing key, or a silent daemon (missed heartbeats) must
  result in deny-all enforcement and a visible degraded state, never silent
  open access;
- **centralized block state**: the canonical block list (sites *and* apps)
  lives only in the main process (encrypted at rest, 0600 perms, verified at
  startup); no renderer or bridge component holds its own writable copy;
- **app blocking while Protection is ON**: the root daemon kills blocked apps
  (exact executable-path and argv-token matching — never substrings — with a
  safety floor that refuses entries pointing at the daemon's own interpreter)
  and re-kills them while protection stays ON; the block list is enforced from
  the same signed, fail-closed config as DNS and the firewall;
- **browser autofill blocking while Protection is ON** (default): the root
  daemon writes macOS managed-preferences plists for the Chromium-family
  browsers (Chrome, Chromium, Brave, Edge) forcing `PasswordManagerEnabled`,
  `AutofillAddressEnabled`, `AutofillCreditCardEnabled`, and `AutoFillEnabled`
  to `false`, so a browser session an agent controls cannot auto-fill saved
  passwords, addresses/phone numbers, or credit cards. The plists are written
  by the root daemon only (unprivileged processes can't delete them while
  protection is on) and removed on protection OFF; they take effect at browser
  launch. **Limitation (not a vulnerability of this layer):** the managed
  policy hooks exist only for the Chromium family — Safari and Firefox are not
  covered — and an already-running browser session retains its autofill
  state until restarted;
- **OS/terminal-level network blocking**: while Protection is ON the root
  daemon loads a dedicated pf anchor (`auren`) that blocks ICMP echo, outbound
  command ports (SSH/FTP/Telnet/SMB/DoT/…), cloud-metadata IPs, and the known
  public DoH/DoT endpoint IPs (logging packets it actually drops). Attempts to
  tunnel non-HTTPS protocols over port 443 are additionally flagged and blocked
  by the command classifier (`cmd_suspicious_443`). The daemon must only ever
  touch its own anchor — never the main pf ruleset, never flushing a
  pre-existing pf configuration, never disabling pf on teardown — and must load
  the blocking rules when it cannot verify the signed config (fail-closed),
  matching the DNS deny-all posture. As a root-owned safety floor, these
  terminal/DoH blocks cannot be disabled or allowlisted away while Protection
  is ON: the daemon re-applies a minimum-safety floor (terminal/DoH blocking
  ON, built-in blocked ports, cloud-metadata endpoints, and known DoH/DoT
  endpoints stripped from any allowlist, `dohHosts` extend-only) even when
  `settings.json` or the signed config has been tampered with or forged;
  `settings.json` itself is HMAC-signed (`settings.sig`) — a mismatch is
  logged, reset to safe defaults, and surfaced in the UI;
- **the privacy invariant**: no biometric or credential data ever passes
  through Auren's process — it only consumes pass/fail results from OS APIs;
- **keystroke shielding while Protection is ON**: Auren's window must be
  excluded from screen captures (`setContentProtection`), sensitive inputs must
  render masked, and while the Auren window holds keyboard focus macOS Secure
  Event Input must be enabled so keyboard-interception processes cannot read
  the user's keys — and must be released again on blur/window-close/quit so it
  never breaks other apps' keyboard-observing features. This shields Auren's
  own surface only; keystrokes typed in other apps are an accepted limitation
  (an agent with Screen Recording or Accessibility permission can still read
  those), not a vulnerability of this layer;
- **accidental collection or transmission of private data** (the activity log
  must never contain more than domain, timestamp, outcome, and a classifier
  type label — never the underlying values);
- **config handling**: the privileged daemon treats `config.json` as untrusted
  input, verifies the HMAC signature, and re-validates everything it reads.

It does **not** cover bypasses documented in the README's "What this does NOT
do yet" and "Storage, integrity, and fail-closed guarantees" (e.g. an agent
with root reconfiguring DNS or stopping the daemon, an admin removing the
OS-level hook outside the app, same-account read-all defeating at-rest
encryption, or a client pointed at a DoH/DoT resolver not on the built-in
list) — those are accepted limitations, not vulnerabilities. The OS firewall is
likewise a cooperative layer with known limits: arbitrary `curl`/`wget` to
HTTPS (port 443) is indistinguishable from browsing at the packet layer and is
not blocked (only explicit non-HTTPS-on-443 tunnels are), guests in VMs and
containers have their own network stack that may bypass the host anchor, and
network-free local code execution (`rm -rf`, `osascript`, compiled binaries)
is outside Auren's reach — stopping that requires the agent itself to run in a
sandbox. App blocking has the same cooperative boundaries: it is a
kill-loop with exact-path matching, not a sandbox — a blocked binary that is
renamed or relocated after being added stops matching, a process not on the
list at all runs freely, and a blocked app can exist for ~1 s between launch
and kill.

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
