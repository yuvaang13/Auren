# Auren — AI Agent Guardrail

A small desktop app that blocks specific websites at the **network level** on
your whole computer — every browser, every app — and makes it hard for an AI
agent to turn that protection off.

> **Honest positioning.** Auren is a **cooperative guardrail**, not a security
> boundary. It adds friction and oversight for ordinary AI-agent sessions. It
> does **not** claim to stop a fully adversarial agent with deep system access.
> Everything below is honest about what it can and can't do — read
> [What this does NOT do yet](#what-this-does-not-do-yet) before relying on it.

## What this actually does

When **Protection Mode is ON**, Auren points your Mac's DNS at a tiny local
resolver it runs itself. Any domain on your block list simply **does not
resolve** (the resolver answers `NXDOMAIN`, exactly like "site doesn't exist"),
so the site is unreachable from **every** browser and app — not just one. There
is no browser extension, no per-browser setup, and nothing an app can do to
"skip" the block by opening a different window.

When you flip protection ON (or add/remove a site) Auren also flushes the
macOS DNS cache, so sites you visited *before* the change don't keep loading
from a previously-cached IP — the next lookup is forced through the local
resolver.

When **Protection Mode is OFF**, your DNS goes back to normal and everything is
reachable as usual.

This is a deliberate architecture change from Auren's first version, which was
a Chrome extension. An extension only watches one browser window — if an AI
agent opens its own separate or headless browser, the extension can't see it.
Auren now sits *below* all of that, at the network layer.

```
AI agent ──▶ any browser or app ──▶ Auren's local DNS resolver (127.0.0.1)
                                        │
                                        ├─ blocked domain  → NXDOMAIN (unreachable)
                                        └─ everything else → forwarded to a real DNS server
```

## What this does NOT do yet

- **It does not intercept page content or form data on its own.** Auren now
  ships a *classifier + auth-gating API* for outgoing form data
  (`agent:inspect-action`, see below), but nothing in Auren currently sits in
  the network path where form submissions happen. Wiring that API into a proxy
  or browser bridge is the integration layer — Auren provides the detection,
  the policy, and the native-auth gate, not the proxy itself.
- **It does not detect humans vs. AI in real time.** Protection is a manual
  on/off switch. Auren does not try to tell whether a given lookup came from
  you or from an agent.
- **It does not defend against a fully adversarial agent with deep system
  access.** If an agent already has root-level OS access it could reconfigure
  DNS itself, stop the background service, edit the config file, or reinstall
  the daemon. That is a known, documented limitation — Auren's protection is
  exactly as strong as the assumption that the machine isn't already
  compromised.
- **It can't intercept apps that bypass the system resolver.** An app or
  browser configured to use DNS-over-HTTPS/TLS with its own hardcoded resolver
  (for example, a browser with "Secure DNS" pointed at a specific DoH server,
  or a VPN client that forces its own DNS) never asks the local resolver, so it
  won't be blocked. By default, normal browsers and apps use the system DNS and
  *are* covered.
- **It can't force a browser's own cache to drop instantly.** Auren flushes the
  macOS system DNS cache on every mode/block-list change, which covers Safari
  and anything that resolves through the OS. Browsers that keep their *own*
  DNS and HTTP caches (Chrome, Firefox) may keep serving a site already loaded
  or recently resolved for up to ~a minute until their internal cache expires —
  closing the tab or restarting the browser makes the block immediate. A tab
  that was already open when protection turned on also keeps its live
  connection; close and reopen it.
- **It blocks by domain name, not IP address.** Direct IP connections bypass
  DNS and are not blocked. The app rejects IP entries for exactly this reason.

## Storage, integrity, and fail-closed guarantees

This is the design contract for how Auren stores its block state and what it
does when it can't trust its own enforcement. It's written to be honest about
what is guaranteed and what is not.

### 1. Block state lives only in the main process

- The canonical block state — protection mode, the block list, and lock/unlock
  metadata — exists **only** in the Electron main process and is persisted to an
  **encrypted store** (`guardrail.dat`, AES-256-GCM, key in `auren.key`). Both
  files are chmod 0600 (owner read/write only), enforced and repaired at every
  app start.
- The renderer never reads or writes those files. It can only ask the main
  process via IPC: `state:get`, `blocklist:add/remove`, `mode:set`,
  `guardrail:is-blocked`.
- The root DNS daemon is a separate process (it can't do Electron IPC), so it
  consumes a **signed read-only snapshot**: the main process writes
  `config.json` + an HMAC-SHA256 `config.sig`. The daemon verifies the
  signature before trusting a single byte and **never writes** the block state
  back. It has no independent, writable copy — its copy is derived and verified.
- **Any component that intercepts agent traffic** (a future proxy, native
  messaging host, or browser-bridge) must use the same main-process API —
  `guardrail:is-blocked` to ask whether a site is blocked, and
  `agent:inspect-action` to gate sensitive actions. No component should keep its
  own copy of block state.

### 2. Fail-closed tamper detection

Auren's default on any verification failure is **block, not allow**:

- **Config tampering.** Editing `config.json` outside the app (without
  regenerating `config.sig`) fails signature verification. The daemon then
  denies **every** outbound lookup (deny-all) and keeps system DNS pointed at
  the local resolver, even if the tampered config claims mode is OFF.
- **Encrypted-store corruption.** If `guardrail.dat` can't be decrypted, the
  app starts in a fail-closed state: mode ON, deny-all flag set, a notification
  shown, and the event logged.
- **Loose file permissions.** If storage files are found looser than 0600 at
  startup, Auren tightens them and logs a `permissions_fixed` event.
- **Heartbeat / watchdog.** The daemon writes a heartbeat every ~2 s with a
  timestamp and its own integrity status. The app checks it every ~3 s; after
  roughly two missed beats (or an `integrityOk: false` report) the app flips to
  **degraded** mode: every gated surface refuses, a persistent banner shows in
  the UI, a macOS notification is raised, and the event is logged with a
  timestamp. When the daemon is healthy again the app logs recovery.

### 3. What happens if the whole app is killed (fail-closed where feasible)

- Closing the Auren app does **not** remove the OS-level hook. On macOS the
  system DNS setting (pointing at `127.0.0.1`) is a SystemConfiguration
  property; the daemon is a launchd `KeepAlive` service. If the app is killed,
  the daemon keeps enforcing. If the daemon itself is killed, system DNS is
  **left** pointing at the local resolver — nothing answers while it's down, so
  the result is deny-all (fail-closed), not open access. launchd restarts the
  daemon, which re-verifies the config signature before resuming.
- Turning the toggle OFF (authenticated) is the only in-app path that restores
  normal DNS, and it's gated by the OS-native check plus the 10-second cooldown.

### 4. Honest limits (known gaps)

- **Same-account read-all defeats storage encryption.** The AES key sits in the
  same user account as the data. A process running as that user that can read
  both `guardrail.dat` and `auren.key` can decrypt the store and forge
  signatures. Auren's real boundaries are OS file permissions, the sandboxed
  renderer, and the fact that browser/agent scripts can't read arbitrary user
  files. A fully compromised machine (already-root or same-user read-all) is
  out of scope — see [What this does NOT do yet](#what-this-does-not-do-yet).
- **An admin can remove the OS-level hook outside the app.** `sudo` unload of
  the launchd plist, manual DNS changes, or deleting the daemon files all happen
  outside Auren's control. Auren cannot prevent an admin user from doing this;
  it can only detect and report. (The activity log and the degraded banner are
  the honest response.)
- **Docker containers and NAT'd guests** bypass the host's DNS setting unless
  explicitly configured to use it.
- **The degraded watchdog covers the daemon**, not the full integrity of the
  machine. If the block list is copied and the copy is served by an attacker
  that also runs the daemon process, Auren can't tell the difference.

## Sensitive-action policy (outgoing form data)

Auren ships a rule-based classifier (`src/core/sensitive.js`) that detects
structured PII and credentials in outgoing form data, decoupled from a policy
layer (`src/core/policy.js`) that decides what to do about it:

- **Classifier signal:** SSN shapes (`NNN-NN-NNNN`), credit-card numbers with a
  Luhn checksum, password/secret form fields, email-or-username + password
  combos, and common API-token shapes (Stripe, AWS, GitHub, Slack, Google, PEM
  private keys). It only emits `{ sensitive: true, types: [...] }` — it never
  stores, logs, or sends the data.
- **Policy:** by default any sensitive signal → **require native OS auth**
  (`requireNativeAuth(reason)` — the same Touch ID / passcode checkpoint used
  for unlocking sites). While Auren is **degraded**, the policy is **block**.
  Policies are tunable without touching detection: set `sensitivePolicy` in
  `~/Library/Application Support/Auren/settings.json`, e.g.
  `{ "sensitivePolicy": { "password": "log" } }`.
- **The gate:** `agent:inspect-action` runs the whole chain (classify → decide →
  authenticate → log) inside the main process. A future proxy or browser bridge
  calls it before allowing an agent's form submission through; Auren returns
  `{ allowed, action, types, reason }` and logs the outcome like a site block.

## Why the biometric gate exists

Turning protection **on** is instant and frictionless — a user (or an agent)
should always be able to increase protection.

Turning protection **off** requires an OS-native biometric or device-passcode
check (macOS Touch ID, with the standard macOS password prompt as the fallback
on machines without Touch ID). After a successful check, the block list stays
active for a **10-second cooldown** before protection actually turns off, so a
human has a moment to confirm the unlock. The reason is simple: an AI agent
that can click buttons must not be able to click protection off on its own.

**Privacy invariant:** Auren only ever calls the OS's authentication APIs and
receives a **pass/fail result**. It never sees, stores, or transmits any
biometric or credential data. Nothing you type into the macOS password dialog
ever passes through Auren's process. This is stated in the code comments in
`src/platform/biometrics.js` as well.

## Requirements

- **macOS** (the fully supported platform right now). The code is structured so
  a Windows port can be added (local DNS via `netsh`, Windows Hello via a
  native module), but that is **planned, not built**.
- One-time admin privileges: installing the background service requires a
  standard macOS password prompt. After that, toggling protection and editing
  the block list need no privileges at all.
- Node.js + npm for development (the app itself is an Electron app).

## Getting started (development)

```bash
npm install                 # installs Electron (see note below if you hit TLS errors)
npm start                   # launches the Auren desktop app
```

First launch shows a short onboarding (what it does, how the toggle works, how
to add sites), then lands you on the block-list screen.

When you turn **Protection Mode ON** for the first time, macOS will ask for
your password once — that installs the background DNS service. Every ON/OFF
after that is instant; only turning OFF asks for your fingerprint or passcode
and then waits out a 10-second cooldown before sites become reachable.

> **Note for machines with TLS/certificate restrictions:** the Electron binary
> is downloaded over HTTPS from GitHub. If `npm install` fails to fetch it
> (`unable to get local issuer certificate`), install the binary once with
> TLS verification disabled for that download:
> `NODE_TLS_REJECT_UNAUTHORIZED=0 npx electron --version`

### Installing the daemon manually (instead of via the app)

If you prefer the command line:

```bash
sudo bash scripts/install-daemon.sh
```

This installs (or updates) the root LaunchDaemon `com.auren.guardrail`, which
runs the DNS resolver persistently, independent of any browser or app. It
reconciles the system's actual DNS with the requested Protection Mode every
~second, reading the same `config.json` the app writes — so changes to the
block list apply in real time with no restart.

## How it's built

```
src/
  main.js                 Electron main process (window, IPC, canonical block state)
  preload.js              minimal bridge to the UI (renderer is sandboxed)
  renderer/               the whole UI: toggle, block list, activity, onboarding
  core/
    domains.js            domain normalization + exact/subdomain matching
    config.js             config.json read/write (atomic) + HMAC signing, shared
    store.js              encrypted at-rest store (AES-256-GCM) for block state
    sensitive.js          outgoing form-data classifier (PII / credentials)
    policy.js             decision layer over the classifier signal (auth-gate)
    activity.js           plain-language activity log (JSONL)
  dns/
    dns-message.js        minimal DNS wire parsing / NXDOMAIN building
    resolver.js           the local DNS server (UDP + TCP, blocks + forwards)
    cache.js              flushes macOS DNS caches on mode/block-list changes
    daemon.js             root service: verifies config signature, fails closed,
                          writes heartbeat, reconciles DNS, runs the resolver
  platform/
    biometrics.js         macOS Touch ID / passcode gate (OS-native, pass/fail)
    dns-controller.js     daemon install + enforcement-status checks
scripts/
  install-daemon.sh       install the root daemon from the CLI
  e2e-check.sh            real end-to-end verification (blocked vs. allowed)
test/
  unit.test.js            core + store + signing + policy, no privileges
  sensitive.test.js       classifier samples (false positives / negatives)
  dns-server.test.js      real resolver/daemon + mock upstream + dig
```

Persistence lives in three small places:

- `~/Library/Application Support/Auren/guardrail.dat` — the **canonical**,
  encrypted block state (`mode`, `blocklist`, lock/unlock metadata). Only the
  main process reads or writes it.
- `~/Library/Application Support/Auren/config.json` + `config.sig` — a
  **signed snapshot** exported by the app for the root daemon, which verifies
  the signature on every poll and fails closed (deny-all) if it doesn't check
  out. The daemon treats this file as untrusted input.
- `~/Library/Application Support/Auren/activity.jsonl` — the plain-language log.

`/Library/LaunchDaemons/com.auren.guardrail.plist` and `/usr/local/lib/auren/`
hold the installed daemon and its copy of the resolver code. Removing it all:

```bash
sudo launchctl unload /Library/LaunchDaemons/com.auren.guardrail.plist
sudo rm /Library/LaunchDaemons/com.auren.guardrail.plist
sudo rm -rf /usr/local/lib/auren "/Library/Application Support/Auren"
```

## The UI (the whole app)

- **Protection Mode** — one prominent toggle. ON is instant; OFF requires
  Touch ID or your device password, and logs the outcome.
- **Sites your AI agent can't visit** — a plain text field ("bank.com",
  "mail.google.com") + **Block** button, and a list with a × to unblock.
  Changes apply immediately. No JSON, no regex, no "policy" language.
- **Recent activity** — plain-language lines like
  "Blocked: attempt to reach bank.com · Aug 7, 2:14 PM". Only domain, time, and
  outcome — never any data.

Every Protection Mode change and every block is written to the activity log
with a timestamp and outcome, so there's a local audit trail of *who turned
protection off and when* — without ever logging credentials or biometrics.

## Privacy

- Auren never handles private user data. It has no backend, makes no network
  connections beyond forwarding DNS queries, and never transmits anything.
- The activity log contains only domain names, timestamps, and outcomes.
- Biometric/credential material never enters Auren's process (see
  [Why the biometric gate exists](#why-the-biometric-gate-exists)).

## Running the tests

```bash
npm run test:unit        # 26 assertions: domains, config, signing, store, policy, activity
npm run test:classifier  # 12 assertions: form-data classifier samples
npm run test:dns         # 10 assertions: real resolver + daemon with dig, no privileges
npm test                 # unit + classifier
npm run test:all         # everything
npm run e2e:check        # REAL system-wide check (daemon installed + Protection ON):
                         #   blocked domain -> NXDOMAIN, normal domain -> resolves
```

`e2e:check` temporarily adds `auren-e2e-check.test` to the block list, verifies
blocking at the network layer with `dig`, then removes it. See
`docs/MANUAL_TEST.md` for the full human-run checklist, including the
biometric-gated toggle-off test.

## FAQ

**Does it work in a headless or separate browser an agent starts?**
Yes — that's the whole point. Blocking happens in DNS, below every browser. A
headless Chromium on this Mac uses the same system DNS, so it hits the same
block.

**My Mac has no Touch ID. Can I still turn protection off?**
Yes. Auren falls back to the standard macOS password prompt (still OS-native,
still only a pass/fail result). If neither succeeds, protection stays ON.

**Does closing the Auren window stop protection?**
No. The DNS service is a separate background daemon. Closing the app window
doesn't stop blocking; turn the toggle OFF (with verification) to stop it.

**Does it block a whole domain including subdomains?**
Yes. Blocking `bank.com` also blocks `mail.bank.com`. But not
`notbank.com`. Matching is exact-or-subdomain only — see `src/core/domains.js`.

**My VPN stopped working while protection is on.**
VPNs sometimes force their own DNS, which can conflict with pointing DNS at
Auren. This is a known rough edge of DNS-level blocking, not something Auren
hides. Turn protection off (or remove the VPN) if it interferes.

**I flipped protection ON but a site I was just on still loads.**
That site was already resolved (and possibly still connected) from before
protection turned on, so it's served from a cache rather than re-resolved.
Auren flushes the macOS DNS cache at every mode change, which covers Safari and
the system resolver immediately; Chrome/Firefox keep their own cache for up to
~a minute. Close the tab (or restart the browser) and the block is instant.

**Is this unbypassable?**
No — see [What this does NOT do yet](#what-this-does-not-do-yet). It's a
cooperative guardrail.

## License

Apache-2.0 — see `LICENSE`.
