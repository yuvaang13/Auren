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

When **Protection Mode is ON**, apps you block also **cannot run**. Search an
installed app by name, add it to the app block list, and the root background
service kills it the moment it starts — and keeps killing it — until you
unblock it or turn protection off. Like DNS, this is system-wide: it doesn't
matter which browser or process launched the app.

When **Protection Mode is ON**, browser autofill is **blocked by default**.
The root service writes macOS managed-policy files that make Chrome,
Chromium, Brave, and Edge refuse to save or auto-fill passwords, addresses,
phone numbers, and credit cards — so a browser session an agent controls can't
be asked to fill in your saved credentials. The files are removed again the
moment protection turns off (see [Browser autofill blocking](#browser-autofill-blocking-default-on)).

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
- **It does not hide keystrokes outside Auren.** The keystroke shield covers
  only Auren's own window and inputs. Keystrokes you type into other apps —
  while an AI agent watches the screen or reads the keyboard — are outside its
  reach (see [Keystroke shielding](#keystroke-shielding-part-of-protection-mode)).
- **It does not sandbox apps.** Blocked apps are killed (and re-killed) while
  protection is on, but any process that isn't on the app block list at all —
  or a blocked binary that is renamed or relocated after it was added — runs
  freely. App blocking is a kill-loop with exact-path matching, not an
  application sandbox (see [App blocking](#app-blocking-blocked-apps-cant-run)).
- **Autofill blocking is Chromium-family only and takes effect at browser
  launch.** It covers Chrome, Chromium, Brave, and Edge via macOS managed
  policies (passwords, addresses/phone numbers, credit cards). Safari and
  Firefox expose no equivalent policy hook, so they're not covered; a browser
  session already running when protection turns on keeps whatever autofill
  data it had until it's restarted (or policies are reloaded via
  `chrome://policy`). See
  [Browser autofill blocking](#browser-autofill-blocking-default-on).
- **It does not defend against a fully adversarial agent with deep system
  access.** If an agent already has root-level OS access it could reconfigure
  DNS itself, stop the background service, edit the config file, or reinstall
  the daemon. That is a known, documented limitation — Auren's protection is
  exactly as strong as the assumption that the machine isn't already
  compromised.
- **DoH/DoT blocking is a blocklist, not a wall.** Auren now blocks the
  well-known public DNS-over-HTTPS/TLS endpoints (Cloudflare, Google, Quad9,
  NextDNS, AdGuard, …) at the OS firewall, so the common "Secure DNS bypass"
  fails. But that's a list of known servers, not every resolver on the
  internet: a client pointed at an obscure or self-hosted DoH server that
  isn't on the list still bypasses DNS blocking. Extend or replace the list
  with `dohHosts` in `settings.json`. Auren also can't read TLS SNI at the
  firewall, so it can't tell *which* HTTPS host an arbitrary 443 connection
  targets — see the terminal section below for what it does about that.
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
- **A terminal command that only uses HTTPS is indistinguishable from a
  browser — at the packet layer.** The OS firewall blocks ICMP ping,
  SSH/FTP/Telnet/DoT and other command ports, cloud-metadata IPs, and known
  DoH endpoints — but `curl`/`wget` to an arbitrary HTTPS host uses the same
  port 443 as normal browsing, so a port rule can't stop it without breaking
  the web. The command gate closes part of that gap: it flags non-HTTPS
  protocols explicitly aimed at port 443 (`ssh -p 443`, `stunnel`,
  `openssl s_client`, raw `nc`/`socat` to `:443`) and blocks them by default.
  What it can't do is see raw bytes inside a legitimate HTTPS connection.
- **It does not stop local code execution that makes no network calls.** The
  firewall and the command gate only cover network-capable commands. An agent
  running `rm -rf`, `osascript`, or compiling and running a binary locally is
  outside Auren's reach — stopping that needs the agent itself to run inside a
  sandbox (a documented future direction, see below).

## Storage, integrity, and fail-closed guarantees

This is the design contract for how Auren stores its block state and what it
does when it can't trust its own enforcement. It's written to be honest about
what is guaranteed and what is not.

### 1. Block state lives only in the main process

- The canonical block state — protection mode, the site block list, the **app
  block list**, and lock/unlock metadata — exists **only** in the Electron main
  process and is persisted to an **encrypted store** (`guardrail.dat`,
  AES-256-GCM, key in `auren.key`). Both files are chmod 0600 (owner read/write
  only), enforced and repaired at every app start.
- The renderer never reads or writes those files. It can only ask the main
  process via IPC: `state:get`, `blocklist:add/remove`, `mode:set`,
  `guardrail:is-blocked`, `appblock:search/add/remove`.
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

### 3. What happens if the whole app is killed

- **Quitting Auren while Protection is ON requires the same OS-native
  biometric/passcode check as turning protection off.** Quitting would lift
  protection, so it is gated the same way: a cancelled/failed check cancels the
  quit and protection stays ON (the app shows a notification). This closes the
  "just quit the app" path an agent could use to get an unauthenticated off.
  Quitting while Protection is OFF needs no gate. A verified unlock cooldown
  still in flight counts as already authenticated, so quitting then is allowed.
- **After an authenticated quit, protection lifts.** Auren writes a signed
  `mode: off` config before exiting; the daemon picks it up within ~1 s,
  restores your normal DNS servers, and stops blocking. The block list is
  preserved, so the next launch starts with protection OFF but the same list
  ready to re-enable.
- **A crash or force-quit skips the gate but also skips the lift.** SIGKILL,
  the force-quit menu, or killing the app process never runs the quit handler,
  so no `mode: off` is ever written — protection stays ON (deny-all) rather
  than opening up. Only an authenticated graceful quit can hand the machine
  back.
- **Killing the daemon stays fail-closed.** The OS-level hook (system DNS
  pointing at `127.0.0.1`) is a SystemConfiguration property and the daemon is
  a launchd `KeepAlive` service. If the daemon itself is killed, system DNS is
  **left** pointing at the local resolver — nothing answers while it's down, so
  the result is deny-all (fail-closed), not open access. launchd restarts the
  daemon, which re-verifies the config signature before resuming.
- Turning the toggle OFF (authenticated) is the in-app path that restores
  normal DNS while the app stays running; it's gated by the OS-native check
  plus the 10-second cooldown.

### 4. Honest limits (known gaps)

- **Same-account read-all defeats storage encryption.** The AES key sits in the
  same user account as the data. A process running as that user that can read
  both `guardrail.dat` and `auren.key` can decrypt the store and forge
  signatures. Auren's real boundaries are OS file permissions, the sandboxed
  renderer, and the fact that browser/agent scripts can't read arbitrary user
  files. A fully compromised machine (already-root or same-user read-all) is
  out of scope — see [What this does NOT do yet](#what-this-does-not-do-yet).
- **The terminal/DoH blocks are a root-owned safety floor.** `terminalBlock`,
  `dohBlock`, and the allowlist live in `settings.json`, and the daemon has to
  load *something*. If `settings.json` (or the signed config) is tampered with
  or forged to disable or allowlist-away those blocks, the daemon re-applies a
  minimum-safety floor: terminal blocking and DoH blocking stay ON, built-in
  blocked ports and the cloud-metadata/DoH endpoints can't be allowlisted away,
  and `dohHosts` can only extend the built-in list. `settings.json` is also
  HMAC-signed (`settings.sig`); a signature mismatch is logged, reset to safe
  defaults, and surfaced in the UI. So an agent editing `settings.json` cannot
  get an unauthenticated open — it gets the floor instead.
- **An admin can remove the OS-level hook outside the app.** `sudo` unload of
  the launchd plist, manual DNS changes, or deleting the daemon files all happen
  outside Auren's control. Auren cannot prevent an admin user from doing this;
  it can only detect and report. (The activity log and the degraded banner are
  the honest response.)
- **VMs and containers have their own network stack.** Docker Desktop,
  Parallels, VMware Fusion, UTM, and VirtualBox each NAT (or bridge) their own
  traffic, which may never transit the host's `auren` pf anchor — so Auren's
  DNS and port blocking may not cover traffic from inside a guest. While
  Protection is ON, Auren detects when one of these runtimes is running and
  says so in the UI and the activity log. Whether your container traffic is
  actually covered is an empirical question: run `npm run audit:container`
  (Docker) with Protection ON to find out.
- **DoH/DoT blocking is list-based.** The built-in list covers the major
  public DNS-over-HTTPS/TLS providers; a client pointed at a resolver that
  isn't on the list bypasses it. `dohHosts` in `settings.json` can only
  *extend* the built-in list — the built-in servers stay blocked no matter what.
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

## Terminal & OS-level network access (default blocking)

Auren also guards against an AI agent reaching out **at the OS/terminal level** —
`ping`, `ssh`, `scp`, `nc`, `telnet`, `curl` to command ports, or stealing
cloud-instance credentials. This is a **default-on** feature: while Protection
Mode is ON, both layers below are active with no setup. It is ON by default and
tied to the same switch as website blocking.

### Layer 1 — an OS firewall (pf) in the root daemon

The root daemon loads a dedicated macOS packet-filter (`pf`) anchor named
`auren` whenever Protection is ON. Because it matches **IPs and ports, not
names**, it closes the gap where direct-IP commands (`ssh user@1.2.3.4`,
`ping 8.8.8.8`) sail past DNS blocking:

- **Blocked by default:** ICMP echo and traceroute (`ping`, `mtr`);
  outbound to command-tool ports — 21 FTP, 22 SSH/SCP/SFTP, 23 Telnet,
  25 SMTP, 110/143/993/995 mail, 135/137/138/139/445 NetBIOS/SMB,
  465/587 submission, 853 DoT, 1080 SOCKS, 3389 RDP, 5900 VNC; the
  cloud-metadata endpoints `169.254.169.254`, `169.254.169.253`,
  `100.100.100.200` (how an agent steals instance credentials — these are
  IPs, so only a firewall can see them); and the known public DoH/DoT
  endpoint IPs (Cloudflare, Google, Quad9, NextDNS, AdGuard, …), which
  Auren logs when something actually tries to reach them.
- **Always allowed:** loopback, DNS (port 53), and browsing (ports 80/443) —
  the anchor never strands the machine, and HTTPS browsing keeps working.
- **Allowlist:** `terminalAllowlist` in `settings.json` can re-open specific
  ports and IP/CIDR hosts (pf matches IPs, so hostnames aren't supported there).
  Additive only: it can never remove the built-in blocks — command ports,
  cloud-metadata endpoints, and known DoH/DoT endpoints stay blocked even if
  listed (the daemon's safety floor enforces this even on a forged config).
- **DoH/DoT:** on by default (`dohBlock: true`). EXTENDS the built-in
  endpoint list via `dohHosts` (union — built-in servers can never be removed):
  `{ "dohBlock": true, "dohHosts": ["9.9.9.9", "149.112.112.112"] }`.
  When a process actually tries to reach a known DoH/DoT endpoint, Auren logs
  the packets it dropped.
- **System-wide while ON:** pf rules apply to every process — including your
  own terminal. `ssh`/`ping` from your terminal are blocked too until
  Protection is turned OFF, which clears the anchor. That's the locked state,
  and the UI says so.
- **Safety:** Auren only ever touches its own `auren` anchor — it never
  flushes or rewrites a pre-existing pf configuration, and never disables pf
  on teardown (an enabled pf with an empty anchor passes everything).
- **Fail-closed:** if the signed config can't be verified, the daemon loads
  the blocking rules too, matching the DNS deny-all posture.

### Layer 2 — a command gate for agents that run through Auren

`agent:inspect-command` is the OS-command twin of `agent:inspect-action`
(see above). A future bridge / native-messaging host that routes an agent's
commands through Auren calls it before executing them. The classifier
(`src/core/commands.js`) recognizes ssh/scp/sftp/rsync sessions, ping and
traceroute, port probes (`nc`, `telnet`, `nmap`), ssh tunnels (`-L/-R/-D`),
tunnel-on-443 attempts (`ssh -p 443`, `stunnel`, `openssl s_client`, raw
`nc`/`socat` to `:443` — blocked as `cmd_suspicious_443`), file
transfers (`curl`, `wget`, `aws s3`, `gsutil`), classic reverse-shell
patterns (`nc -e`, `bash -i >& /dev/tcp/`, `python -c socket`, …), remote
database/cluster admin, and credential-store exfiltration pipelines
(`cat ~/.aws/credentials | nc …`). **Default policy: block.** Tuning lives in
`settings.json` (`commandPolicy`, e.g. `{ "commandPolicy": { "cmd_transfer":
"require_auth" } }`). The gate is active only while Protection is ON; while
degraded it refuses (fail-closed). Every outcome is logged like a site block.

The honest boundary: Layer 2 only helps when the agent's commands actually go
through Auren's bridge. A raw terminal session Auren can't see is covered by
Layer 1 (the pf firewall) instead. And no layer here stops local,
network-free code execution — that needs the agent sandboxed.

## App blocking (blocked apps can't run)

DNS blocking stops a site from *resolving*; it can't stop an agent from
**running a local tool**. App blocking closes that gap: search an installed app
by name, and while Protection Mode is ON the root daemon kills it the moment it
starts — and re-kills it on every subsequent launch — until you remove it from
the list or turn protection off.

- **Matching is by exact executable path.** The app you search resolves to its
  executable path (`/Applications/Discord.app/Contents/MacOS/Discord`), and the
  daemon only matches that exact path — it never substring-matches, so blocking
  `Discord` never touches `Discord Web` or anything with a similar name. The
  daemon also matches *argv tokens*: a launcher script that execs a blocked app
  (`node run-discord.js`) still matches, because the app path appears as an
  argument. Matches are exact token comparisons, never `includes()`.
- **The daemon kills, and keeps killing.** Enforcement lives in the root
  daemon (so an app can't kill the enforcer back), scans processes every second,
  and is tied to the same Protection switch as DNS + firewall blocking. If the
  daemon can't verify its config, app blocking fails closed with everything else.
- **Safety floor:** the daemon refuses to add an entry whose path is its own
  interpreter or the daemon binary itself — a config that tries to point the
  kill-loop at Auren is rejected outright.
- **What it isn't:** a sandbox. A blocked app can flash up for ~1 s before it's
  killed; a blocked binary that is renamed/relocated after being added stops
  matching; and a *different* executable that isn't on the list runs freely. It
  also only blocks at launch — if the app is *already* running when you add it,
  the daemon kills it too on its next sweep.
- **Who sees it:** the block list lives in the same canonical encrypted store as
  sites (see Storage above) and the UI shows it in the **Apps** card alongside
  the sites card, with a stat tile for how many processes were killed.

## Browser autofill blocking (default on)

A browser session that an agent controls can ask the browser to auto-fill — and
thereby reveal — credentials it has no business seeing: saved passwords, saved
addresses/phone numbers, and saved credit-card numbers. Auren blocks that while
Protection Mode is ON, **by default**, using the operating system's own managed
policy mechanism rather than touching any browser or user setting.

- **How it works:** while protection is on, the root daemon writes one small
  property-list file per browser into `/Library/Managed Preferences/`
  (`com.google.Chrome.plist`, `org.chromium.Chromium.plist`,
  `com.brave.Browser.plist`, `com.microsoft.Edge.plist`). The policy keys force
  `PasswordManagerEnabled`, `AutofillAddressEnabled`,
  `AutofillCreditCardEnabled`, and (for older builds) `AutoFillEnabled` to
  `false` — Chrome/Chromium/Brave/Edge read these at launch and grey out the
  corresponding autofill options. No browser profile, saved password, or user
  preference is modified.
- **It's fully reversible.** The moment protection turns off (or you set
  `autofillBlock: false` in `settings.json`), the daemon deletes the files. The
  browser's own data was never touched.
- **It's a next-launch guard.** Managed policies are read when a browser
  starts, so a browser that is already open keeps whatever it had until it's
  restarted (or you hit **Reload policies** in `chrome://policy`). Auren does
  not terminate browsers to force this.
- **Scope:** the four Chromium-family browsers above. Safari and Firefox don't
  expose an equivalent policy hook for autofill, so they are outside the
  current scope (documented under *What this does NOT do yet*).
- **Fail-closed:** like everything else in the daemon, autofill blocking is keyed
  on the same verified config. If the config can't be verified the daemon fails
  closed and the policies stay in place. The files are written only by the root
  daemon, so an unprivileged app can't silently delete them while protection is on.

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

## Keystroke shielding (part of Protection Mode)

While **Protection Mode is ON**, Auren also hides *your* keystrokes so a
screen-watching or keystroke-reading AI agent can't capture a password you type
into Auren. There is no separate toggle — it is simply what Protection Mode
means, and it engages the moment protection turns on:

- **The window can't be screen-captured.** Auren's window is excluded from
  screen recordings and captures (`setContentProtection`), so a computer-use
  agent taking screenshots sees nothing that happens in Auren — including
  anything you type there.
- **Keystrokes can't be intercepted.** While Auren's window has keyboard focus,
  macOS **Secure Event Input** is enabled, so keyboard-interception processes
  (Accessibility / event-tap keyloggers) can't read the keys you press in
  Auren. The moment focus leaves Auren, it's disabled again, so other apps'
  keyboard-observing features (password managers, text expanders, logitech
  software) keep working normally.
- **Sensitive fields render masked.** Any input that can carry a secret
  (`type="password"` or a `shield-masked` field) renders as dots, so even a
  capture that ignores window content protection sees nothing readable. The
  block-list box is *not* masked — a domain name isn't a secret.
- **Visible, not hidden.** A **"Keystrokes hidden"** badge appears in the
  header whenever the shield is active, and onboarding tells you it exists.

**Honest limits** (see also [What this does NOT do yet](#what-this-does-not-do-yet)):

- **Auren only shields its own window.** Keystrokes you type in *other* apps —
  your browser, your password manager, your terminal — are outside Auren's
  reach. An AI agent with Screen Recording or Accessibility permission could
  still see those; for passwords elsewhere, use the macOS Secure Entry that
  apps like Safari and password managers already enable on their secret fields.
- **The macOS passcode dialog is already shielded.** When you turn protection
  off (or quit while protected), the passcode prompt is a native macOS dialog
  that enables Secure Event Input itself — nothing you type there is readable
  by keystroke-interception processes.
- **It is cooperative, not adversarial.** As with every Auren layer, an agent
  with root-level OS access can bypass it.

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
    apps.js               app block entries: validate, normalize, ps matching
    sensitive.js          outgoing form-data classifier (PII / credentials)
    commands.js           OS/terminal command classifier (ssh, ping, 443 tunnels, exfil, ...)
    policy.js             decision layer over classifier signals (block / auth-gate)
    activity.js           plain-language activity log (JSONL)
    virt.js               VM/container-runtime detection (Docker, Parallels, UTM, ...)
  dns/
    dns-message.js        minimal DNS wire parsing / NXDOMAIN building
    resolver.js           the local DNS server (UDP + TCP, blocks + forwards)
    cache.js              flushes macOS DNS caches on mode/block-list changes
    pf.js                 macOS pf firewall anchor rules (block ping/ssh/DoH/...)
    daemon.js             root service: verifies config signature, fails closed,
                          writes heartbeat, reconciles DNS + pf + apps + autofill,
                          runs the resolver
  platform/
    biometrics.js         macOS Touch ID / passcode gate (OS-native, pass/fail)
    dns-controller.js     daemon install + enforcement-status checks
    app-resolver.js       installed-app search (LaunchServices + Info.plist)
    autofill.js           browser autofill blocking via managed-prefs plists
scripts/
  install-daemon.sh       install the root daemon from the CLI
  e2e-check.sh            real end-to-end verification (blocked vs. allowed)
  e2e-apps-check.sh       real end-to-end app-block verification (needs Protection ON)
test/
  unit.test.js            core + store + signing + policy, no privileges
  sensitive.test.js       classifier samples (false positives / negatives)
  dns-server.test.js      real resolver/daemon + mock upstream + dig
```

Persistence lives in three small places:

- `~/Library/Application Support/Auren/guardrail.dat` — the **canonical**,
  encrypted block state (`mode`, `blocklist`, `appBlocklist`, lock/unlock
  metadata). Only the main process reads or writes it.
- `~/Library/Application Support/Auren/config.json` + `config.sig` — a
  **signed snapshot** exported by the app for the root daemon, which verifies
  the signature on every poll and fails closed (deny-all) if it doesn't check
  out. The daemon treats this file as untrusted input. It carries protection
  mode, the site block list, the app block list, the terminal-block toggle,
  the firewall allowlist, and the autofill-block toggle.
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
- **Keystroke shield badge** — while protection is on, a "Keystrokes hidden"
  badge shows in the header: the window can't be screen-captured, and
  keystrokes typed into Auren are hidden from keystroke-reading agents.
- **Sites your AI agent can't visit** — a plain text field ("bank.com",
  "mail.google.com") + **Block** button, and a list with a × to unblock.
  Changes apply immediately. No JSON, no regex, no "policy" language.
- **Recent activity** — plain-language lines like
  "Blocked: attempt to reach bank.com · Aug 7, 2:14 PM". Only domain, time, and
  outcome — never any data.
- **Terminal & OS-level access** — no separate toggle: while Protection is on,
  the OS firewall and the command gate are active by default. An
  **OS commands blocked** stat and plain-language activity lines
  ("OS-level terminal access blocked (firewall rules applied) · …",
  "Agent command blocked (cmd_ssh) · …") report when they fire.
- **Apps** — a card next to sites: search an installed app by name, pick a
  match, and it lands on the app block list (each entry shows its executable
  path, with a × to unblock). While Protection is on, the daemon kills blocked
  apps at launch. A **Processes killed** stat and activity lines
  ("Blocked: app Discord started · …") report each kill.

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
npm run test:unit        # 68 assertions: domains, config, signing, store, policy, pf rules (incl. DoH + safety floor), activity, app blocking, keystroke shield, quit gate, autofill plists
npm run test:classifier  # 29 assertions: form-data + OS-command classifiers (incl. tunnel-on-443)
npm run test:dns         # 18 assertions: real resolver + daemon (incl. app kills + autofill policies) with dig, no privileges
npm test                 # unit + classifier
npm run test:all         # everything
npm run e2e:check        # REAL system-wide DNS check (daemon installed + Protection ON):
                         #   blocked domain -> NXDOMAIN, normal domain -> resolves
npm run e2e:apps         # REAL app-block check (daemon installed + Protection ON):
                         #   adds a dummy app to the block list, verifies the daemon
                         #   kills it, then removes the entry
sudo npm run e2e:pf          # REAL OS-firewall check (Protection ON, as root):
                             #   pf anchor loaded (incl. DoH rules), ping blocked,
                             #   ssh/DoT blocked, DoH endpoint unreachable, HTTPS still ok
                             #   (or: sudo bash scripts/e2e-pf-check.sh, from the repo root)
npm run audit:container      # Docker isolation audit (Protection ON): does container
                             #   traffic bypass Auren's firewall? Reports DNS, port 22,
                             #   and HTTPS reachability from inside a container
```

`e2e:check` temporarily adds `auren-e2e-check.test` to the block list, verifies
blocking at the network layer with `dig`, then removes it. See
`docs/MANUAL_TEST.md` for the full human-run checklist, including the
biometric-gated toggle-off test.

`e2e:apps` does the same for app blocking: it adds a harmless dummy "app" (an
executable shell script) to the app block list, spawns it, confirms the daemon
kills it within ~1 s, and removes the entry. It refuses to run unless Protection
is ON, and it never touches a real application.

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

**If I block an app, when does it get killed?**
Within ~1 second of it starting — the root daemon scans every second while
Protection is ON and kills blocked apps (matching by exact executable path and
argv tokens, never by substring). It also kills a blocked app that was already
running when you added it. Remove the app from the list (or turn protection
OFF) and it runs normally again.

**Does app blocking survive a daemon crash?**
No process can out-muscle a broken daemon. If the daemon itself fails, App
Blocking pauses with DNS + firewall until the LaunchDaemon restarts it; Auren
logs the outage. If the daemon can't verify its config, everything fails closed
(deny-all) instead.

**My VPN stopped working while protection is on.**
VPNs sometimes force their own DNS, which can conflict with pointing DNS at
Auren. This is a known rough edge of DNS-level blocking, not something Auren
hides. Turn protection off (or remove the VPN) if it interferes.

**Why is my own terminal's `ssh` / `ping` blocked while Protection is on?**
That's the OS firewall doing its job. While Protection Mode is ON it blocks
command ports (SSH, FTP, Telnet…) and ICMP for every process on the Mac —
including your terminal — because an AI agent on this Mac could be using that
same terminal. Turning Protection off clears the rules within ~1 second. If you
need a specific port or IP open while protected, add it to `terminalAllowlist`
in `settings.json` (ports and IPs/CIDRs; pf matches IPs, not hostnames).

**I flipped protection ON but a site I was just on still loads.**
That site was already resolved (and possibly still connected) from before
protection turned on, so it's served from a cache rather than re-resolved.
Auren flushes the macOS DNS cache at every mode change, which covers Safari and
the system resolver immediately; Chrome/Firefox keep their own cache for up to
~a minute. Close the tab (or restart the browser) and the block is instant.

**Can an AI agent see my keystrokes while protection is on?**
Not inside Auren: while protection is on, Auren's window can't be screen-
captured and macOS Secure Event Input stops keystroke-reading agents from
intercepting what you type there. But this covers Auren's own window only —
keystrokes you type in other apps (your browser, your password manager) are
outside Auren's reach, and the OS passcode prompt is protected by macOS itself.

**Is this unbypassable?**
No — see [What this does NOT do yet](#what-this-does-not-do-yet). It's a
cooperative guardrail.

## License

Apache-2.0 — see `LICENSE`.
