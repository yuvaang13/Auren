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

- **It does not inspect page content or form data.** There is no PII-in-forms
  detection at this stage. Blocking at the DNS layer can't see inside web pages
  — catching PII in form submissions would require a *proxy* layer (a different
  mechanism, explicitly out of scope for this pivot). If that matters to you,
  it's a possible future direction, not something Auren fakes.
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
- **It blocks by domain name, not IP address.** Direct IP connections bypass
  DNS and are not blocked. The app rejects IP entries for exactly this reason.

## Why the biometric gate exists

Turning protection **on** is instant and frictionless — a user (or an agent)
should always be able to increase protection.

Turning protection **off** requires an OS-native biometric or device-passcode
check (macOS Touch ID, with the standard macOS password prompt as the fallback
on machines without Touch ID). The reason is simple: an AI agent that can click
buttons must not be able to click protection off on its own.

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
after that is instant; only turning OFF asks for your fingerprint or passcode.

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
  main.js                 Electron main process (window, IPC, audit entries)
  preload.js              minimal bridge to the UI (renderer is sandboxed)
  renderer/               the whole UI: toggle, block list, activity, onboarding
  core/
    domains.js            domain normalization + exact/subdomain matching
    config.js             config.json read/write (atomic), shared with the daemon
    activity.js           plain-language activity log (JSONL)
  dns/
    dns-message.js        minimal DNS wire parsing / NXDOMAIN building
    resolver.js           the local DNS server (UDP + TCP, blocks + forwards)
    daemon.js             the root service: reconciles DNS + runs the resolver
  platform/
    biometrics.js         macOS Touch ID / passcode gate (OS-native, pass/fail)
    dns-controller.js     daemon install + enforcement-status checks
scripts/
  install-daemon.sh       install the root daemon from the CLI
  e2e-check.sh            real end-to-end verification (blocked vs. allowed)
test/
  unit.test.js            core + DNS-message logic, no privileges
  dns-server.test.js      real resolver/daemon + mock upstream + dig
```

Persistence lives in two small places:

- `~/Library/Application Support/Auren/config.json` — the single source of
  truth: `{ "mode": "on"|"off", "blocklist": ["bank.com", ...] }`. Written by
  the app (atomically), polled by the daemon. This is the *only* file that
  controls behavior.
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
npm run test:unit      # 16 assertions: domains, config, activity, DNS wire format
npm run test:dns       # 8 assertions: real resolver + daemon with dig, no privileges
npm test               # both
npm run e2e:check      # REAL system-wide check (daemon installed + Protection ON):
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

**Is this unbypassable?**
No — see [What this does NOT do yet](#what-this-does-not-do-yet). It's a
cooperative guardrail.

## License

Apache-2.0 — see `LICENSE`.
