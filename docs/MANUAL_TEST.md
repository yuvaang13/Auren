# Auren — manual test checklist

Every flow here should be run against the real app (`npm start`). The tests in
`test/` cover the logic; this checklist covers the things only a human at the
machine can confirm — the OS-native prompts and the real network behavior.

Prerequisites: `npm install`, then `npm start`.

## 1. Onboarding

- [ ] First launch shows the welcome screen (2 steps, plain language, no
      technical config).
- [ ] "Next" leads to step 2, which describes the block list and the biometric
      gate.
- [ ] "Start" closes onboarding and focuses the block-list input.
- [ ] Re-launching the app skips onboarding (it's marked done).

## 2. Block list (no privileges needed)

- [ ] Type `example.com` and click **Block**. It appears in the list.
- [ ] Type `mail.example.com` and click **Block**. It appears. (Blocking a
      subdomain is fine; blocking `example.com` also covers subdomains.)
- [ ] Type an IP like `1.2.3.4` — rejected with a plain-English message.
- [ ] Click **×** on a row — it disappears immediately.
- [ ] Restart the app — the block list persists.

## 3. Protection Mode ON (instant)

- [ ] Flip Protection Mode **ON**. On the very first time only, macOS asks for
      your password (installs the background service). Later flips are instant.
- [ ] The status line reads "Protection is ON … unreachable in every app and
      browser".
- [ ] With `example.com` blocked, confirm a *real* browser can't reach it
      (site fails to load) and that a *different* site still loads.
- [ ] **Cache flush check:** visit a blocked site while Protection is OFF (it
      loads), then flip Protection **ON** and revisit it — the site must now
      fail to load without a browser restart. Auren flushes the macOS DNS cache
      at every mode / block-list change so previously-resolved sites re-resolve
      through the local resolver. If a tab that was already open keeps loading,
      that's a live connection, not DNS — close the tab and reopen it.
- [ ] **Block-list edit check:** with Protection ON, add a site you were just
      visiting to the block list — it becomes unreachable within a second, no
      restart needed.

## 4. Real system-wide check (network layer)

With Protection ON and at least one domain blocked:

```bash
npm run e2e:check
```

- [ ] "ALL CHECKS PASSED" — blocked domain → NXDOMAIN, normal domain resolves,
      and `scutil --dns` shows the Mac pointing at `127.0.0.1`.

You can also poke directly:

```bash
dig @127.0.0.1 <blocked-domain>     # -> status: NXDOMAIN
dig @127.0.0.1 example.com          # -> status: NOERROR, an A record
```

## 5. Biometric / passcode gate (the important one)

- [ ] With Protection ON, flip the toggle **OFF**.
- [ ] macOS shows a Touch ID prompt (or, on machines without Touch ID, the
      standard password prompt). Complete it.
- [ ] The toggle stays ON but disabled for **10 seconds** and the status reads
      something like "Verified. Protection stays ON … sites will unlock in Ns."
- [ ] While the countdown runs, a blocked site is still unreachable.
- [ ] After ~10 seconds the toggle flips OFF on its own and the status reads
      "Protection is OFF"; the sites are now reachable.
- [ ] Flip OFF again but **cancel** the prompt. Protection stays ON and the
      activity log shows the request was cancelled.
- [ ] Check `~/Library/Application Support/Auren/activity.jsonl` — toggle
      events have a timestamp and outcome (`off_pending` when the cooldown
      starts, `off` when it completes). Confirm there is **no** credential
      or biometric data anywhere in that file.

## 5.5 Storage integrity (encrypted store + signatures)

- [ ] After any use, `~/Library/Application Support/Auren/guardrail.dat` exists
      and is encrypted: `grep -c bank.com ~/Library/Application\ Support/Auren/guardrail.dat`
      returns `0` (the block list is not in plaintext).
- [ ] `ls -l` on `guardrail.dat`, `auren.key`, `config.json`, and `config.sig`
      all show `-rw-------` (0600, owner read/write only).
- [ ] Loosen one file (`chmod 644 config.json`), relaunch the app, then check
      it's been tightened back to `0600` and the activity log contains a
      `permissions_fixed` line.
- [ ] Manually edit `config.json` to remove a blocked site (do NOT touch
      `config.sig`). Within ~1 second the daemon fails closed: every domain,
      blocked or not, now answers NXDOMAIN, and `dig` confirms it. Restore by
      toggling the app (which rewrites a valid signature).

## 5.6 Heartbeat / watchdog (degraded mode)

- [ ] With Protection ON and the daemon healthy, `/Library/Application
      Support/Auren/heartbeat.json` is fresh (updated every ~2 s) with
      `"integrityOk": true`.
- [ ] Stop the daemon: `sudo launchctl bootout system/com.auren.guardrail`.
- [ ] Within ~10 seconds the app shows the **degraded banner**, the status pill
      reads "Degraded", a macOS notification fires, and the activity log gains
      an `enforcement_degraded` line.
- [ ] Restart the daemon (`sudo bash scripts/install-daemon.sh` or toggle the
      switch), and the app logs `enforcement_restored` and clears the banner.

## 5.7 Sensitive-action gating (agent:inspect-action)

With the app running, call the gate the way a future bridge would — from the
renderer devtools or a test script:

```js
await window.auren.inspectAction({ url: 'https://shop.example.com/checkout', data: { card: '4111111111111111' } })
// -> { allowed: false, action: 'require_auth', types: ['credit_card'], ... }
```

- [ ] The OS-native auth prompt appears with a human-readable reason naming
      "credit card". Cancel it: `allowed: false` and the activity log records
      the block.
- [ ] A benign payload returns `allowed: true` with no auth prompt:
      `await window.auren.inspectAction({ data: { q: 'restaurants near me' } })`.
- [ ] While the app is **degraded** (see 5.6), even benign payloads return
      `allowed: false` (fail-closed policy).
- [ ] `window.auren.isBlocked('bank.com')` returns `true` while blocked and
      `false` when not, and never touches a file on disk.

## 6. Protection survives app restart

- [ ] Leave Protection ON, quit Auren, relaunch — the toggle is still ON and
      blocked sites are still unreachable (the daemon is independent of the
      app).
- [ ] Reboot the Mac, launch nothing, and confirm blocked sites are still
      unreachable (the daemon starts at boot).

## 7. Honest scope spot-checks

- [ ] The app's copy never promises "guaranteed" or "unbypassable" protection.
- [ ] The README's "What this does NOT do yet" section is accurate against the
      shipped build.

## Removing Auren

```bash
sudo launchctl unload /Library/LaunchDaemons/com.auren.guardrail.plist
sudo rm /Library/LaunchDaemons/com.auren.guardrail.plist
sudo rm -rf /usr/local/lib/auren "/Library/Application Support/Auren"
rm -rf ~/Library/Application\ Support/Auren
```
