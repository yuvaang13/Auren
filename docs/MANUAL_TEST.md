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
- [ ] The toggle goes OFF and the status reads "Protection is OFF".
- [ ] Flip OFF again but **cancel** the prompt. Protection stays ON and the
      activity log shows the request was cancelled.
- [ ] Check `~/Library/Application Support/Auren/activity.jsonl` — toggle
      events have a timestamp and outcome. Confirm there is **no** credential
      or biometric data anywhere in that file.

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
