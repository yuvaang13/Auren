# Contributing to Auren

Thanks for contributing. Auren is a small, focused project — please read the
README first, especially **What this does NOT do yet** and the **privacy
invariant**.

## Ground rules

- **Auren never handles biometric or credential data.** All authentication
  goes through OS-native APIs and only a pass/fail result comes back. Any new
  code that touches biometrics directly (or stores/transmits it) will be
  rejected.
- **Keep honest limitations honest.** Don't imply Auren is a security boundary.
  Update the README's limitations section if a change affects bypass surface.
- **Fail closed.** If the authentication gate fails or is cancelled,
  Protection Mode stays ON. Preserve this invariant.
- **Protection ON is instant; OFF is gated.** Don't add friction to turning
  protection on, and never allow turning it off without the OS-native check.
- **No new core enforcement scope.** Bug fixes, hardening, tests, docs, and
  polish are welcome. Brand-new enforcement capabilities (e.g. a proxy layer
  for content inspection) should be discussed in an issue first.
- **The block list is plain-language.** No JSON, regex, or "policy" language in
  the default UI.

## Development setup

```bash
npm install            # Electron binary downloads over HTTPS — if it fails
                       # with a cert error, see the README's TLS note
npm run test:unit      # 16 assertions, no privileges, no browser
npm run test:dns       # 8 assertions, real resolver + daemon + dig
npm run e2e:check      # real system-wide check (needs daemon + Protection ON)
```

Run `npm test` before pushing. Both suites must end with `N passed, 0 failed`.
Manual flows are documented in `docs/MANUAL_TEST.md`.

## Where things live

| Concern | File |
|---|---|
| Domain matching (the only logic carried over from the old extension) | `src/core/domains.js` |
| Shared config (mode + block list), written by app, read by daemon | `src/core/config.js` |
| Plain-language activity log | `src/core/activity.js` |
| DNS wire format (parse / NXDOMAIN build) | `src/dns/dns-message.js` |
| Local DNS server (block + forward) | `src/dns/resolver.js` |
| Root background service (DNS reconciliation) | `src/dns/daemon.js` |
| Biometric / passcode gate (macOS) | `src/platform/biometrics.js` |
| Daemon install + status | `src/platform/dns-controller.js` |
| Electron main + IPC | `src/main.js`, `src/preload.js` |
| UI | `src/renderer/` |

`src/core/*`, `src/dns/*`, and `src/platform/dns-controller.js` must stay
runnable as plain Node (no `electron` import at module load) so the tests can
exercise them without a browser. `biometrics.js` feature-detects Electron
instead of importing it unconditionally.

## Pull requests

- One logical change per PR; small and reviewable.
- Add or update tests for behavior changes (unit and DNS integration where
  they touch blocking or gating).
- Keep the changelog note in the PR description, not a separate file.
- Follow the existing style (2-space indent, semicolons, no new dependencies
  without discussion, comments only to clarify a non-obvious invariant).

## Reporting security issues

Do **not** open a public issue for security problems. See `SECURITY.md`.
