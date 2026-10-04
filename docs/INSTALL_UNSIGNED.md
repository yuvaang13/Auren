# Installing Auren — Public Beta (Unsigned Builds)

Public Beta builds in `release/` are currently **unsigned** and not notarized. Your OS will show a trust warning — this is expected.

## macOS (Gatekeeper)

**Symptom:** `“Auren” is damaged and can’t be opened` / `unidentified developer`.

**Fix (recommended):**
1. Download `auren-0.5.0-arm64.dmg` from the GitHub Release.
2. **Right-click (Ctrl-click) → Open** the app (not double-click) → `Open` in the dialog.
3. On first toggle ON, macOS will prompt for admin password once to install the background service (`com.auren.guardrail`). Later toggles are instant; turning OFF needs Touch ID / passcode.

**Alternative (quarantine clear):**
```bash
xattr -cr /Applications/auren.app   # if you dragged it there
# or
xattr -cr ./release/mac-arm64/auren.app
```

Verify daemon: `sudo bash scripts/check-ports.sh` (port 53 + 42792). Check `npm run e2e:check` with Protection ON.

## Windows (SmartScreen)

**Symptom:** `Windows protected your PC — Unknown publisher`.

**Beta builds ship as a portable `.zip`** (`auren-<version>-win-portable.zip`):
1. Unzip and run `auren.exe`.
2. If SmartScreen blocks it, click `More info → Run anyway`.
3. On first toggle ON, allow the UAC elevation once to register the `AurenGuardrailDaemon` Scheduled Task. Win Firewall rules are group `Auren`.

A per-machine NSIS installer (`auren-<version>-setup.exe`, see `nsis.perMachine` in `electron-builder.yml`) is built from a Windows runner / release job — if the current GitHub Release has no `-setup.exe` yet, use the portable `.zip` above.

Verify: `Get-NetFirewallRule -Group Auren` and `npm run e2e:check:win`.

## Trust notes

- No data leaves the device. See `PRIVACY.md`.
- Activity log contains only domain/timestamp/outcome + classifier labels, never values.
- Unsigned status does **not** affect the HMAC-signed config / AES-256-GCM store — those are still verified at `src/core/config.js:118` / `src/core/store.js:85`.
- Auto-update is not yet configured for beta — re-download the next GitHub Release to update (see `CHANGELOG.md`).

## After signing lands

This document will be removed; builds will open with a normal double-click. The app path and data directory do not change (`~/Library/Application Support/Auren` / `%APPDATA%\Auren`).
