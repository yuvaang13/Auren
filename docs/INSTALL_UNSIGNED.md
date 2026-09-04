# Installing Auren — Public Beta (Unsigned Builds)

Public Beta builds in `release/` are currently **unsigned** and not notarized. Your OS will show a trust warning — this is expected.

## macOS (Gatekeeper)

**Symptom:** `“Auren” is damaged and can’t be opened` / `unidentified developer`.

**Fix (recommended):**
1. Download `auren-0.4.0.dmg` from the GitHub Release.
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

**Fix:** Click `More info → Run anyway`. The NSIS installer (`auren-0.4.0-setup.exe`, per-machine) then asks for UAC elevation once to register the `AurenGuardrailDaemon` Scheduled Task. Win Firewall rules are group `Auren`.

Verify: `Get-NetFirewallRule -Group Auren` and `npm run e2e:check:win`.

## Trust notes

- No data leaves the device. See `PRIVACY.md`.
- Activity log contains only domain/timestamp/outcome + classifier labels, never values.
- Unsigned status does **not** affect the HMAC-signed config / AES-256-GCM store — those are still verified at `src/core/config.js:118` / `src/core/store.js:85`.
- Auto-update is not yet configured for beta — re-download the next GitHub Release to update (see `CHANGELOG.md`).

## After signing lands

This document will be removed; builds will open with a normal double-click. The app path and data directory do not change (`~/Library/Application Support/Auren` / `%APPDATA%\Auren`).
