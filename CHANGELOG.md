# Changelog

All notable changes to Auren are documented here. Format follows Keep a Changelog and SemVer. This project is currently **Public Beta** (`0.4.x`).

## [0.4.0] — 2026-09-03 — Public Beta

### Added
- **Network & Domain Blocker:** DNS-level `NXDOMAIN` blocking at `127.0.0.1:53`, HTTPS SNI CONNECT proxy `127.0.0.1:42792` with QUIC (`UDP 443`) drop, PAC-routed `https:` only.
- **App & Process Controls:** daemon kill-loop for blocked apps (exact path + argv token, safety floor), autofill managed-policy blocking (Chromium family), keystroke shielding (content protection + Secure Event Input on macOS).
- **File System Guard & Virtual Isolation:** default-deny Virtual Mounts, canonical-first (`path-normalize.js`) symlink/traversal collapse, forced exclusions (`.env`, `.env.*`, `.ssh`, `.aws`, `.pem`, `.key`, browser stores) — see `docs/FILESYSTEM_GUARD.md`.
- **Sandbox Monitor:** platform profile (App Sandbox / Hardened Runtime / pf anchor / AppContainer) + 200-entry ephemeral in-memory event ring (`src/platform/sandbox.js`).
- **Agent Bridge:** loopback HTTP `127.0.0.1:42791` (`POST /v1/check/action|command|fs`), token-gated, read/gate-only, fail-closed.
- **Auto-protect (Beta):** dwell + confidence process detection (`src/core/agentdetect|agenttrack|autoprotect.js`), snooze on manual off.

### Hardening
- Fail-closed integrity: signed `config.json` + HMAC, encrypted `guardrail.dat` (AES-256-GCM + 0600), watchdog degraded mode, safety floor for `terminalBlock`/`dohBlock`.

### Known limits
- See `README.md#what-this-does-not-do-yet` and `docs/FILESYSTEM_GUARD.md` — unsigned builds require the Gatekeeper/SmartScreen workaround in `docs/INSTALL_UNSIGNED.md`.

## [0.3.x] — prior
- See `git log --oneline` for incremental hardening (pf anchor caching, degraded recovery, daemon test hardening).

[0.4.0]: https://github.com/yuvaang13/Auren-Guardrail-for-AI-agents/releases/tag/v0.4.0
