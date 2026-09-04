# Privacy Policy — Auren (Public Beta)

**Effective:** 2026-09-03 · **Scope:** Local desktop app `auren-guardrail@0.4.0` (no SaaS).

Auren is **zero-knowledge, local-only.** No blocklists, mounts, paths, or activity data are collected or transmitted.

## What Auren stores locally

| File | Location | Contents | Protection |
|------|----------|----------|------------|
| `guardrail.dat` | `~/Library/Application Support/Auren` (macOS) / `%APPDATA%\Auren` (Win) | Encrypted block state (sites, apps, `fsGuard` mounts) | AES-256-GCM, key `auren.key` (0600) |
| `auren.key` | same dir | 32-byte key | 0600 |
| `config.json` + `config.sig` | same dir | Signed snapshot for daemon | HMAC-SHA256, verified every poll |
| `settings.json` + `settings.sig` | same dir | Tunables (`terminalBlock`, `fsGuard`, etc.) | HMAC-signed, safe defaults on tamper |
| `bridge.token` | same dir | Loopback bridge bearer token | 0600, random 32-byte hex |
| `activity.jsonl` | same dir | Domain + timestamp + outcome + classifier label only | Append-only, never values |
| `heartbeat.json` | `/Library/Application Support/Auren` / `%PROGRAMDATA%\Auren` | Daemon liveness + integrity | 0644 spool |
| `guardrail.dat` lives only in main process; renderer and bridge never touch files. |

## What Auren does not do

- No telemetry, analytics, or remote logging. No network request leaves the machine except the DNS forward to your configured upstream and normal browsing.
- No biometric data ever passes through Auren — `src/platform/biometrics.js` consumes only pass/fail from OS APIs (Touch ID / Windows Hello).
- No file contents or full paths logged; `activity.jsonl` and sandbox ring (`src/platform/sandbox.js:26`) store only basenames/labels.

## Known limitation

At-rest encryption is scoped to OS file permissions (0600). A same-user `read-all` process that can read both `guardrail.dat` + `auren.key` can decrypt (see `README.md#storage-integrity`). The enforced boundary is permissions + sandboxed renderer + daemon HMAC, not a hardware keystore.

## Contact

Privacy questions: `privacy@auren.app` (beta — `security@auren.app` is the same inbox until dedicated route lands).
