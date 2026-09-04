# Support — Auren Public Beta

## Quick triage

- **App won’t start / blank?** `npm start` from repo root, check `~/Library/Application Support/Auren/activity.jsonl`.
- **Port conflicts?** `sudo bash scripts/check-ports.sh` (macOS) / `.\scripts\check-ports.ps1` (Win) — names owner of UDP 53 / 127.0.0.1:42792.
- **Unsigned warning?** See `docs/INSTALL_UNSIGNED.md`.
- **Protection degraded?** Banner → `Retry — reinstall service` (re-triggers `scripts/install-daemon.sh|ps1`). Check heartbeat: `/Library/Application Support/Auren/heartbeat.json`.

## Filing an issue

1. Search existing issues.
2. Include: OS + version, `app.getVersion()`, repro steps, `activity.jsonl` excerpt (redact domains if desired), `heartbeat.json` snippet, `scripts/e2e-check.sh` output if network-related.
3. Do **not** paste `guardrail.dat`, `auren.key`, `config.sig`, or `bridge.token`.

## Security

Do not open a public issue. See `SECURITY.md#reporting` → `security@auren.app`.

## Manual checklist

For full QA, run `docs/MANUAL_TEST.md` on a clean machine.
