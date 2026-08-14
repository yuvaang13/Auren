/* Auren — autoprotect.js
 *
 * Decision layer for auto-protect: when live, *confirmed* AI-agent activity is
 * detected (see src/core/agentdetect.js + agenttrack.js) while protection is
 * OFF, engage protection automatically — or, per settings, ask first.
 *
 * Invariant: auto-protect can only ever RAISE protection. It never turns it
 * off, and a detected session that disappears leaves protection exactly where
 * it was. Turning protection off is always the biometric-gated user path.
 *
 * Two anti-false-positive mechanisms:
 *   - confidence: the tracker only hands over CONFIRMED sessions (present for
 *     >= minDwellMs); shouldEngage only acts once their summed score reaches
 *     minConfidence (default 3 — a single real agent binary, or ~2 wrapper
 *     invocations). A transient `rg codex` (score 1, gone in a second) never
 *     reaches either bar.
 *   - snooze: after the user manually turns protection off, the tools that
 *     engaged it are snoozed (snoozeMs) so protection doesn't immediately
 *     fight the user back on. A DIFFERENT tool still engages immediately.
 *
 * Settings shape (settings.json, HMAC-signed like the rest):
 *   { "autoProtect": { "enabled": true, "mode": "on" | "prompt",
 *                      "tools": [ ...agentdetect signatures... ],
 *                      "ignore": [{ "tool": "...", "exe": "..." }],
 *                      "minDwellMs": 2000, "minConfidence": 3, "snoozeMs": 1800000 } }
 */

'use strict';

const DEFAULT_AUTO_PROTECT = Object.freeze({
  enabled: true,
  mode: 'on',
  minDwellMs: 2000,
  minConfidence: 3,
  snoozeMs: 30 * 60 * 1000
});

const clamp = (v, lo, hi, dflt) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.max(lo, Math.min(hi, Math.round(n)));
};

// Normalize (and validate) the autoProtect settings block. Pure and safe to
// call on arbitrary user input. `tools` and `ignore` pass through raw — the
// agentdetect normalizers own their validation.
function normalizeAutoProtect(raw) {
  const r = (raw && typeof raw === 'object') ? raw : {};
  return {
    enabled: r.enabled !== false,
    mode: r.mode === 'prompt' ? 'prompt' : 'on',
    minDwellMs: clamp(r.minDwellMs, 500, 60000, DEFAULT_AUTO_PROTECT.minDwellMs),
    minConfidence: clamp(r.minConfidence, 1, 100, DEFAULT_AUTO_PROTECT.minConfidence),
    snoozeMs: clamp(r.snoozeMs, 0, 24 * 60 * 60 * 1000, DEFAULT_AUTO_PROTECT.snoozeMs),
    tools: Array.isArray(r.tools) ? r.tools.slice() : [],
    ignore: Array.isArray(r.ignore) ? r.ignore.slice() : []
  };
}

// Should we auto-engage protection right now? Only ever raises. The caller
// handles the 'prompt' mode by showing an ask and calling back to engage.
//   sessions:      confirmed sessions from agenttrack.update() — each with a
//                  numeric `score` (missing score defaults to 3 for callers
//                  that pass raw matches)
//   snoozedUntil:  { [tool]: epochMs } — tools the user asked us to leave off
//   now:           epoch ms for the snooze check
function shouldEngage({ mode, failClosed, autoProtect, sessions, snoozedUntil, now }) {
  const ap = normalizeAutoProtect(autoProtect);
  if (!ap.enabled) return false;
  if (mode === 'on' || failClosed) return false;
  if (ap.mode === 'prompt') return false; // deferred to the caller
  const list = (Array.isArray(sessions) ? sessions : []).filter((s) => s && s.tool);
  if (list.length === 0) return false;
  const t = now == null ? null : Number(now);
  const eligible = t == null || !snoozedUntil
    ? list
    : list.filter((s) => !(snoozedUntil[s.tool] && snoozedUntil[s.tool] > t));
  if (eligible.length === 0) return false;
  const confidence = eligible.reduce((sum, s) => sum + (Number.isFinite(s.score) ? s.score : 3), 0);
  return confidence >= ap.minConfidence;
}

// Distinct tool names across a set of detected sessions, for logging and UI.
function uniqueToolNames(sessions) {
  return Array.from(new Set((Array.isArray(sessions) ? sessions : []).map((s) => s.tool).filter(Boolean)));
}

// After the user turns protection off — manually, or by an authenticated quit —
// snooze the tools that engaged it so auto-protect doesn't instantly fight the
// user back on while those agents are still running. Pure; returns a NEW
// snoozedUntil map, leaving the caller's untouched. A different (non-snoozed)
// tool still engages immediately. Returns the previous map (and not a copy) if
// nothing to snooze, so callers can detect "no change" via identity.
function snoozeTools(engagedBy, autoProtect, snoozedUntil, now) {
  const tools = (Array.isArray(engagedBy) ? engagedBy : []).filter(Boolean);
  if (tools.length === 0) return snoozedUntil || {};
  const ap = normalizeAutoProtect(autoProtect);
  const until = (now == null ? Date.now() : Number(now)) + ap.snoozeMs;
  const next = Object.assign({}, snoozedUntil || {});
  for (const tool of tools) next[tool] = until;
  return next;
}

module.exports = { DEFAULT_AUTO_PROTECT, normalizeAutoProtect, shouldEngage, uniqueToolNames, snoozeTools };
