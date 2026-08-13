/* Auren — autoprotect.js
 *
 * Decision layer for auto-protect: when a live AI-agent session is detected
 * (see src/core/agentdetect.js) while protection is OFF, engage protection
 * automatically — or, per settings, ask first.
 *
 * Invariant: auto-protect can only ever RAISE protection. It never turns it
 * off, and a detected session that disappears leaves protection exactly where
 * it was. Turning protection off is always the biometric-gated user path.
 *
 * Settings shape (settings.json, HMAC-signed like the rest):
 *   { "autoProtect": { "enabled": true, "mode": "on" | "prompt",
 *                      "tools": [ ... ] } }
 *   - enabled: false disables auto-protect entirely.
 *   - mode:    "on" engages automatically on detection (default);
 *              "prompt" asks the user first (the caller shows the ask).
 */

'use strict';

const DEFAULT_AUTO_PROTECT = Object.freeze({ enabled: true, mode: 'on' });

// Normalize (and validate) the autoProtect settings block. Pure and safe to
// call on arbitrary user input.
function normalizeAutoProtect(raw) {
  const r = (raw && typeof raw === 'object') ? raw : {};
  return {
    enabled: r.enabled !== false,
    mode: r.mode === 'prompt' ? 'prompt' : 'on'
  };
}

// Should we auto-engage protection on this scan? Only ever raises. The caller
// handles the 'prompt' mode by showing an ask and calling back to engage.
function shouldEngage({ mode, failClosed, sessions, autoProtect }) {
  const ap = normalizeAutoProtect(autoProtect);
  if (!ap.enabled) return false;
  if (!Array.isArray(sessions) || sessions.length === 0) return false;
  if (mode === 'on' || failClosed) return false;
  if (ap.mode === 'prompt') return false;
  return true;
}

// Distinct tool names across a set of detected sessions, for logging and UI.
function uniqueToolNames(sessions) {
  return Array.from(new Set((Array.isArray(sessions) ? sessions : []).map((s) => s.tool).filter(Boolean)));
}

module.exports = { DEFAULT_AUTO_PROTECT, normalizeAutoProtect, shouldEngage, uniqueToolNames };
