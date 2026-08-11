/* Auren - shield.js
 *
 * Keystroke shielding: part of what Protection Mode means, with no separate
 * toggle. While protection is expected to be enforced, Auren hides the
 * human's keystrokes so a screen-recording or keystroke-intercepting AI agent
 * can't capture a password typed into Auren.
 *
 * What it covers (Auren's own surface only):
 *   1. Window content protection  — the window can't appear in screen
 *      captures/recordings (applied in the main process).
 *   2. macOS Secure Event Input   — while the Auren window holds keyboard
 *      focus, macOS stops keyboard-interception processes (accessibility /
 *      event-tap keyloggers) from reading the user's keys.
 *   3. On-screen masking          — any input marked `shield-masked` renders
 *      as dots, so even a capture that ignores content protection sees
 *      nothing readable.
 *
 * Honest limits (see README "Keystroke shielding"):
 *   - This shields only Auren's own window. Keystrokes typed into other apps
 *     are outside Auren's reach.
 *   - It is a cooperative guardrail: an agent with root / deep OS access can
 *     bypass it.
 *
 * This module only answers "is the shield supposed to be on right now?" —
 * the actual window/focus plumbing lives in the main process (main.js).
 */

'use strict';

// The shield is simply part of Protection Mode. It is active whenever
// protection is expected to be enforced — mode ON, or fail-closed deny-all.
function keystrokeShieldActive(state) {
  if (!state) return false;
  return state.mode === 'on' || state.failClosed === true;
}

// Secure Event Input must only be enabled while the Auren window actually
// holds keyboard focus (Apple's "use secure event input fairly" rule), so it
// never breaks keyboard-observing features in other apps while Auren sits in
// the background.
function secureInputWanted(state, focused) {
  return keystrokeShieldActive(state) && focused === true;
}

module.exports = { keystrokeShieldActive, secureInputWanted };
