/* Auren — quit.js
 *
 * Decision logic for gating a graceful quit. While Protection is ON (or the
 * app is fail-closed), quitting lifts protection and hands the machine back to
 * the open state, so it requires the same OS-native authentication as turning
 * protection off. A verified unlock cooldown still in flight counts as
 * authenticated (the user passed the check seconds ago and protection is about
 * to turn off anyway), so quitting then just finishes the cooldown.
 *
 * Pure and unit-testable; the prompt flow itself lives in the Electron main
 * process (src/main.js).
 */
'use strict';

function quitRequiresAuth(state) {
  if (!state || (state.mode !== 'on' && !state.failClosed)) return false;
  if (state.lock && state.lock.state === 'unlocking') return false;
  return true;
}

module.exports = { quitRequiresAuth };
