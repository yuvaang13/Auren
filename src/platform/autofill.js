/* Auren — autofill.js
 *
 * Platform seam for browser autofill blocking. macOS writes managed-prefs
 * plists (Chromium enterprise policies, read at browser launch); Windows
 * writes the same policies into HKLM registry keys with reg.exe. Both expose
 * the same contract to the daemon: reconcileAutofill(enforce) ->
 * { changed, enforcing, covered, errors }.
 *
 * See autofill-mac.js / autofill-win.js for the per-platform mechanisms.
 */

'use strict';
module.exports = process.platform === 'win32'
  ? require('./autofill-win')
  : require('./autofill-mac');
