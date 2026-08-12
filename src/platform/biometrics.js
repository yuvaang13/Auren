/* Auren — biometrics.js
 *
 * Platform seam for the gate that protects turning Protection Mode OFF.
 * macOS uses Touch ID + passcode (biometrics-mac.js); Windows uses Windows
 * Hello + UAC (biometrics-win.js). Both honor the same privacy invariant: only
 * OS-native prompts are shown and only a pass/fail/cancel result ever comes
 * back — no biometric data is seen, stored, or transmitted.
 *
 * Contract: requireAuthentication(reason) -> { ok, cancelled, method },
 *           requireNativeAuth(reason) -> Promise<boolean>
 */

'use strict';
module.exports = process.platform === 'win32'
  ? require('./biometrics-win')
  : require('./biometrics-mac');
