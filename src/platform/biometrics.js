/* Auren — biometrics.js
 *
 * The gate that protects turning Protection Mode OFF.
 *
 * PRIVACY INVARIANT: this module NEVER sees, handles, stores, or transmits
 * any biometric data. It only ever calls OS-native APIs and consumes a
 * pass/fail (or user-cancelled) result:
 *
 *   1. macOS Touch ID via Electron's `systemPreferences.promptTouchID` —
 *      which wraps the LocalAuthentication framework and returns success or
 *      failure only.
 *   2. If Touch ID is unavailable, the OS's standard passcode prompt via
 *      `osascript ... with administrator privileges`. The password is typed
 *      into the OS's own dialog; this process only observes exit status.
 *
 * Everything here is macOS-specific. Other platforms are rejected loudly
 * rather than silently faked.
 */

'use strict';

function loadElectron() {
  try { return require('electron'); } catch { return null; }
}

function runOsa(script) {
  return new Promise((resolve) => {
    const { execFile } = require('child_process');
    execFile('/usr/bin/osascript', ['-e', 'do shell script ' + JSON.stringify(script) + ' with administrator privileges'], (error) => {
      resolve(error);
    });
  });
}

// Fallback: OS-native passcode/password prompt. Only the exit status is used.
// The `script` is a no-op shell command; its only purpose is to trigger the OS
// prompt. Nothing the user types is captured or logged here.
async function passcodeFallback() {
  const err = await runOsa('exit 0');
  if (!err) return { ok: true, cancelled: false, method: 'passcode' };
  const msg = String((err && (err.message || err.code)) || '');
  return { ok: false, cancelled: /-128|cancel|interrupted/i.test(msg), method: 'passcode' };
}

// Attempts to authenticate the user via an OS-native mechanism.
// Resolves to { ok, cancelled, method } — never any credential material.
async function requireAuthentication(reason) {
  if (process.platform !== 'darwin') {
    return { ok: false, cancelled: false, method: 'unsupported' };
  }
  const electron = loadElectron();
  const sp = electron && electron.systemPreferences;
  if (sp && typeof sp.promptTouchID === 'function') {
    try {
      await sp.promptTouchID(reason || 'Auren');
      return { ok: true, cancelled: false, method: 'touchid' };
    } catch (err) {
      const msg = String((err && (err.message || err.code || err)) || '');
      if (/cancel|userCanceledErr|-128|interrupted/i.test(msg)) {
        return { ok: false, cancelled: true, method: 'touchid' };
      }
      // Touch ID unavailable or errored in some other way -> passcode fallback.
      return passcodeFallback();
    }
  }
  return passcodeFallback();
}

module.exports = { requireAuthentication };
