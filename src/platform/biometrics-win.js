/* Auren — biometrics-win.js
 *
 * Windows gate that protects turning Protection Mode OFF.
 *
 * PRIVACY INVARIANT: identical to biometrics-mac.js — this module NEVER sees,
 * handles, stores, or transmits any biometric data. It only calls OS-native
 * APIs and consumes a pass/fail (or user-cancelled) result:
 *
 *   1. Windows Hello via the UserConsentVerifier WinRT API (fingerprint, face,
 *      or PIN). The prompt is rendered by Windows itself; PowerShell only gets
 *      back a UserConsentVerificationResult enum (Verified / Canceled / ...).
 *   2. If Hello is unavailable, the OS UAC consent prompt via
 *      Start-Process -Verb RunAs. The human must click through the OS dialog;
 *      this process only observes whether it was completed or cancelled.
 *
 * The Hello prompt is built from a pure command builder so it is unit-testable
 * without Windows; the exec wrappers spawn `powershell.exe` (AUREN_PS).
 */

'use strict';
const { execFile } = require('child_process');

const VERIFIED = 0;
const CANCELED = 6;

function psBin() {
  return process.env.AUREN_PS || 'powershell.exe';
}

function psQuote(s) {
  return "'" + String(s).replace(/'/g, "''") + "'";
}

// Pure builder: prompts Windows Hello for the given reason and prints the
// numeric UserConsentVerificationResult.
function helloCmd(reason) {
  return 'Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null; '
    + '[Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime] | Out-Null; '
    + '$r = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync(' + psQuote(reason || 'Auren') + ').AsTask().Result; '
    + '[int]$r';
}

function runPS(script) {
  return new Promise((resolve) => {
    execFile(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], (error, stdout, stderr) => {
      resolve({ error, stdout: String(stdout || '').trim(), stderr: String(stderr || '') });
    });
  });
}

// Windows Hello prompt. Resolves { ok, cancelled, method: 'hello' } or null
// when Hello is unavailable on this machine.
async function helloAuth(reason) {
  const r = await runPS(helloCmd(reason));
  if (r.error) return null;
  const code = parseInt(r.stdout, 10);
  if (!Number.isFinite(code)) return null;
  if (code === VERIFIED) return { ok: true, cancelled: false, method: 'hello' };
  if (code === CANCELED) return { ok: false, cancelled: true, method: 'hello' };
  // DeviceNotPresent / NotConfiguredForUser / DisabledByPolicy / DeviceBusy /
  // RetriesExhausted -> fall through to the UAC fallback.
  return null;
}

// Fallback: UAC consent prompt. The human must click through the OS dialog
// (or enter an admin password). Only the exit status is used.
function uacFallback() {
  return new Promise((resolve) => {
    const cmd = 'Start-Process ' + psBin() + ' -Verb RunAs -Wait -ArgumentList ' + psQuote('-NoProfile -Command "exit 0"');
    execFile(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', cmd], (error) => {
      if (!error) return resolve({ ok: true, cancelled: false, method: 'uac' });
      const msg = String((error && (error.message || error.code)) || '');
      resolve({ ok: false, cancelled: /1223|cancel|interrupted/i.test(msg), method: 'uac' });
    });
  });
}

// Attempts to authenticate the user via an OS-native mechanism.
// Resolves to { ok, cancelled, method } — never any credential material.
async function requireAuthentication(reason) {
  const hello = await helloAuth(reason);
  if (hello) return hello;
  return uacFallback();
}

// Same contract as biometrics-mac.js.
async function requireNativeAuth(reason) {
  const r = await requireAuthentication(reason);
  return r.ok === true;
}

module.exports = { requireAuthentication, requireNativeAuth, helloCmd };
