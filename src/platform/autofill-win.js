/* Auren — autofill-win.js
 *
 * Windows autofill blocking via Chromium-family enterprise policies in the
 * registry. On Windows those browsers read mandatory policy from
 * HKLM\Software\Policies\<vendor>\, which this module writes and deletes with
 * reg.exe. Same policy names as the macOS managed-prefs plists.
 *
 * Covered: Google Chrome, Chromium, Brave, Microsoft Edge — mirroring
 * autofill-mac.js. Safari/Firefox have no equivalent policy hook.
 *
 * The daemon runs as SYSTEM (Scheduled Task, highest privileges), so writing
 * HKLM needs no elevation here. Removal fully reverts the block.
 *
 * Command builders are pure (unit-testable without reg.exe); the exec wrappers
 * spawn `reg.exe` (override with AUREN_REG).
 */

'use strict';
const { spawnSync } = require('child_process');

// Vendor policy roots, in the same family order as autofill-mac.js BROWSERS.
const BROWSERS = [
  { id: 'Google Chrome', key: 'HKLM\\Software\\Policies\\Google\\Chrome' },
  { id: 'Chromium', key: 'HKLM\\Software\\Policies\\Chromium' },
  { id: 'Brave', key: 'HKLM\\Software\\Policies\\BraveSoftware\\Brave' },
  { id: 'Microsoft Edge', key: 'HKLM\\Software\\Policies\\Microsoft\\Edge' }
];

// Same keys as BLOCK_POLICIES in autofill-mac.js; value 0 disables the feature.
const BLOCK_POLICIES = {
  PasswordManagerEnabled: 0,
  AutofillAddressEnabled: 0,
  AutofillCreditCardEnabled: 0,
  AutoFillEnabled: 0
};

function regBin() {
  return process.env.AUREN_REG || 'reg.exe';
}

// Pure builders: return argv arrays ready for spawnSync(regBin(), argv).

function setPolicyCmds(browser) {
  return Object.keys(BLOCK_POLICIES).map((name) => [
    'add', browser.key, '/v', name, '/t', 'REG_DWORD', '/d', '0', '/f'
  ]);
}

function deletePolicyCmds(browser) {
  return Object.keys(BLOCK_POLICIES).map((name) => [
    'delete', browser.key, '/v', name, '/f'
  ]);
}

function run(argv) {
  try {
    const r = spawnSync(regBin(), argv, { encoding: 'utf8' });
    return { status: r.status ?? -1, stdout: (r.stdout || ''), stderr: (r.stderr || '') };
  } catch (err) {
    return { status: -1, stdout: '', stderr: err.message || String(err) };
  }
}

// Writes every policy value for every browser. A browser is "covered" when all
// of its values were written; failures are collected per-browser (non-fatal).
function applyAutofillBlock() {
  const covered = [];
  const errors = [];
  for (const b of BROWSERS) {
    const failed = [];
    for (const argv of setPolicyCmds(b)) {
      const r = run(argv);
      if (r.status !== 0) failed.push(String(r.stderr || r.stdout || '').trim());
    }
    if (failed.length === 0) covered.push(b.id);
    else errors.push({ browser: b.id, error: failed.join(' | ') });
  }
  return { enforcing: true, covered, errors };
}

// Deletes the policy values we wrote. A browser is "covered" when at least one
// value existed and was removed. A missing value makes reg.exe exit non-zero,
// which is expected — not an error.
function clearAutofillBlock() {
  const covered = [];
  const errors = [];
  for (const b of BROWSERS) {
    let touched = false;
    const failed = [];
    for (const argv of deletePolicyCmds(b)) {
      const r = run(argv);
      if (r.status === 0) touched = true;
      else failed.push(String(r.stderr || r.stdout || '').trim());
    }
    if (touched) covered.push(b.id);
  }
  return { enforcing: false, covered, errors };
}

let lastState = null; // null = never reconciled in this process

// Idempotent entry point for the daemon (same contract as autofill-mac.js).
function reconcileAutofill(enforce) {
  if (enforce === lastState) return { changed: false };
  lastState = enforce;
  const res = enforce ? applyAutofillBlock() : clearAutofillBlock();
  return Object.assign({ changed: true }, res);
}

module.exports = { BROWSERS, BLOCK_POLICIES, setPolicyCmds, deletePolicyCmds, applyAutofillBlock, clearAutofillBlock, reconcileAutofill };
