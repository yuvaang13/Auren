/* Auren — autofill.js
 *
 * Blocks browser autofill while Protection Mode is on. The mechanism is the
 * macOS "managed preferences" plist, which Chromium-family browsers read their
 * enterprise policies from at launch. No browser is patched, no user settings
 * are mutated, and removing the files fully reverts the change — so it fits
 * the cooperative-guardrail model.
 *
 * Covered: Google Chrome, Chromium, Brave, Microsoft Edge. Safari and Firefox
 * expose no equivalent policy hook for autofill, so they are out of scope
 * (documented in SECURITY.md / README.md).
 *
 * Because policies are read when a browser starts, this is a next-launch
 * guard: an already-running browser session keeps whatever it had until it is
 * restarted (or its policies are reloaded via chrome://policy).
 */

'use strict';
const fs = require('fs');
const path = require('path');

// Chrome/Chromium/Brave/Edge read mandatory policy from here on macOS. The
// dir override lets integration tests point writes at a temp dir instead of
// the real system path (the daemon normally runs as root and writes here).
function managedPrefsDir() {
  return process.env.AUREN_AUTOFILL_DIR || '/Library/Managed Preferences';
}

// Chromium-family browsers all share the same enterprise policy names and the
// same macOS managed-preferences mechanism.
const BROWSERS = [
  { id: 'com.google.Chrome', name: 'Google Chrome' },
  { id: 'org.chromium.Chromium', name: 'Chromium' },
  { id: 'com.brave.Browser', name: 'Brave' },
  { id: 'com.microsoft.Edge', name: 'Microsoft Edge' }
];

// Enforcing these keys disables: saving/autofilling passwords, address +
// phone-number autofill, credit-card autofill, and the legacy catch-all that
// older Chromium builds use for form autofill.
const BLOCK_POLICIES = {
  PasswordManagerEnabled: false,
  AutofillAddressEnabled: false,
  AutofillCreditCardEnabled: false,
  AutoFillEnabled: false
};

function policyPath(browserId) {
  return path.join(managedPrefsDir(), browserId + '.plist');
}

// Minimal flat-bool-dict plist writer; Chromium's policy parser accepts it as-is.
function plistXml(policies) {
  const entries = Object.keys(policies)
    .map((k) => '\t<key>' + k + '</key>\n\t<' + policies[k] + '/>')
    .join('\n');
  return '<?xml version="1.0" encoding="UTF-8"?>\n'
    + '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    + '<plist version="1.0">\n<dict>\n' + entries + '\n</dict>\n</plist>\n';
}

// Writes one managed-prefs plist per known browser. Returns which browsers were
// covered and any per-browser write errors (non-fatal: one stubborn browser
// must not block the others).
function applyAutofillBlock() {
  const covered = [];
  const errors = [];
  for (const b of BROWSERS) {
    try {
      fs.mkdirSync(managedPrefsDir(), { recursive: true });
      fs.writeFileSync(policyPath(b.id), plistXml(BLOCK_POLICIES), { mode: 0o644 });
      covered.push(b.name);
    } catch (err) {
      errors.push({ browser: b.name, error: err.message });
    }
  }
  return { enforcing: true, covered, errors };
}

// Removes the managed-prefs plists we wrote, fully reverting the policy. Only
// browsers whose plist actually existed are reported as covered.
function clearAutofillBlock() {
  const covered = [];
  const errors = [];
  for (const b of BROWSERS) {
    try {
      if (fs.existsSync(policyPath(b.id))) {
        fs.unlinkSync(policyPath(b.id));
        covered.push(b.name);
      }
    } catch (err) {
      errors.push({ browser: b.name, error: err.message });
    }
  }
  return { enforcing: false, covered, errors };
}

let lastState = null; // null = never reconciled in this process

// Idempotent entry point for the daemon: applies or clears the block only when
// the desired state actually changed, so a 200ms poll never rewrites files.
function reconcileAutofill(enforce) {
  if (enforce === lastState) return { changed: false };
  lastState = enforce;
  const res = enforce ? applyAutofillBlock() : clearAutofillBlock();
  return Object.assign({ changed: true }, res);
}

module.exports = { BROWSERS, BLOCK_POLICIES, managedPrefsDir, policyPath, plistXml, applyAutofillBlock, clearAutofillBlock, reconcileAutofill };
