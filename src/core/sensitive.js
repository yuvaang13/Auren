/* Auren - sensitive.js
 *
 * Lightweight, rule-based classifier for OUTGOING form data. It is deliberately
 * decoupled from any policy: this module only emits "this looks sensitive:
 * [types]" signals. A separate policy layer (src/core/policy.js) decides what
 * to do with the signal (require auth, block, just log).
 *
 * The classifier accepts:
 *   - a JS object (form fields, JSON body),
 *   - a URL-encoded / query string,
 *   - a JSON string,
 *   - an arbitrary raw string (multipart bodies and the like), which is also
 *     scanned for self-identifying patterns (SSNs, card numbers, secret tokens).
 *
 * Signal types emitted (rules are intentionally conservative - false-positive
 * towards "sensitive" so a guardrail errs on the side of asking for auth):
 *   'ssn'          structured US Social Security number (NNN-NN-NNNN)
 *   'credit_card'  13-19 digit number that passes the Luhn checksum
 *   'password'     a form field that looks like a password/secret
 *   'email_password' an email-ish field AND a password field in the same payload
 *   'secret'       known cloud/API token shapes (Stripe, AWS, GitHub, Slack,
 *                  Google, PEM private keys)
 *
 * No credentials are stored, logged, or transmitted anywhere in this module.
 */

'use strict';

const SSN_DASHED = /\b\d{3}-\d{2}-\d{4}\b/;
const CARD_DIGITS_RE = /^\d{13,19}$/;

function normKey(k) {
  return String(k || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

const PASSWORD_KEY_RE = /^(?:pass|password|passwd|pwd|passcode|pin|otp|secret|token|apikey|apitoken|authtoken)$|(?:pass|password|passwd|pwd|passcode|otp|secret|token|apikey|apitoken|authtoken)\d*$/;
const EMAIL_KEY_RE = /^(email|e?mail|emailaddress|login|loginid|username|user|userid|userid|account|accountid|identifier|handle)$/;
const SSN_KEY_RE = /ssn|socialsecurity|social[_-]?security/;
const CARD_KEY_RE = /card|credit|ccnumber|ccn|pan|paymentnumber|cardnumber|cardnum/;

const SECRET_PATTERNS = [
  /sk-live-[A-Za-z0-9_-]{16,}/,                 // Stripe secret key
  /\bAKIA[0-9A-Z]{16}\b/,                        // AWS access key id
  /\bghp_[A-Za-z0-9]{36}\b/,                     // GitHub personal access token
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,            // Slack tokens
  /\bAIza[0-9A-Za-z_-]{35}\b/,                   // Google API key
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,          // PEM private key block
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b/ // JWT-ish
];

function luhnValid(numStr) {
  let sum = 0;
  let alt = false;
  for (let i = numStr.length - 1; i >= 0; i--) {
    const code = numStr.charCodeAt(i);
    if (code < 48 || code > 57) return false;
    let n = code - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function isCardNumber(value) {
  const digits = String(value || '').replace(/[\s-]/g, '');
  return CARD_DIGITS_RE.test(digits) && luhnValid(digits);
}

// Parse various payload shapes into [{ key, value }] pairs.
function parseFormData(input) {
  const pairs = [];
  let raw = '';
  if (typeof input === 'string') {
    raw = input.trim();
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') return { pairs: flatten(parsed), raw };
    } catch { /* not JSON */ }
    if (/[=&]/.test(raw)) {
      for (const part of raw.split(/[&;]/)) {
        const eq = part.indexOf('=');
        if (eq === -1) { pairs.push({ key: part.trim(), value: '' }); continue; }
        let k = part.slice(0, eq);
        let v = part.slice(eq + 1);
        try { k = decodeURIComponent(k.replace(/\+/g, ' ')); } catch {}
        try { v = decodeURIComponent(v.replace(/\+/g, ' ')); } catch {}
        pairs.push({ key: k, value: v });
      }
      return { pairs, raw };
    }
    // Plain blob (multipart, raw text, etc.) - nothing to split reliably.
    return { pairs, raw };
  }
  if (input && typeof input === 'object') {
    return { pairs: flatten(input), raw };
  }
  return { pairs, raw };
}

function flatten(obj, prefix) {
  const out = [];
  for (const k of Object.keys(obj)) {
    const key = prefix ? prefix + '.' + k : k;
    const v = obj[k];
    if (v && typeof v === 'object') {
      out.push.apply(out, flatten(v, key));
    } else {
      out.push({ key, value: v == null ? '' : String(v) });
    }
  }
  return out;
}

// Returns { sensitive: boolean, types: string[] }.
function classifySensitivePayload(input) {
  const types = new Set();
  const { pairs, raw } = parseFormData(input);
  let emailSeen = false;
  let passwordSeen = false;

  for (const { key, value } of pairs) {
    const k = normKey(key);
    if (!k) continue;

    if (SSN_KEY_RE.test(k) && /^\d{9}$/.test(value)) types.add('ssn');
    if (SSN_DASHED.test(value)) types.add('ssn');

    if (isCardNumber(value) || (CARD_KEY_RE.test(k) && isCardNumber(value))) {
      types.add('credit_card');
    }

    if (PASSWORD_KEY_RE.test(k)) {
      types.add('password');
      if (value.length > 0) passwordSeen = true;
    }
    // A login identifier (email OR username) counts toward the credential
    // combo signal; it is only sensitive when a password is present too.
    if (EMAIL_KEY_RE.test(k) && value.length > 0) emailSeen = true;

    for (const re of SECRET_PATTERNS) {
      if (re.test(value)) { types.add('secret'); break; }
    }
  }

  // Conservative multipart/raw heuristic: a password-ish and an email-ish
  // field name present together in a body counts as a credential combo.
  if (/name="(?:pass(?:word|code|wd)?|pwd|pin|otp|secret|token|api[_-]?key|auth[_-]?token)"/i.test(raw)) {
    types.add('password');
    passwordSeen = true;
  }
  if (/name="(?:e-?mail|emailaddress|login|username|user)"/i.test(raw)) emailSeen = true;

  // Raw text scan (catches values that never got split into key/value pairs).
  if (SSN_DASHED.test(raw)) types.add('ssn');
  const cardHits = raw.match(/(?<!\d)\d{13,19}(?!\d)/g) || [];
  for (const hit of cardHits) {
    if (luhnValid(hit)) { types.add('credit_card'); break; }
  }
  for (const re of SECRET_PATTERNS) {
    if (re.test(raw)) { types.add('secret'); break; }
  }

  if (emailSeen && passwordSeen) types.add('email_password');

  return { sensitive: types.size > 0, types: Array.from(types) };
}

module.exports = { classifySensitivePayload, luhnValid, parseFormData };
