/* Auren - store.js
 *
 * Encrypted, main-process-only storage for the canonical block state:
 * protection mode, the block list, and lock/unlock metadata.
 *
 * WHY ENCRYPT:
 *   The renderer is sandboxed (contextIsolation, no nodeIntegration) and agent
 *   scripts run in a browser sandbox, so neither can normally read files. At
 *   rest encryption is the second line of defense: if a file is copied out by
 *   sync tools, backups, a casual reader, or a sandbox-escaped script that only
 *   gets read access to user files, it sees ciphertext, not the list.
 *
 * HONEST LIMIT (documented in the README):
 *   The AES key lives in the same user account as the data file. A process
 *   running as the same user that can read BOTH files can decrypt the store
 *   and forge signatures. Auren's real boundaries are OS file permissions
 *   (0600), the Electron renderer sandbox, and the fact that browser/agent
 *   scripts cannot read arbitrary user files. A same-account process with
 *   read-all access defeats this; that is an accepted, documented limitation.
 *
 * Format: one file, `<userData>/guardrail.dat`, holding a base64 envelope
 *   "auren:v1:" + iv(12) + authTag(16) + AES-256-GCM ciphertext.
 * Key: 32 random bytes in `<userData>/auren.key`, chmod 0600.
 *
 * No Electron, no OS keychain - pure Node crypto so this module is unit-
 * testable and portable. (Keychain-backed keys are a documented future option.)
 */

'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEY_FILE = 'auren.key';
const STORE_FILE = 'guardrail.dat';
const STORE_MAGIC = 'auren:v1:';

// Tighten a file to owner read/write only. Returns true if a change was made.
// Windows: the ACL model already scopes files under %APPDATA% to the owning
// user, so this is intentionally a no-op (chmod there only toggles the
// read-only bit and would report a spurious "change" every call).
function ensurePermissions(file) {
  if (process.platform === 'win32') return false;
  try {
    const st = fs.statSync(file);
    if (st.mode & 0o077) {
      fs.chmodSync(file, 0o600);
      return true;
    }
    return false;
  } catch (err) {
    if (err.code !== 'ENOENT') {
      try { fs.chmodSync(file, 0o600); return true; } catch { /* ignore */ }
    }
    return false;
  }
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

// Returns the 32-byte key, creating it (0600) on first run.
function loadOrCreateKey(dir) {
  ensureDir(dir);
  const kf = path.join(dir, KEY_FILE);
  if (fs.existsSync(kf)) {
    const key = fs.readFileSync(kf);
    ensurePermissions(kf);
    if (key && key.length >= 32) return key;
    // Key file is corrupt/empty. If a store already exists we cannot decrypt
    // it - the caller decides how to fail closed. Generate a fresh key so the
    // app can keep running in a known-degraded state.
    const fresh = crypto.randomBytes(32);
    fs.writeFileSync(kf, fresh, { mode: 0o600 });
    ensurePermissions(kf);
    return fresh;
  }
  const key = crypto.randomBytes(32);
  fs.writeFileSync(kf, key, { mode: 0o600 });
  ensurePermissions(kf);
  return key;
}

function encryptJSON(data, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return STORE_MAGIC + Buffer.concat([iv, tag, ct]).toString('base64');
}

function decryptJSON(payload, key) {
  const s = String(payload || '');
  if (!s.startsWith(STORE_MAGIC)) throw new Error('unknown store format');
  const raw = Buffer.from(s.slice(STORE_MAGIC.length), 'base64');
  const iv = raw.slice(0, 12);
  const tag = raw.slice(12, 28);
  const ct = raw.slice(28);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
}

function storeFilePath(dir) {
  return path.join(dir, STORE_FILE);
}

function storeFileExists(dir) {
  return fs.existsSync(storeFilePath(dir));
}

function saveSecureStore(dir, key, data) {
  ensureDir(dir);
  const file = storeFilePath(dir);
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, encryptJSON(data, key), { mode: 0o600 });
  fs.renameSync(tmp, file);
  ensurePermissions(file);
}

// Returns parsed object, or null if no store file exists yet.
// Throws if the store exists but fails authentication (tamper/corruption).
function loadSecureStore(dir, key) {
  const file = storeFilePath(dir);
  if (!fs.existsSync(file)) return null;
  ensurePermissions(file);
  return decryptJSON(fs.readFileSync(file, 'utf8'), key);
}

module.exports = {
  KEY_FILE,
  STORE_FILE,
  ensurePermissions,
  loadOrCreateKey,
  encryptJSON,
  decryptJSON,
  saveSecureStore,
  loadSecureStore,
  storeFileExists,
  storeFilePath
};
