/* Auren — config.js
 *
 * The single source of truth for Protection Mode + block list, shared between
 * the desktop app (writer) and the root DNS daemon (reader).
 *
 * Stored as a plain JSON file at <userData>/config.json. Writes are atomic
 * (temp file + rename) so the daemon can safely poll without ever reading a
 * half-written file.
 *
 * Note: the daemon reads this file while running as root. It only ever
 * consumes `mode` and `blocklist` — no other fields — and it treats the file
 * as untrusted input (it re-validates everything it reads).
 */

'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { normalizeDomain, validateBlockDomain } = require('./domains');

const DEFAULT_CONFIG = Object.freeze({ version: 1, mode: 'off', blocklist: [], failClosed: false, terminalBlock: true, terminalAllowlist: { ports: [], hosts: [] } });
const SIG_SUFFIX = '.sig';

// Keep only the shape of the allowlist; strict IP/CIDR + port validation
// happens in the daemon's pf rule builder (src/dns/pf.js) and in the main
// process before persisting. The daemon treats these as untrusted input.
function normalizeAllowlist(raw) {
  const ports = Array.isArray(raw && raw.ports)
    ? raw.ports.map((p) => parseInt(p, 10)).filter((n) => n >= 1 && n <= 65535)
    : [];
  const hosts = Array.isArray(raw && raw.hosts)
    ? raw.hosts.map((h) => String(h).trim()).filter(Boolean)
    : [];
  return { ports: Array.from(new Set(ports)).sort((a, b) => a - b), hosts: Array.from(new Set(hosts)) };
}

function configFile(userDataDir) {
  return path.join(userDataDir, 'config.json');
}

function readConfigFile(file) {
  let raw = '';
  try {
    raw = fs.readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw);
    const mode = parsed.mode === 'on' ? 'on' : 'off';
    const blocklist = Array.isArray(parsed.blocklist)
      ? parsed.blocklist.map(normalizeDomain).filter(Boolean)
      : [];
    return {
      version: 1,
      mode,
      blocklist,
      failClosed: parsed.failClosed === true,
      terminalBlock: parsed.terminalBlock !== false,
      terminalAllowlist: normalizeAllowlist(parsed.terminalAllowlist)
    };
  } catch (err) {
    if (err.code !== 'ENOENT') {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      try { fs.writeFileSync(file + '.corrupt', String(raw || '') + '\n', { flag: 'a' }); } catch {}
    }
    return { version: 1, mode: 'off', blocklist: [], failClosed: false, terminalBlock: true, terminalAllowlist: { ports: [], hosts: [] } };
  }
}

function writeConfigFile(file, cfg) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({
    version: 1,
    mode: cfg.mode,
    blocklist: cfg.blocklist,
    failClosed: cfg.failClosed === true,
    terminalBlock: cfg.terminalBlock !== false,
    terminalAllowlist: normalizeAllowlist(cfg.terminalAllowlist)
  }, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

// HMAC-SHA256 integrity over the on-disk bytes. `config.sig` is written by the
// main process next to `config.json`; the root daemon verifies it before
// trusting the file, so an edit made outside the app fails verification and
// the daemon fails closed (blocks everything).
function signData(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function verifyData(data, key, sigHex) {
  if (!sigHex || !key) return false;
  const expected = Buffer.from(signData(data, key), 'hex');
  const given = Buffer.from(String(sigHex).trim(), 'hex');
  return given.length === expected.length && crypto.timingSafeEqual(expected, given);
}

// Writes the plaintext config for the daemon PLUS its signature sidecar.
function writeSignedConfig(file, cfg, key) {
  writeConfigFile(file, cfg);
  fs.writeFileSync(file + SIG_SUFFIX, signData(fs.readFileSync(file), key) + '\n', { mode: 0o600 });
}

function readConfig(userDataDir) {
  return readConfigFile(configFile(userDataDir));
}

function writeConfig(userDataDir, cfg) {
  writeConfigFile(configFile(userDataDir), cfg);
}

function setMode(userDataDir, mode) {
  const cfg = readConfig(userDataDir);
  cfg.mode = mode === 'on' ? 'on' : 'off';
  writeConfig(userDataDir, cfg);
  return cfg;
}

function addDomain(userDataDir, input) {
  const v = validateBlockDomain(input);
  if (!v.ok) return { ok: false, error: v.error, blocklist: null };
  const cfg = readConfig(userDataDir);
  if (!cfg.blocklist.includes(v.domain)) cfg.blocklist.push(v.domain);
  writeConfig(userDataDir, cfg);
  return { ok: true, blocklist: cfg.blocklist };
}

function removeDomain(userDataDir, input) {
  const d = normalizeDomain(input);
  const cfg = readConfig(userDataDir);
  cfg.blocklist = cfg.blocklist.filter((x) => x !== d);
  writeConfig(userDataDir, cfg);
  return { ok: true, blocklist: cfg.blocklist };
}

module.exports = { DEFAULT_CONFIG, SIG_SUFFIX, configFile, readConfigFile, writeConfigFile, readConfig, writeConfig, setMode, addDomain, removeDomain, signData, verifyData, writeSignedConfig };
