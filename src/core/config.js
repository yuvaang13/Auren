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
const { normalizeDomain, validateBlockDomain } = require('./domains');

const DEFAULT_CONFIG = Object.freeze({ version: 1, mode: 'off', blocklist: [] });

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
    return { version: 1, mode, blocklist };
  } catch (err) {
    if (err.code !== 'ENOENT') {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      try { fs.writeFileSync(file + '.corrupt', String(raw || '') + '\n', { flag: 'a' }); } catch {}
    }
    return { version: 1, mode: 'off', blocklist: [] };
  }
}

function writeConfigFile(file, cfg) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ version: 1, mode: cfg.mode, blocklist: cfg.blocklist }, null, 2) + '\n');
  fs.renameSync(tmp, file);
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

module.exports = { DEFAULT_CONFIG, configFile, readConfigFile, writeConfigFile, readConfig, writeConfig, setMode, addDomain, removeDomain };
