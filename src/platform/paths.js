/* Auren — paths.js
 *
 * Platform-aware file locations, so the rest of the app never hardcodes a
 * macOS path. macOS values are byte-identical to the historical hardcoded
 * ones; Windows uses the standard %APPDATA% / %ProgramData% layout.
 *
 *   USER_DATA    per-user config + encrypted store + bridge token
 *   SYSTEM_SPOOL system-wide shared files (state.json, heartbeat.json,
 *                daemon.log) — writable by the privileged daemon, readable
 *                by the unprivileged app
 *   DAEMON_DIR   where the daemon modules live (mac: /usr/local/lib/auren,
 *                win: <ProgramData>\Auren\daemon)
 */

'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');

function userDataDir() {
  if (process.platform === 'win32') {
    return path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'Auren');
  }
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support', 'Auren');
  }
  return path.join(os.homedir(), '.auren');
}

function systemSpoolDir() {
  if (process.platform === 'win32') {
    return path.join(process.env.ProgramData || 'C:\\ProgramData', 'Auren');
  }
  if (process.platform === 'darwin') {
    return '/Library/Application Support/Auren';
  }
  return path.join(userDataDir(), 'spool');
}

function daemonDir() {
  if (process.platform === 'win32') {
    return path.join(systemSpoolDir(), 'daemon');
  }
  return '/usr/local/lib/auren';
}

function stateFile() { return path.join(systemSpoolDir(), 'state.json'); }
function heartbeatFile() { return path.join(systemSpoolDir(), 'heartbeat.json'); }
function daemonLogFile() { return path.join(systemSpoolDir(), 'daemon.log'); }
function installLogFile() { return path.join(systemSpoolDir(), 'install.log'); }

// chmod-equivalent tightening is a no-op on Windows: files under the user's
// own %APPDATA% profile are already scoped to the user by the OS ACL model,
// and the shared %ProgramData% files are only ever written by SYSTEM.
function ensurePermissions(file) {
  if (process.platform === 'win32') return false;
  try {
    fs.chmodSync(file, 0o600);
    return true;
  } catch { return false; }
}

module.exports = { userDataDir, systemSpoolDir, daemonDir, stateFile, heartbeatFile, daemonLogFile, installLogFile, ensurePermissions };
