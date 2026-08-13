/* Auren — procs-mac.js
 *
 * macOS process listing for the daemon's app blocker and auto-protect:
 * `ps -axo pid=,ppid=,command=` parsed with the shared core/apps.js parser,
 * and `/bin/kill -9` for the kill. Extracted from daemon.js so the daemon
 * stays platform-neutral. ppid feeds agent ancestry detection; the app blocker
 * simply ignores it.
 */

'use strict';
const { spawnSync } = require('child_process');
const path = require('path');

// Shared process-line parser (core/apps.js in the repo, apps.js flat beside
// the daemon in the install dir). Resolve both ways like daemon.js load().
let apps;
try { apps = require(path.join(__dirname, 'apps.js')); } catch (err) {
  if (err.code !== 'MODULE_NOT_FOUND') throw err;
  apps = require(path.join(__dirname, '..', 'core', 'apps.js'));
}
const { parsePsLine } = apps;

// [{ pid, ppid, exe, tokens }, ...] or null when ps itself fails.
function list() {
  const r = spawnSync('/bin/ps', ['-axo', 'pid=,ppid=,command='], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  if (r.status !== 0) return null;
  return String(r.stdout || '')
    .split('\n')
    .map(parsePsLine)
    .filter(Boolean);
}

function kill(pid) {
  const r = spawnSync('/bin/kill', ['-9', String(pid)], { encoding: 'utf8' });
  return { ok: r.status === 0, error: r.status === 0 ? '' : String(r.stderr || '').trim() };
}

module.exports = { list, kill };
