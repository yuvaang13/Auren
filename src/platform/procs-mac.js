/* Auren — procs-mac.js
 *
 * macOS process listing for the daemon's app blocker and auto-protect:
 * `ps -axo pid=,ppid=,command=` parsed with the shared core/apps.js parser,
 * and `/bin/kill -9` for the kill. Extracted from daemon.js so the daemon
 * stays platform-neutral. ppid feeds agent ancestry detection; the app blocker
 * simply ignores it.
 *
 * list()/kill() are ASYNC on purpose: the daemon runs its app-block scan on
 * the same single-threaded event loop that answers DNS. A synchronous `ps`
 * fork (~35 ms) every poll stalls every DNS reply that arrives during it —
 * non-blocked sites get noticeably slower. `spawn` keeps the scan off the loop
 * entirely. listSync() remains for rare cached callers (e.g. virt.js) that
 * need a blocking snapshot.
 */

'use strict';
const { spawn, spawnSync } = require('child_process');
const path = require('path');

// Shared process-line parser (core/apps.js in the repo, apps.js flat beside
// the daemon in the install dir). Resolve both ways like daemon.js load().
let apps;
try { apps = require(path.join(__dirname, 'apps.js')); } catch (err) {
  if (err.code !== 'MODULE_NOT_FOUND') throw err;
  apps = require(path.join(__dirname, '..', 'core', 'apps.js'));
}
const { parsePsLine } = apps;

const PS_ARGS = ['-axo', 'pid=,ppid=,command='];

function parseList(stdout) {
  return String(stdout || '')
    .split('\n')
    .map(parsePsLine)
    .filter(Boolean);
}

// Blocking snapshot for cached, occasional callers only — never the daemon's
// hot path (see header note).
function listSync() {
  const r = spawnSync('/bin/ps', PS_ARGS, { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  if (r.status !== 0) return null;
  return parseList(r.stdout);
}

// [{ pid, ppid, exe, tokens }, ...] or null when ps itself fails. Never blocks
// the event loop.
function list() {
  return new Promise((resolve) => {
    const child = spawn('/bin/ps', PS_ARGS, { stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.on('error', () => resolve(null));
    child.on('close', (code) => {
      if (code !== 0) return resolve(null);
      resolve(parseList(out));
    });
  });
}

function kill(pid) {
  return new Promise((resolve) => {
    const child = spawn('/bin/kill', ['-9', String(pid)], { stdio: ['ignore', 'ignore', 'pipe'] });
    let err = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => { err += chunk; });
    child.on('error', (e) => resolve({ ok: false, error: e.message || String(e) }));
    child.on('close', (code) => resolve({ ok: code === 0, error: code === 0 ? '' : err.trim() }));
  });
}

module.exports = { list, listSync, kill };
