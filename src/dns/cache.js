/* Auren — cache.js
 *
 * Flushes the macOS DNS caches so that blocking takes effect immediately for
 * sites that were resolved before Protection Mode was turned on.
 *
 * DNS-level blocking only affects NEW resolutions: macOS's mDNSResponder and
 * browsers keep previously-answered IPs (and live connections) cached, so a
 * site visited while protection was OFF would keep loading from cache after it
 * is turned ON. The root daemon flushes the OS cache at every transition
 * (mode on/off, block-list change), forcing the next lookup to re-resolve
 * through Auren's resolver.
 *
 * `dscacheutil -flushcache` and `killall -HUP mDNSResponder` both require root;
 * that's why this lives in the daemon and not the desktop app. The exec is
 * injectable so the unprivileged test suite can exercise the logic without
 * touching a real machine's cache.
 */

'use strict';
const fs = require('fs');
const { execFile, execFileSync } = require('child_process');

// macOS consolidated its command-line tools into /usr/bin; older systems keep
// the classic /bin and /usr/sbin copies (often as symlinks). Resolve each tool
// to the first path that actually exists at load time, so the root daemon can
// spawn it on any modern macOS instead of failing with ENOENT when a binary
// lives somewhere else than the classic layout.
function resolveExecutable(candidates) {
  for (const p of candidates) {
    try { fs.accessSync(p, fs.constants.X_OK); return p; } catch { /* try next */ }
  }
  return candidates[0];
}

// Order matters: flush first, then poke mDNSResponder so it drops its in-memory
// positive and negative cache entries. Failures are non-fatal — worst case the
// cache survives and blocking still applies to genuinely new lookups.
const FLUSH_COMMANDS = [
  [resolveExecutable(['/usr/bin/dscacheutil', '/usr/sbin/dscacheutil']), ['-flushcache']],
  [resolveExecutable(['/usr/bin/killall', '/bin/killall']), ['-HUP', 'mDNSResponder']]
];

function describeError(cmd, err) {
  return cmd + ': ' + (err && err.message || err);
}

// Synchronous flush (used by the CLI and the test suite). Blocking by design —
// the running daemon must use flushDnsCacheAsync instead so a slow
// `killall -HUP mDNSResponder` can never starve the heartbeat writer, which
// shares the daemon's single event loop.
function flushDnsCache(opts) {
  const run = (opts && opts.execFileSync) || execFileSync;
  const errors = [];
  for (const [cmd, args] of FLUSH_COMMANDS) {
    try {
      run(cmd, args, { stdio: 'ignore' });
    } catch (err) {
      errors.push(describeError(cmd, err));
    }
  }
  return { flushed: errors.length === 0, errors };
}

// Non-blocking flush: fires both commands without awaiting and reports once
// both have settled. The daemon uses this so the watchdog heartbeat interval
// keeps running no matter how slow mDNSResponder is to restart. Injectable for
// tests, just like the sync variant.
function flushDnsCacheAsync(opts, cb) {
  const run = (opts && opts.execFile) || execFile;
  const errors = [];
  let pending = FLUSH_COMMANDS.length;
  for (const [cmd, args] of FLUSH_COMMANDS) {
    run(cmd, args, { stdio: 'ignore' }, (err) => {
      if (err) errors.push(describeError(cmd, err));
      pending -= 1;
      if (pending === 0) cb({ flushed: errors.length === 0, errors });
    });
  }
}

module.exports = { flushDnsCache, flushDnsCacheAsync, FLUSH_COMMANDS };
