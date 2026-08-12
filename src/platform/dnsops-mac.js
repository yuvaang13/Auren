/* Auren — dnsops-mac.js
 *
 * macOS DNS primitives for the daemon (networksetup/scutil). Extracted from
 * daemon.js so the daemon stays platform-neutral; see dnsops.js for the
 * dispatch. Every function is a thin spawnSync wrapper with no state.
 */

'use strict';
const { spawnSync } = require('child_process');

function run(args) {
  const r = spawnSync('/usr/sbin/networksetup', args, { encoding: 'utf8' });
  return { status: r.status, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
}

// Network services, e.g. ["Wi-Fi", "Ethernet"]. Skips asterisk-muted services
// ("*Denotes a disabled service"), which networksetup refuses to reconfigure.
function listServices() {
  const r = run(['-listallnetworkservices']);
  if (r.status !== 0) return [];
  return r.stdout.split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('*') && !l.toLowerCase().includes('asterisk'));
}

function getServers(service) {
  const r = run(['-getdnsservers', service]);
  if (r.status !== 0) return [];
  const lines = r.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return [];
  if (/aren't any dns servers|no dns server/i.test(r.stdout)) return [];
  return lines.filter((l) => /^\d{1,3}(\.\d{1,3}){3}$/.test(l));
}

function setServers(service, ips) {
  const args = ips && ips.length ? ['-setdnsservers', service, ...ips] : ['-setdnsservers', service, 'Empty'];
  return run(args).status === 0;
}

// What the system would resolve through normally: prefer the servers we backed
// up (state.services), else whatever `scutil --dns` reports, else a fixed
// default. State is passed in — this module holds no memory of past takeovers.
function discoverUpstream(stateServices, fallback) {
  const fromState = [];
  for (const svc of Object.values(stateServices || {})) {
    for (const ip of svc || []) if (ip !== '127.0.0.1' && !fromState.includes(ip)) fromState.push(ip);
  }
  if (fromState.length) return fromState;

  const r = spawnSync('/usr/sbin/scutil', ['--dns'], { encoding: 'utf8' });
  const found = [];
  if (r.status === 0 && r.stdout) {
    for (const line of r.stdout.split('\n')) {
      const m = /^\s*nameserver\[\d+\]\s*:\s*([^\s]+)/.exec(line);
      if (m) {
        const ip = m[1].trim();
        if (ip !== '127.0.0.1' && !ip.startsWith('0.') && !ip.startsWith('255.') && !found.includes(ip)) found.push(ip);
      }
    }
  }
  if (found.length) return found;
  return fallback;
}

// True when every visible resolver is a loopback address (protection on).
function isEnforcing() {
  const r = spawnSync('/usr/sbin/scutil', ['--dns'], { encoding: 'utf8' });
  if (r.status !== 0) return false;
  let saw = 0;
  let allLoopback = true;
  for (const line of r.stdout.split('\n')) {
    const m = /^\s*nameserver\[\d+\]\s*:\s*([^\s]+)/.exec(line);
    if (m) {
      saw++;
      if (!['127.0.0.1', '::1'].includes(m[1].trim())) allLoopback = false;
    }
  }
  return saw > 0 && allLoopback;
}

module.exports = { listServices, getServers, setServers, discoverUpstream, isEnforcing };
