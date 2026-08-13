/* Auren — proxyops-mac.js
 *
 * macOS system-proxy primitives for the daemon (networksetup), mirroring
 * dnsops-mac.js: per network service, remember what the auto-proxy URL was,
 * point it at Auren's PAC, and restore it later. State lives in the daemon's
 * state.json (state.proxy = { service: { enabled, url } }) so a takeover
 * round-trips a daemon restart exactly like the DNS takeover does.
 */

'use strict';
const { spawnSync } = require('child_process');
const dnsops = require('./dnsops-mac');

function run(args) {
  const r = spawnSync('/usr/sbin/networksetup', args, { encoding: 'utf8' });
  return { status: r.status, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
}

function listServices() {
  return dnsops.listServices();
}

// { enabled: boolean, url: string } for one service's auto-proxy config.
function getProxyState(service) {
  const r = run(['-getautoproxyurl', service]);
  if (r.status !== 0) return { enabled: false, url: '' };
  let url = '';
  let enabled = false;
  for (const line of r.stdout.split('\n')) {
    const m = /^URL:\s*(.*)$/.exec(line.trim());
    if (m) url = m[1].trim();
    if (/^Enabled:\s*Yes/i.test(line.trim())) enabled = true;
  }
  return { enabled, url };
}

function setAutoProxy(service, pacUrl) {
  const u = run(['-setautoproxyurl', service, pacUrl]);
  const s = run(['-setautoproxystate', service, 'on']);
  return u.status === 0 && s.status === 0;
}

function clearAutoProxy(service) {
  return run(['-setautoproxystate', service, 'off']).status === 0;
}

// Point every network service's auto-proxy at Auren's PAC. Remembers each
// service's prior { enabled, url } the first time it takes it over (so the
// original config is never lost), then skips services already pointed at us.
function applyProxy(state, pacUrl) {
  if (!state || typeof state !== 'object') state = {};
  if (!state.proxy) state.proxy = {};
  let changed = false;
  let failed = false;
  for (const service of listServices()) {
    if (!(service in state.proxy)) {
      const cur = getProxyState(service);
      state.proxy[service] = cur;
    }
    const st = getProxyState(service);
    if (st.enabled && st.url === pacUrl) continue;
    if (setAutoProxy(service, pacUrl)) changed = true;
    else failed = true;
  }
  return { changed, failed };
}

// Restore each service we took over to its original auto-proxy config, then
// forget it. Services that vanished from the network list are dropped silently.
// Only services currently pointed at `pacUrl` (ours) are touched, so a service
// the user re-pointed elsewhere meanwhile is left alone.
function clearProxy(state, pacUrl) {
  if (!state || typeof state !== 'object' || !state.proxy) return { changed: false, failed: false };
  let changed = false;
  let failed = false;
  for (const service of Object.keys(state.proxy)) {
    const prior = state.proxy[service] || {};
    const st = getProxyState(service);
    const ours = !!pacUrl ? st.url === pacUrl : /^http:\/\/127\.0\.0\.1:4279\d\/proxy\.pac$/.test(st.url);
    if (ours) {
      if (prior.url) {
        setAutoProxy(service, prior.url);
        if (!prior.enabled) clearAutoProxy(service);
      } else {
        clearAutoProxy(service);
      }
      changed = true;
    }
    delete state.proxy[service];
  }
  return { changed, failed };
}

// True when at least one service has auto-proxy enabled pointing at our PAC.
function isProxyActive(pacUrl) {
  for (const service of listServices()) {
    const st = getProxyState(service);
    if (st.enabled && st.url === pacUrl) return true;
  }
  return false;
}

module.exports = { listServices, getProxyState, setAutoProxy, clearAutoProxy, applyProxy, clearProxy, isProxyActive };
