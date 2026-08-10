/* Auren — daemon.js
 *
 * The privileged DNS daemon. Installed by the desktop app as a root
 * LaunchDaemon (com.auren.guardrail) and runs persistently, independent of
 * any browser or app.
 *
 * Responsibilities:
 *   1. Run the local DNS resolver on 127.0.0.1:53.
 *   2. Reconcile the system's real state with the requested Protection Mode:
 *        mode ON  -> point every network service's DNS at 127.0.0.1
 *        mode OFF -> restore each service's previous DNS servers
 *   3. Read the shared config file (mode + block list) and apply it in real
 *      time — no restart needed when the user adds or removes a blocked site.
 *
 * The daemon consumes only the `mode` and `blocklist` fields of the config
 * file, treats that file as untrusted input, and never touches credentials or
 * biometric data. In test mode (AUREN_DNS_ENABLED=0) it runs the resolver on
 * a configurable port and leaves system DNS alone.
 */

'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

// The daemon is run either from the repo (src/dns/) or from the flattened
// install dir (/usr/local/lib/auren/). Resolve sibling modules in both cases.
function load(name) {
  try { return require(path.join(__dirname, name)); } catch (err) {
    if (err.code !== 'MODULE_NOT_FOUND') throw err;
    return require(path.join(__dirname, '..', 'core', name));
  }
}

const { DnsResolver, DEFAULT_UPSTREAM } = require(path.join(__dirname, 'resolver.js'));
const { domainMatches } = load('domains.js');
const { readConfigFile, verifyData } = load('config.js');
const { makeEntry, appendActivity } = load('activity.js');

function logActivity(entry) {
  if (!ACTIVITY) return;
  try {
    // Never create the activity dir here: the daemon may run as root and we
    // must not create a root-owned file the user app can't write to. The app
    // owns that directory.
    if (!fs.existsSync(path.dirname(ACTIVITY))) {
      log('warn', 'activity dir missing, skipping event: ' + entry.kind + '/' + entry.outcome);
      return;
    }
    appendActivity(ACTIVITY, entry);
  } catch (err) { log('error', 'activity write failed: ' + err.message); }
}

const CONFIG = process.env.AUREN_CONFIG;
const ACTIVITY = process.env.AUREN_ACTIVITY;
const STATE = process.env.AUREN_STATE;
const KEY_FILE = process.env.AUREN_KEY;
const HEARTBEAT = process.env.AUREN_HEARTBEAT;
const DNS_ENABLED = String(process.env.AUREN_DNS_ENABLED || '1') !== '0';
const PORT = parseInt(process.env.AUREN_PORT || '53', 10);

const POLL_MS = 800;
const LOG_THROTTLE_MS = 5000;
const HEARTBEAT_MS = 2000;

// Keep in sync with dns-controller.js DAEMON_VERSION. Surfaced in the
// heartbeat so the desktop app can tell a current daemon from a stale one.
const DAEMON_VERSION = 2;

let mode = 'off';
let blocklist = [];
let resolver = null;
let upstreamApplied = false;
let state = { services: {}, applied: false };

// Fail-closed integrity state. When true, EVERY outbound lookup is refused
// (NXDOMAIN) and system DNS stays pointed at the local resolver, regardless of
// what the config file claims. Set when the config signature doesn't verify,
// the config is unreadable, or the signing key is unavailable.
let failClosed = false;
let integrityKey = null;
let integrityReported = false;

/* ----------------------------- helpers ----------------------------- */

function log(level, msg) {
  const line = `${new Date().toISOString()} [${level}] ${msg}`;
  try { fs.appendFileSync(process.env.AUREN_DAEMON_LOG || '/tmp/auren-daemon.log', line + '\n'); } catch {}
}

// Load the HMAC key that the main process uses to sign config.json. The daemon
// runs as root, so it can read the user's 0600 key file. If the key is missing
// or unreadable, the daemon cannot verify its config -> fail closed.
function loadIntegrityKey() {
  if (!KEY_FILE) {
    log('error', 'AUREN_KEY not set — cannot verify config; failing closed');
    failClosed = true;
    return;
  }
  try {
    const key = fs.readFileSync(KEY_FILE);
    if (!key || key.length === 0) throw new Error('empty key');
    integrityKey = key;
  } catch (err) {
    log('error', 'integrity key unreadable: ' + err.message);
    failClosed = true;
  }
}

// Liveness signal for the desktop app's watchdog. Written at a short interval
// with a timestamp, pid, and integrity status. World-readable on purpose: the
// unprivileged app must be able to read it. It contains no secrets.
function writeHeartbeat() {
  if (!HEARTBEAT) return;
  const body = JSON.stringify({ ts: Date.now(), pid: process.pid, version: DAEMON_VERSION, mode, failClosed, integrityOk: !failClosed }) + '\n';
  try { fs.writeFileSync(HEARTBEAT, body, { mode: 0o644 }); } catch (err) { log('error', 'heartbeat write failed: ' + err.message); }
}

function runNetworksetup(args) {
  const r = spawnSync('/usr/sbin/networksetup', args, { encoding: 'utf8' });
  return { status: r.status, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
}

function listServices() {
  const r = runNetworksetup(['-listallnetworkservices']);
  if (r.status !== 0) return [];
  return r.stdout.split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('*') && !l.toLowerCase().includes('asterisk'));
}

function getServers(service) {
  const r = runNetworksetup(['-getdnsservers', service]);
  if (r.status !== 0) return [];
  const lines = r.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return [];
  if (/aren't any dns servers|no dns server/i.test(r.stdout)) return [];
  return lines.filter((l) => /^\d{1,3}(\.\d{1,3}){3}$/.test(l));
}

function setServers(service, ips) {
  const args = ips && ips.length ? ['-setdnsservers', service, ...ips] : ['-setdnsservers', service, 'Empty'];
  return runNetworksetup(args).status === 0;
}

function saveState() {
  if (!STATE) return;
  try { fs.writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n'); } catch (err) { log('error', 'saveState: ' + err.message); }
}

function loadState() {
  if (!STATE) return;
  try { state = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch {}
  if (!state || typeof state !== 'object' || !state.services) state = { services: {}, applied: false };
}

/* --------------------------- DNS takeover --------------------------- */

function applyDns() {
  if (!DNS_ENABLED || !resolver || !resolver.running) return;
  loadState();
  let changed = false;
  for (const service of listServices()) {
    const current = getServers(service);
    const isOurs = current.length === 1 && current[0] === '127.0.0.1';
    if (isOurs) continue;
    if (!(service in state.services) && current.length > 0 && !current.includes('127.0.0.1')) {
      state.services[service] = current;
    }
    if (setServers(service, ['127.0.0.1'])) changed = true;
    else log('error', 'could not set DNS on service: ' + service);
  }
  if (changed) {
    state.applied = true;
    saveState();
    logActivity(makeEntry('daemon', 'dns_applied'));
    log('info', 'DNS pointed at 127.0.0.1 (protection on)');
  }
}

function restoreDns() {
  if (!DNS_ENABLED) return;
  loadState();
  let changed = false;
  for (const service of listServices()) {
    const current = getServers(service);
    if (!current.includes('127.0.0.1')) {
      delete state.services[service];
      continue;
    }
    const original = state.services[service];
    if (original && original.length) {
      if (setServers(service, original)) changed = true;
    } else {
      if (setServers(service, [])) changed = true;
    }
    delete state.services[service];
  }
  if (changed) {
    state.applied = false;
    saveState();
    logActivity(makeEntry('daemon', 'dns_restored'));
    log('info', 'DNS restored (protection off)');
  }
}

function discoverUpstream() {
  const fromState = [];
  for (const svc of Object.values(state.services || {})) {
    for (const ip of svc || []) if (ip !== '127.0.0.1' && !fromState.includes(ip)) fromState.push(ip);
  }
  if (fromState.length) return fromState;

  // Parse `scutil --dns` for the resolver IPs the system would use normally.
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
  return DEFAULT_UPSTREAM;
}

/* ------------------------------ blocking ----------------------------- */

function isBlocked(name) {
  const n = name.toLowerCase();
  if (!n || n === 'localhost' || n.endsWith('.local') || n.endsWith('.arpa') || n === 'localhost.') return false;
  // Fail-closed: if we can't verify our own config, refuse everything outbound.
  if (failClosed) return true;
  if (mode !== 'on') return false;
  for (const d of blocklist) {
    if (domainMatches(n, d)) return true;
  }
  return false;
}

const lastLog = new Map();
function onBlocked(name) {
  const now = Date.now();
  const last = lastLog.get(name) || 0;
  if (now - last < LOG_THROTTLE_MS) return;
  lastLog.set(name, now);
  logActivity(makeEntry('block', 'blocked', name));
}

/* ------------------------------ reconcile ---------------------------- */

let resolverDownReported = false;

async function reconcile() {
  let cfg = null;
  try {
    const raw = fs.readFileSync(CONFIG);
    const sigFile = CONFIG + '.sig';
    const sig = fs.existsSync(sigFile) ? fs.readFileSync(sigFile, 'utf8') : '';
    if (integrityKey && verifyData(raw, integrityKey, sig)) {
      cfg = readConfigFile(CONFIG);
      failClosed = !!cfg.failClosed;
    } else {
      if (!integrityReported) {
        logActivity(makeEntry('daemon', 'integrity_failed', null, 'config signature verification failed'));
        log('error', 'config signature verification FAILED — failing closed (blocking all outbound)');
        integrityReported = true;
      }
      failClosed = true;
    }
  } catch (err) {
    if (!integrityReported) {
      logActivity(makeEntry('daemon', 'integrity_failed', null, 'config unreadable: ' + err.message));
      integrityReported = true;
    }
    log('error', 'readConfig: ' + err.message);
    failClosed = true;
  }

  if (cfg) {
    mode = cfg.mode;
    blocklist = cfg.blocklist;
  } else {
    // Fail-closed: we can't trust the config, so block everything.
    mode = 'on';
    blocklist = [];
  }

  if (!resolver) {
    resolver = new DnsResolver({
      port: PORT,
      blockFn: isBlocked,
      onBlocked,
      onError: (err) => { logActivity(makeEntry('daemon', 'error', null, err.message)); log('error', err.message); }
    });
    try {
      await resolver.start();
      logActivity(makeEntry('daemon', 'started'));
      log('info', 'resolver listening on 127.0.0.1:' + PORT);
      resolverDownReported = false;
    } catch (err) {
      resolver = null;
      if (!resolverDownReported) {
        logActivity(makeEntry('daemon', 'error', null, 'could not start DNS server (port ' + PORT + ' busy?)'));
        resolverDownReported = true;
      }
      log('error', 'resolver start failed: ' + err.message);
    }
  }

  if (resolver && resolver.running && (mode === 'on' || failClosed)) {
    const upstream = discoverUpstream();
    if (!upstreamApplied || JSON.stringify(upstream) !== JSON.stringify(resolver.upstreamServers)) {
      resolver.setUpstream(upstream);
      upstreamApplied = true;
    }
  }

  // Fail-closed means DNS stays pointed at us and we deny everything, even if
  // a tampered config claims mode is OFF.
  if (mode === 'on' || failClosed) applyDns();
  else restoreDns();

  writeHeartbeat();
}

/* -------------------------------- main ------------------------------- */

function shutdown() {
  log('info', 'shutting down');
  if (mode === 'on' || failClosed) {
    // Fail-closed: leave system DNS pointed at the local resolver. Nothing
    // answers while we're down, so outbound stays denied; launchd restarts us.
    log('info', 'fail-closed: leaving DNS pointed at local resolver (deny-all while down)');
  } else {
    restoreDns();
  }
  if (resolver) resolver.stop().catch(() => {});
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

(async () => {
  log('info', 'daemon starting (dns-enabled=' + DNS_ENABLED + ' port=' + PORT + ')');
  loadIntegrityKey();
  logActivity(makeEntry('daemon', 'started'));
  await reconcile();
  setInterval(reconcile, POLL_MS);
  setInterval(writeHeartbeat, HEARTBEAT_MS);
})().catch((err) => {
  log('error', 'fatal: ' + (err && err.stack || err));
  process.exit(1);
});
