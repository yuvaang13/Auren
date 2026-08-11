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
 * The daemon consumes the `mode`, `blocklist`, `terminalBlock`,
 * `terminalAllowlist`, `dohBlock`, and `dohHosts` fields of the config
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
const { flushDnsCacheAsync } = require(path.join(__dirname, 'cache.js'));
const pf = require(path.join(__dirname, 'pf.js'));
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
const PF_ENABLED = String(process.env.AUREN_PF_ENABLED || '1') !== '0';
const PF_RULES = process.env.AUREN_PF_RULES || path.join(__dirname, 'pf.rules');

const POLL_MS = 800;
const LOG_THROTTLE_MS = 5000;
const HEARTBEAT_MS = 2000;

// Keep in sync with dns-controller.js DAEMON_VERSION. Surfaced in the
// heartbeat so the desktop app can tell a current daemon from a stale one.
const DAEMON_VERSION = 7;

let mode = 'off';
let blocklist = [];
let resolver = null;
let upstreamApplied = false;
let state = { services: {}, applied: false };

// OS/terminal-level network blocking (pf anchor), tied to Protection Mode.
let terminalBlock = true;
let terminalAllowlist = { ports: [], hosts: [] };
let dohBlock = true;
let dohHosts = [];
let pfActive = false;
let lastAnchorJson = '';
let pfFailReported = false;
// DoH/DoT packet-counter sweep: a negative baseline means "not yet seen", so
// the first sweep after an anchor (re)load establishes a baseline instead of
// logging a spurious delta.
let lastDohPackets = -1;
let lastDohSweep = 0;

// Last-applied policy, used to detect real changes (mode switch, DNS switch,
// block-list edit) so we only flush the OS DNS cache when it matters — not on
// every 800 ms poll.
let lastMode = 'off';
let lastBlocklistJson = '[]';

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
  const body = JSON.stringify({ ts: Date.now(), pid: process.pid, version: DAEMON_VERSION, mode, failClosed, pf: pfActive, integrityOk: !failClosed }) + '\n';
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
  if (!DNS_ENABLED || !resolver || !resolver.running) return false;
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
  return changed;
}

function restoreDns() {
  if (!DNS_ENABLED) return false;
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
  return changed;
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

/* --------------------------- cache flushing --------------------------- */

// Drop macOS's cached DNS answers so sites resolved before a protection or
// block-list change re-resolve through this resolver instead of loading from
// cache. Runs as root (the daemon); failures are logged but non-fatal. Uses the
// async variant so a slow mDNSResponder restart can never stall the watchdog
// heartbeat, which shares this process's event loop.
function flushCache() {
  flushDnsCacheAsync(null, (res) => {
    if (!res.flushed) {
      for (const e of res.errors) log('warn', 'dns cache flush failed: ' + e);
      logActivity(makeEntry('daemon', 'cache_flush_failed'));
    } else {
      log('info', 'dns cache flushed');
    }
  });
}

/* ------------------------------ reconcile ---------------------------- */

let resolverDownReported = false;

async function reconcile() {
  // Liveness first: stamp a heartbeat BEFORE any blocking work (networksetup,
  // scutil, DNS-cache flush) so the desktop app's watchdog never reads a stale
  // file just because a slow reconcile iteration is still running. The 2s
  // interval keeps writing between iterations; this guarantees freshness even
  // while one is in flight.
  writeHeartbeat();

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
    terminalBlock = cfg.terminalBlock !== false;
    terminalAllowlist = cfg.terminalAllowlist || { ports: [], hosts: [] };
    dohBlock = cfg.dohBlock !== false;
    dohHosts = Array.isArray(cfg.dohHosts) ? cfg.dohHosts : [];
  } else {
    // Fail-closed: we can't trust the config, so block everything.
    mode = 'on';
    blocklist = [];
    terminalBlock = true;
    terminalAllowlist = { ports: [], hosts: [] };
    dohBlock = true;
    dohHosts = [];
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
  const dnsChanged = (mode === 'on' || failClosed) ? applyDns() : restoreDns();
  const modeChanged = mode !== lastMode;
  const blocklistChanged = JSON.stringify(blocklist) !== lastBlocklistJson;
  lastMode = mode;
  lastBlocklistJson = JSON.stringify(blocklist);

  // Flush the OS DNS cache whenever the enforced policy changed (mode toggled,
  // DNS servers switched, or a domain was added/removed while staying ON), so
  // previously-cached sites are forced to re-resolve through this resolver.
  if (DNS_ENABLED && (dnsChanged || modeChanged || blocklistChanged)) {
    flushCache();
  }

  // OS/terminal-level network blocking via the pf anchor. Engages whenever
  // protection is on (or we are fail-closed) and terminal blocking is enabled.
  // Rules are only reloaded when their content actually changes, mirroring the
  // block-list change detection above. Failures are logged (once per failure
  // window) and retried on the next poll; they must never affect DNS
  // enforcement.
  const osBlock = PF_ENABLED && (mode === 'on' || failClosed) && terminalBlock;
  const rules = osBlock ? pf.buildAnchorRules({ allowPorts: terminalAllowlist.ports, allowHosts: terminalAllowlist.hosts, dohBlock, dohHosts }) : [];
  const rulesJson = JSON.stringify(rules);
  if (osBlock && rulesJson !== lastAnchorJson) {
    try {
      fs.writeFileSync(PF_RULES, rules.join('\n') + '\n', { mode: 0o600 });
      const res = pf.applyAnchor(PF_RULES);
      if (res.ok) {
        if (!pfActive) logActivity(makeEntry('daemon', 'pf_applied'));
        pfActive = true;
        pfFailReported = false;
        lastAnchorJson = rulesJson;
        log('info', 'pf anchor loaded (' + rules.length + ' rules)');
      } else {
        if (!pfFailReported) {
          logActivity(makeEntry('daemon', 'pf_failed', null, res.error));
          pfFailReported = true;
        }
        log('error', 'pf apply failed: ' + res.error);
      }
    } catch (err) {
      if (!pfFailReported) {
        logActivity(makeEntry('daemon', 'pf_failed', null, err.message));
        pfFailReported = true;
      }
      log('error', 'pf apply failed: ' + err.message);
    }
  } else if (!osBlock && pfActive) {
    const res = pf.clearAnchor();
    if (res.ok) {
      pfActive = false;
      pfFailReported = false;
      lastAnchorJson = '';
      logActivity(makeEntry('daemon', 'pf_cleared'));
      log('info', 'pf anchor cleared');
    } else {
      log('error', 'pf clear failed: ' + res.error);
    }
  }

  // Watch pf's packet counters for the DoH/DoT block rules and log whenever
  // something actually attempted a bypass. DNS-level filtering alone would
  // stay silent here — only a packet counter can see it. Deltas, not absolute
  // counts, and at most one entry per 15 s.
  if (pfActive) sweepDohCounters();

  writeHeartbeat();
}

// See the call site above. Polls `pfctl -a auren -vsr`, maps the DoH block
// rules by index (dohBlockRange), and logs the packet delta.
function sweepDohCounters() {
  if (!dohBlock || !pfActive) return;
  const now = Date.now();
  if (now - lastDohSweep < 15000) return;
  lastDohSweep = now;
  const range = pf.dohBlockRange({ allowPorts: terminalAllowlist.ports, allowHosts: terminalAllowlist.hosts, dohBlock, dohHosts });
  if (!range) return;
  const res = pf.ruleStats();
  if (!res.ok || !Array.isArray(res.stats) || res.stats.length < range.start + range.count) return;
  let packets = 0;
  for (let i = range.start; i < range.start + range.count; i++) {
    packets += res.stats[i] ? res.stats[i].packets : 0;
  }
  if (lastDohPackets < 0) {
    // First sweep after an anchor (re)load: anchor reloads reset counters, so
    // this establishes the baseline without logging a phantom delta.
    lastDohPackets = packets;
    return;
  }
  const delta = packets - lastDohPackets;
  if (delta > 0) {
    logActivity(makeEntry('daemon', 'doh_blocked', null, delta + ' packet(s) to known DoH/DoT endpoints blocked'));
    log('info', 'DoH/DoT block attempt: ' + delta + ' packet(s)');
  }
  lastDohPackets = packets;
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
  // Write a heartbeat immediately and keep the interval running BEFORE the
  // first reconcile completes. The first reconcile makes blocking network
  // calls (networksetup, dns cache flush) and can be slow; the desktop app's
  // watchdog must not read "no heartbeat" as "daemon is dead" just because
  // startup is still in progress.
  writeHeartbeat();
  setInterval(writeHeartbeat, HEARTBEAT_MS);
  await reconcile();
  setInterval(reconcile, POLL_MS);
})().catch((err) => {
  log('error', 'fatal: ' + (err && err.stack || err));
  process.exit(1);
});
