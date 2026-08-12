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
 *   3. Read the shared config file (mode + block lists) and apply it in real
 *      time — no restart needed when the user adds or removes a blocked site
 *      or app.
 *   4. Enforce the app block list: kill running copies of blocked apps and
 *      keep them stopped while protection is on.
 *   5. Block browser autofill while protection is on: write managed-prefs
 *      plists that disable Chromium-family password/address/card autofill.
 *
 * The daemon consumes the `mode`, `blocklist`, `appBlocklist`,
 * `terminalBlock`, `terminalAllowlist`, `dohBlock`, `dohHosts`, and
 * `autofillBlock` fields of the config file, treats that file as untrusted
 * input, and never touches credentials or biometric data. In test mode
 * (AUREN_DNS_ENABLED=0) it runs the resolver on a configurable port and
 * leaves system DNS alone.
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

// Platform modules live in src/platform/ in the repo and flat in the install
// dir (staged alongside the daemon), mirroring load().
function loadPlatform(name) {
  try { return require(path.join(__dirname, name)); } catch (err) {
    if (err.code !== 'MODULE_NOT_FOUND') throw err;
    return require(path.join(__dirname, '..', 'platform', name));
  }
}

const { DnsResolver, DEFAULT_UPSTREAM } = require(path.join(__dirname, 'resolver.js'));
const { flushDnsCacheAsync } = require(path.join(__dirname, 'cache.js'));
const pf = require(path.join(__dirname, 'pf.js'));
const { domainMatches } = load('domains.js');
const { readConfigFile, verifyData } = load('config.js');
const { makeEntry, appendActivity } = load('activity.js');
const apps = load('apps.js');
const autofill = loadPlatform('autofill.js');

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
const APPS_ENABLED = String(process.env.AUREN_APPS_ENABLED || '1') !== '0';
const AUTOFILL_ENABLED = String(process.env.AUREN_AUTOFILL_ENABLED || '1') !== '0';

// Fast tick. The dominant cost per tick is the ps app-block scan (~35 ms);
// all subprocess-heavy DNS/firewall work is deferred until the config changes
// or a slow self-heal sweep comes due, so 200 ms is cheap. The old 800 ms
// poll meant a site block / mode toggle / app kill took up to 800 ms to apply.
const POLL_MS = 200;
// Self-heal cadence for the network layer: re-points DNS at the resolver (or
// restores it) when the outside world drifted — a new Wi-Fi network, a NIC
// that changed, a takeover that failed — independent of config changes.
const NETWORK_SWEEP_MS = 2000;
const LOG_THROTTLE_MS = 5000;
const HEARTBEAT_MS = 2000;

// Keep in sync with dns-controller.js DAEMON_VERSION. Surfaced in the
// heartbeat so the desktop app can tell a current daemon from a stale one.
const DAEMON_VERSION = 14;

let mode = 'off';
let blocklist = [];
let appBlocklist = [];
let resolver = null;
let upstreamApplied = false;
let state = { services: {}, applied: false };
let reconciling = false;
let lastCfgMtime = null;
let lastFailClosed = false;
let lastNetworkRun = 0;
let networkFailed = false;

// OS/terminal-level network blocking (pf anchor), tied to Protection Mode.
let terminalBlock = true;
let terminalAllowlist = { ports: [], hosts: [] };
let dohBlock = true;
let dohHosts = [];
let autofillBlock = true;
let pfActive = false;
let lastAnchorJson = '';
let pfFailReported = false;
// Dedup key for the safety-floor activity entry (see reconcile below): only
// log when the floor actually dropped/forced something different from last time.
let lastFloorJson = '';
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

// Cheap config-change probe (~0.02 ms, no subprocess): the desktop app writes
// config.json only when something actually changed, so an mtime diff means a
// full reconcile is due. Returns null if the file is missing/unreadable.
function statCfgMtime() {
  try { return fs.statSync(CONFIG).mtimeMs; } catch { return null; }
}

/* --------------------------- DNS takeover --------------------------- */

function applyDns() {
  if (!DNS_ENABLED || !resolver || !resolver.running) return { changed: false, failed: false };
  loadState();
  let changed = false;
  let failed = false;
  for (const service of listServices()) {
    const current = getServers(service);
    const isOurs = current.length === 1 && current[0] === '127.0.0.1';
    if (isOurs) continue;
    if (!(service in state.services) && current.length > 0 && !current.includes('127.0.0.1')) {
      state.services[service] = current;
    }
    if (setServers(service, ['127.0.0.1'])) changed = true;
    else {
      failed = true;
      log('error', 'could not set DNS on service: ' + service);
    }
  }
  if (changed) {
    state.applied = true;
    saveState();
    logActivity(makeEntry('daemon', 'dns_applied'));
    log('info', 'DNS pointed at 127.0.0.1 (protection on)');
  }
  return { changed, failed };
}

function restoreDns() {
  if (!DNS_ENABLED) return { changed: false, failed: false };
  loadState();
  let changed = false;
  let failed = false;
  for (const service of listServices()) {
    const current = getServers(service);
    if (!current.includes('127.0.0.1')) {
      delete state.services[service];
      continue;
    }
    const original = state.services[service];
    if (original && original.length) {
      if (setServers(service, original)) changed = true;
      else failed = true;
    } else {
      if (setServers(service, [])) changed = true;
      else failed = true;
    }
    delete state.services[service];
  }
  if (changed) {
    state.applied = false;
    saveState();
    logActivity(makeEntry('daemon', 'dns_restored'));
    log('info', 'DNS restored (protection off)');
  }
  return { changed, failed };
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

/* --------------------------- app blocking --------------------------- */

// Dedup key for the per-app kill activity entry (see enforceAppBlocks below):
// log at most one "Blocked app" line per app per throttle window, even though
// the kill itself runs on every poll while the app stays running.
const lastAppKillLog = new Map();

// Kill running copies of blocked apps. Scans `ps -axo pid=,command=`, matches
// exact executable path / basename / argv token (core/apps.js — never a
// substring), and kills matches with SIGKILL. Runs on every poll while
// protection is expected, so a blocked app that is (re)launched is killed
// within ~1 s and stays stopped. Never touches our own pid or the daemon
// interpreter (process.execPath); the safety floor below has already stripped
// any entry pointing at it.
function enforceAppBlocks() {
  if (!APPS_ENABLED || appBlocklist.length === 0) return;
  const r = spawnSync('/bin/ps', ['-axo', 'pid=,command='], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  if (r.status !== 0) {
    log('error', 'app scan failed: ' + String(r.stderr || r.stdout || '').trim());
    return;
  }
  const hits = apps.findBlockedPids(String(r.stdout || '').split('\n'), appBlocklist, {
    selfPid: process.pid,
    protectedExes: [process.execPath]
  });
  const now = Date.now();
  for (const hit of hits) {
    const key = hit.entry.id;
    const kill = spawnSync('/bin/kill', ['-9', String(hit.pid)], { encoding: 'utf8' });
    if (kill.status !== 0) {
      log('warn', 'could not kill ' + hit.entry.name + ' (pid ' + hit.pid + '): ' + String(kill.stderr || '').trim());
      continue;
    }
    const last = lastAppKillLog.get(key) || 0;
    if (now - last >= LOG_THROTTLE_MS) {
      lastAppKillLog.set(key, now);
      logActivity(makeEntry('app', 'blocked', null, hit.entry.name));
      log('info', 'killed blocked app ' + hit.entry.name + ' (pid ' + hit.pid + ')');
    }
  }
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

// Polled entry point. Runs the full reconcile but never lets iterations
// overlap: setInterval fires on a fixed cadence regardless of how long the
// previous run took, and a slow networksetup/spawnSync iteration must not
// overlap the next one or subprocesses pile up.
async function reconcile() {
  if (reconciling) return;
  reconciling = true;
  try {
    await reconcileInner();
  } finally {
    reconciling = false;
  }
}

async function reconcileInner() {
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
    appBlocklist = cfg.appBlocklist;
    terminalBlock = cfg.terminalBlock !== false;
    terminalAllowlist = cfg.terminalAllowlist || { ports: [], hosts: [] };
    dohBlock = cfg.dohBlock !== false;
    dohHosts = Array.isArray(cfg.dohHosts) ? cfg.dohHosts : [];
    autofillBlock = cfg.autofillBlock !== false;
  } else {
    // Fail-closed: we can't trust the config, so block everything. App
    // blocking keeps the last-verified list — the config is untrusted now,
    // but the previously verified blocks are still the safe thing to enforce.
    mode = 'on';
    blocklist = [];
    terminalBlock = true;
    terminalAllowlist = { ports: [], hosts: [] };
    dohBlock = true;
    dohHosts = [];
    autofillBlock = true;
  }

  // Minimum-safety floor (root-enforced): while we are blocking, refuse to
  // disable terminal/DoH blocking or let the allowlist carve out the built-in
  // blocked ports / metadata IPs / DoH endpoints — no matter what the (possibly
  // forged) signed config claims. When protection is OFF the floor is inert.
  if (mode === 'on' || failClosed) {
    const floor = pf.safetyFloor({
      terminalBlock,
      allowPorts: terminalAllowlist.ports,
      allowHosts: terminalAllowlist.hosts,
      dohBlock,
      dohHosts
    });
    terminalBlock = floor.terminalBlock;
    terminalAllowlist = { ports: floor.allowPorts, hosts: floor.allowHosts };
    dohBlock = floor.dohBlock;
    dohHosts = floor.dohHosts;
    const floorJson = JSON.stringify([floor.changed, floor.allowPorts, floor.allowHosts, floor.dohHosts]);
    if (floor.changed && floorJson !== lastFloorJson) {
      lastFloorJson = floorJson;
      logActivity(makeEntry('daemon', 'security_floor', null, 'enforced minimum-safety floor on configured terminal/DoH settings'));
    }
    // App-block safety floor: never let a (possibly forged) signed config kill
    // Auren's own daemon interpreter. Entries pointing at process.execPath are
    // stripped before the kill loop ever sees them.
    const appFloor = apps.appSafetyFloor(appBlocklist, { selfExes: [process.execPath] });
    appBlocklist = appFloor.appBlocklist;
    if (appFloor.changed) {
      log('warn', 'dropped app-block entry pointing at the daemon interpreter: ' + appFloor.dropped.map((d) => d.id).join(', '));
    }
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

  // Cheap change detection (no subprocesses): the app writes config.json only
  // when something actually changed, so an mtime diff means a reconcile is due.
  // A missing config is treated as a change on the transition (the read above
  // already flipped us to fail-closed); updating lastCfgMtime either way stops
  // a vanished file from re-triggering a full reconcile on every tick.
  const cfgMtime = statCfgMtime();
  const cfgChanged = cfgMtime !== lastCfgMtime;
  lastCfgMtime = cfgMtime;

  // The subprocess-heavy DNS/firewall work (networksetup, scutil) runs only
  // when it can actually matter: the config changed, we entered/left
  // fail-closed, a self-heal sweep is due (external drift, e.g. a new Wi-Fi
  // network or a NIC that changed), or the last attempt failed. Everything else
  // on this path — the ps app scan, cache flush, pf — is cheap or already gated
  // on change, so POLL_MS can stay low without stalling blocking.
  const now = Date.now();
  const failClosedChanged = failClosed !== lastFailClosed;
  lastFailClosed = failClosed;
  const networkDue = cfgChanged || failClosedChanged || networkFailed || now - lastNetworkRun >= NETWORK_SWEEP_MS;

  let dnsChanged = false;
  if (networkDue) {
    lastNetworkRun = now;
    networkFailed = false;
    if (resolver && resolver.running && (mode === 'on' || failClosed)) {
      const upstream = discoverUpstream();
      if (!upstreamApplied || JSON.stringify(upstream) !== JSON.stringify(resolver.upstreamServers)) {
        resolver.setUpstream(upstream);
        upstreamApplied = true;
      }
    }

    // Fail-closed means DNS stays pointed at us and we deny everything, even
    // if a tampered config claims mode is OFF.
    const res = (mode === 'on' || failClosed) ? applyDns() : restoreDns();
    dnsChanged = res.changed;
    networkFailed = res.failed;
  }

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

  // App blocking: kill running copies of blocked apps while protection is
  // expected. Deliberately last — it must never hold up DNS/pf enforcement.
  if (mode === 'on' || failClosed) enforceAppBlocks();

  // Browser autofill blocking: while protection is on (and autofill blocking
  // is enabled), force Chromium-family browsers to disable password/address/
  // credit-card autofill via macOS managed-prefs plists. Idempotent — files
  // are only written when the desired state changes.
  if (AUTOFILL_ENABLED) {
    const res = autofill.reconcileAutofill((mode === 'on' || failClosed) && autofillBlock);
    if (res.changed) {
      if (res.enforcing) {
        logActivity(makeEntry('daemon', 'autofill_applied', null, res.covered.length ? res.covered.join(', ') : 'none'));
        log('info', 'browser autofill blocked for: ' + (res.covered.length ? res.covered.join(', ') : 'none'));
      } else {
        logActivity(makeEntry('daemon', 'autofill_cleared', null, res.covered.length ? res.covered.join(', ') : 'none'));
        log('info', 'browser autofill policies removed');
      }
      for (const e of res.errors || []) log('error', 'autofill policy failed for ' + e.browser + ': ' + e.error);
    }
  }

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
