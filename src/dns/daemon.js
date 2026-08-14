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

// Proxy modules live in src/proxy/ in the repo and flat in the install dir.
function loadProxy(name) {
  try { return require(path.join(__dirname, name)); } catch (err) {
    if (err.code !== 'MODULE_NOT_FOUND') throw err;
    return require(path.join(__dirname, '..', 'proxy', name));
  }
}

const { DnsResolver, DEFAULT_UPSTREAM } = require(path.join(__dirname, 'resolver.js'));
const { flushDnsCacheAsync } = require(path.join(__dirname, 'cache.js'));
const pf = require(path.join(__dirname, 'pf.js'));
const proxyServer = loadProxy('server.js');
const { domainMatches, expandBlocklist } = load('domains.js');
const { readConfigFile, verifyData } = load('config.js');
const { makeEntry, appendActivity } = load('activity.js');
const { mergeState } = load('state.js');
const apps = load('apps.js');
const autofill = loadPlatform('autofill.js');
// Platform DNS primitives (networksetup/scutil on macOS, PowerShell DnsClient
// on Windows) — the daemon never calls into the OS directly for DNS.
const dnsops = loadPlatform('dnsops.js');
// Platform process listing/killing for the app blocker.
const procs = loadPlatform('procs.js');
// Platform system-proxy push/restore (networksetup on macOS, WinINET hives on
// Windows) — the daemon never calls into the OS directly for proxy config.
const proxyops = loadPlatform('proxyops.js');

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

// Config comes from env vars (mac LaunchDaemon) or --AUREN_*=... argv
// (Windows Scheduled Task, which can't carry env vars cleanly). argv wins.
function argValue(name, def) {
  const want = '--' + name + '=';
  for (const a of process.argv.slice(2)) if (a.startsWith(want)) return a.slice(want.length);
  return process.env[name] !== undefined ? process.env[name] : def;
}

const CONFIG = argValue('AUREN_CONFIG');
const ACTIVITY = argValue('AUREN_ACTIVITY');
const STATE = argValue('AUREN_STATE');
const KEY_FILE = argValue('AUREN_KEY');
const HEARTBEAT = argValue('AUREN_HEARTBEAT');
const DNS_ENABLED = String(argValue('AUREN_DNS_ENABLED', '1')) !== '0';
const PORT = parseInt(argValue('AUREN_PORT', '53'), 10);
const PF_ENABLED = String(argValue('AUREN_PF_ENABLED', '1')) !== '0';
const PF_RULES = argValue('AUREN_PF_RULES', path.join(__dirname, 'pf.rules'));
const APPS_ENABLED = String(argValue('AUREN_APPS_ENABLED', '1')) !== '0';
const AUTOFILL_ENABLED = String(argValue('AUREN_AUTOFILL_ENABLED', '1')) !== '0';
const PROXY_ENABLED = String(argValue('AUREN_PROXY_ENABLED', '1')) !== '0';
const PROXY_PORT = parseInt(argValue('AUREN_PROXY_PORT', '42792'), 10);
// Whether the daemon also points the OS system proxy at its PAC. Kept separate
// from PROXY_ENABLED so test mode can run the blocking proxy itself without
// touching the machine's real network settings.
const PROXY_NET_ENABLED = String(argValue('AUREN_PROXY_NET_ENABLED', '1')) !== '0';
const DAEMON_LOG = argValue('AUREN_DAEMON_LOG', '/tmp/auren-daemon.log');

// System proxy points at this PAC; the proxy server serves it on its own port.
// `proxyPort`/`pacUrl` are the ACTUAL values in effect: if the default port is
// taken by another process, the proxy binds the first free port above it (up to
// +16) and the PAC URL follows, so the system proxy never points at a dead port.
let proxyPort = PROXY_PORT;
let pacUrl = 'http://127.0.0.1:' + proxyPort + '/proxy.pac';

// Fast tick. The dominant cost per tick is the ps app-block scan (~35 ms);
// all subprocess-heavy DNS/firewall work is deferred until the config changes
// or a slow self-heal sweep comes due, so 200 ms is cheap. The old 800 ms
// poll meant a site block / mode toggle / app kill took up to 800 ms to apply.
const POLL_MS = 200;
// Self-heal cadence for the network layer: re-points DNS at the resolver (or
// restores it) when the outside world drifted — a new Wi-Fi network, a NIC
// that changed, a takeover that failed — independent of config changes.
const NETWORK_SWEEP_MS = 2000;
// Hard timeout for one reconcile iteration. If a run hangs at an await (e.g.
// a proxy stop waiting on a socket that won't die) past this deadline, the
// loop is force-reset so the next tick retries instead of silently never
// reconciling again — which would leave blocking dead while the heartbeat
// keeps looking healthy.
const RECONCILE_HARD_TIMEOUT_MS = 15000;
const LOG_THROTTLE_MS = 5000;
const HEARTBEAT_MS = 2000;

// Keep in sync with dns-controller.js DAEMON_VERSION. Surfaced in the
// heartbeat so the desktop app can tell a current daemon from a stale one.
const DAEMON_VERSION = 23;

let mode = 'off';
let blocklist = [];
// The list isBlocked() actually consults: each normalized entry, deduped.
// Matching is exact-or-subdomain, so blocking mail.google.com does NOT block
// google.com — unrelated services on the same registrable domain stay
// reachable.
let effectiveBlocklist = [];
let appBlocklist = [];
let resolver = null;
let upstreamApplied = false;
let state = { services: {}, applied: false };
let reconciling = false;
let reconcileIteration = 0;
let lastReconcileStartAt = Date.now();
let lastReconcileDoneAt = Date.now();
let reconcileStuckReported = false;
let lastCfgMtime = null;
let lastFailClosed = false;
let lastNetworkRun = 0;
let networkFailed = false;

// OS/terminal-level network blocking (pf anchor), tied to Protection Mode.
let terminalBlock = true;
let terminalAllowlist = { ports: [], hosts: [] };
let dohBlock = true;
let dohHosts = [];
// HTTPS hostname blocking (loopback SNI proxy + QUIC drop), tied to Protection
// Mode. The safety floor forces it on while protection is on.
let proxyBlock = true;
let proxyActive = false;
let proxyStartReported = false;
let proxySniReported = false;
let autofillBlock = true;
let pfActive = false;
// Port-53 conflict: set when the resolver can't bind because another process
// owns the port. Surfaced in the heartbeat so the app can warn instead of
// silently running without DNS enforcement.
let dnsConflict = null;
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

// Integrity state. Two independent knobs:
//
//   failClosed       — explicit deny-all from a VERIFIED config ("failClosed":
//                      true). Every outbound lookup is refused and system DNS
//                      stays pointed at the local resolver.
//   integrityDegraded — the config could not be VERIFIED (stale/missing
//                      signature, unreadable file, missing key). The daemon
//                      then keeps enforcing the last verified policy instead of
//                      trusting (or denying on behalf of) the unverified file:
//                      unrelated traffic keeps flowing and a tampered config
//                      can neither add blocks nor weaken the enforced ones.
//                      Surfaced as integrityOk:false in the heartbeat so the
//                      app can warn.
let failClosed = false;
let integrityDegraded = false;
let integrityKey = null;
let integrityReported = false;

/* ----------------------------- helpers ----------------------------- */

function log(level, msg) {
  const line = `${new Date().toISOString()} [${level}] ${msg}`;
  try { fs.appendFileSync(DAEMON_LOG, line + '\n'); } catch {}
}

// Load the HMAC key that the main process uses to sign config.json. The daemon
// runs as root, so it can read the user's 0600 key file. If the key is missing
// or unreadable, the daemon cannot verify its config: it degrades (keeps the
// last verified policy, reports integrityOk:false) instead of denying every
// lookup.
function loadIntegrityKey() {
  if (!KEY_FILE) {
    log('error', 'AUREN_KEY not set — cannot verify config; degrading (keeping last verified policy)');
    integrityDegraded = true;
    return;
  }
  try {
    const key = fs.readFileSync(KEY_FILE);
    if (!key || key.length === 0) throw new Error('empty key');
    integrityKey = key;
  } catch (err) {
    log('error', 'integrity key unreadable: ' + err.message);
    integrityDegraded = true;
  }
}

// Liveness signal for the desktop app's watchdog. Written at a short interval
// with a timestamp, pid, and integrity status. World-readable on purpose: the
// unprivileged app must be able to read it. It contains no secrets.
function writeHeartbeat() {
  if (!HEARTBEAT) return;
  const body = JSON.stringify({ ts: Date.now(), pid: process.pid, version: DAEMON_VERSION, mode, failClosed, pf: pfActive, proxy: proxyActive, proxyPort: proxyActive ? proxyPort : null, dnsConflict, integrityOk: !integrityDegraded, lastReconcile: lastReconcileDoneAt }) + '\n';
  try { fs.writeFileSync(HEARTBEAT, body, { mode: 0o644 }); } catch (err) { log('error', 'heartbeat write failed: ' + err.message); }
}

function saveState() {
  if (!STATE) return;
  try { fs.writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n'); } catch (err) { log('error', 'saveState: ' + err.message); }
}

function loadState() {
  if (!STATE) return;
  let disk = null;
  try { disk = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch {}
  // Merge, don't replace: applyProxy records each service's prior proxy config
  // in state.proxy and this loop re-reads state.json before the proxy reconcile
  // runs. A plain replace would throw those in-memory records away and
  // clearProxy would then have nothing to restore — leaving the system PAC
  // pointed at a stopped proxy, which breaks ALL HTTPS (the exact "internet is
  // broken after protection turns off" symptom).
  state = mergeState(state, disk);
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
  // "Is 127.0.0.1 ours?" is only true when OUR resolver actually owns port 53.
  // If another process squats on 53, an existing 127.0.0.1 DNS entry belongs to
  // THAT resolver, not us — treat it as a foreign value to snapshot and restore,
  // otherwise turning protection off would clear the user's DNS to nothing.
  const dnsOurs = !!(resolver && resolver.running);
  for (const service of dnsops.listServices()) {
    const current = dnsops.getServers(service);
    const isOurs = dnsOurs && current.length === 1 && current[0] === '127.0.0.1';
    if (isOurs) continue;
    if (!(service in state.services) && current.length > 0 && !(dnsOurs && current.includes('127.0.0.1'))) {
      state.services[service] = current;
    }
    if (dnsops.setServers(service, ['127.0.0.1'])) changed = true;
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
  for (const service of dnsops.listServices()) {
    const current = dnsops.getServers(service);
    if (!current.includes('127.0.0.1')) {
      delete state.services[service];
      continue;
    }
    const original = state.services[service];
    if (original && original.length) {
      if (dnsops.setServers(service, original)) changed = true;
      else failed = true;
    } else {
      if (dnsops.setServers(service, [])) changed = true;
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
  return dnsops.discoverUpstream(state.services, DEFAULT_UPSTREAM);
}

/* ------------------------------ blocking ----------------------------- */

function isBlocked(name) {
  const n = name.toLowerCase();
  if (!n || n === 'localhost' || n.endsWith('.local') || n.endsWith('.arpa') || n === 'localhost.') return false;
  // Explicit fail-closed (from a verified config): refuse everything outbound.
  if (failClosed) return true;
  if (mode !== 'on') return false;
  for (const d of effectiveBlocklist) {
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

// Kill running copies of blocked apps. Scans the platform process list,
// matches exact executable path / basename / argv token (core/apps.js — never
// a substring), and kills matches with SIGKILL/taskkill. Runs while protection
// is expected, throttled to once per second (a blocked app that is relaunched
// is killed within ~1 s and stays stopped). The scan is ASYNC — it runs on the
// same event loop that answers DNS, and a synchronous `ps`/CIM fork on every
// poll would stall every DNS reply that arrives during it, making all
// non-blocked sites feel slower. Never touches our own pid or the daemon
// interpreter (process.execPath); the safety floor below has already stripped
// any entry pointing at it.
const APP_SCAN_MS = 1000;
let lastAppScanAt = 0;
async function enforceAppBlocks() {
  if (!APPS_ENABLED || appBlocklist.length === 0) return;
  const now = Date.now();
  if (now - lastAppScanAt < APP_SCAN_MS) return;
  lastAppScanAt = now;
  const processList = await procs.list();
  if (!processList) {
    log('error', 'app scan failed');
    return;
  }
  const hits = apps.findBlockedProcesses(processList, appBlocklist, {
    selfPid: process.pid,
    protectedExes: [process.execPath]
  });
  for (const hit of hits) {
    const key = hit.entry.id;
    const killRes = await procs.kill(hit.pid);
    if (!killRes.ok) {
      log('warn', 'could not kill ' + hit.entry.name + ' (pid ' + hit.pid + '): ' + String(killRes.error || '').trim());
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
// previous run took, and a slow subprocess iteration (networksetup, scutil,
// PowerShell, pfctl) must not overlap the next one or subprocesses pile up.
//
// A run that hangs at an await would otherwise wedge the loop forever:
// `reconciling` stays true, every subsequent call no-ops, and blocking stops
// silently while the heartbeat interval (independent of this loop) keeps
// writing fresh liveness. So if a run is still in flight past the hard
// timeout, the flag is force-reset and the next tick starts a fresh iteration
// — the stuck run is abandoned, and its late finally() is fenced off by the
// iteration counter so it can't clear a newer run's flag.
async function reconcile() {
  const myIter = ++reconcileIteration;
  if (reconciling) {
    const stuckMs = Date.now() - lastReconcileStartAt;
    if (!reconcileStuckReported && stuckMs >= RECONCILE_HARD_TIMEOUT_MS) {
      reconcileStuckReported = true;
      log('error', 'reconcile iteration stuck for ' + stuckMs + 'ms — force-resetting the loop so blocking resumes');
    }
    if (stuckMs >= RECONCILE_HARD_TIMEOUT_MS) reconciling = false;
    return;
  }
  reconciling = true;
  lastReconcileStartAt = Date.now();
  try {
    await reconcileInner();
    reconcileStuckReported = false;
    if (reconcileIteration === myIter) lastReconcileDoneAt = Date.now();
  } catch (err) {
    log('error', 'reconcile iteration failed: ' + (err && (err.stack || err.message) || err));
  } finally {
    if (reconcileIteration === myIter) reconciling = false;
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
      integrityDegraded = false;
    } else {
      if (!integrityReported) {
        logActivity(makeEntry('daemon', 'integrity_failed', null, 'config signature verification failed'));
        log('error', 'config signature verification FAILED — keeping the last verified policy (config ignored)');
        integrityReported = true;
      }
      // Fail-safe, not fail-closed: the unverified file is ignored entirely.
      // mode/blocklist/appBlocklist/etc. keep their last verified values, so a
      // tampered config can neither add blocks nor weaken the ones already
      // enforced. (Explicit deny-all via cfg.failClosed is honored only from a
      // VERIFIED config.) The heartbeat reports integrityOk:false so the app
      // warns that the policy is the previously verified one.
      integrityDegraded = true;
    }
  } catch (err) {
    if (!integrityReported) {
      logActivity(makeEntry('daemon', 'integrity_failed', null, 'config unreadable: ' + err.message));
      integrityReported = true;
    }
    log('error', 'readConfig: ' + err.message);
    integrityDegraded = true;
  }

  if (cfg) {
    mode = cfg.mode;
    blocklist = cfg.blocklist;
    effectiveBlocklist = expandBlocklist(blocklist);
    appBlocklist = cfg.appBlocklist;
    terminalBlock = cfg.terminalBlock !== false;
    terminalAllowlist = cfg.terminalAllowlist || { ports: [], hosts: [] };
    dohBlock = cfg.dohBlock !== false;
    dohHosts = Array.isArray(cfg.dohHosts) ? cfg.dohHosts : [];
    proxyBlock = cfg.proxyBlock !== false;
    autofillBlock = cfg.autofillBlock !== false;
  }
  // No cfg (unverifiable or unreadable): keep the last verified values above —
  // the daemon never widens enforcement based on an untrusted file.

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
      dohHosts,
      proxyBlock
    });
    terminalBlock = floor.terminalBlock;
    terminalAllowlist = { ports: floor.allowPorts, hosts: floor.allowHosts };
    dohBlock = floor.dohBlock;
    dohHosts = floor.dohHosts;
    proxyBlock = floor.proxyBlock;
    const floorJson = JSON.stringify([floor.changed, floor.allowPorts, floor.allowHosts, floor.dohHosts, floor.proxyBlock]);
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
      if (dnsConflict) {
        dnsConflict = null;
        logActivity(makeEntry('daemon', 'dns_conflict_cleared'));
      }
    } catch (err) {
      resolver = null;
      if (!resolverDownReported) {
        logActivity(makeEntry('daemon', 'error', null, 'could not start DNS server (port ' + PORT + ' busy?)'));
        resolverDownReported = true;
      }
      log('error', 'resolver start failed: ' + err.message);
      // Name the port owner so the desktop app can tell the user exactly what
      // is squatting on 53 instead of a generic "port busy".
      try {
        const owner = dnsops.portOwner(PORT);
        const key = JSON.stringify(owner);
        const changed = JSON.stringify(dnsConflict) !== key;
        dnsConflict = owner ? { port: PORT, pid: owner.pid, name: owner.name } : { port: PORT, pid: null, name: null };
        if (changed) {
          logActivity(makeEntry('daemon', 'dns_conflict', null, owner && owner.name ? owner.name + ' (pid ' + owner.pid + ') is listening on 53' : 'unidentified process is listening on 53'));
          log('warn', 'port ' + PORT + ' is owned by ' + (owner ? (owner.name + ' (pid ' + owner.pid + ')') : 'an unidentified process'));
        }
      } catch (e) { log('error', 'port-53 owner probe failed: ' + e.message); }
    }
  }

  // HTTPS hostname blocking: run the loopback SNI proxy whenever protection is
  // on (or fail-closed) and the proxy layer is enabled. It never terminates
  // TLS; it only reads CONNECT hosts / ClientHello SNI and refuses blocked
  // hostnames (fail-closed on anything unreadable). A bind failure is logged
  // and retried each poll — never fatal, and the system proxy is only pointed
  // at it once it is actually listening.
  const wantProxy = PROXY_ENABLED && proxyBlock && (mode === 'on' || failClosed);
  if (wantProxy && !proxyActive) {
    // Bind the first free port in [PROXY_PORT, PROXY_PORT+16]. A conflict on
    // the default (42792) shouldn't silently kill HTTPS host blocking — the
    // PAC it serves embeds whichever port actually bound.
    let bound = null;
    for (let p = PROXY_PORT; p <= PROXY_PORT + 16 && !bound; p++) {
      try {
        bound = await proxyServer.start({
          port: p,
          blockFn: isBlocked,
          onBlocked,
          onUnreadable: () => {
            if (!proxySniReported) {
              logActivity(makeEntry('daemon', 'proxy_sni_unreadable', null, 'HTTPS tunnel with unreadable hostname refused (fail-closed)'));
              proxySniReported = true;
            }
          }
        });
      } catch (err) {
        if (p === PROXY_PORT + 16) {
          log('error', 'proxy start failed on all ports ' + PROXY_PORT + '..' + (PROXY_PORT + 16) + ': ' + err.message);
        } else {
          log('warn', 'proxy port ' + p + ' busy (' + err.message + '), trying ' + (p + 1));
        }
      }
    }
    if (bound) {
      proxyPort = bound.port;
      pacUrl = 'http://127.0.0.1:' + proxyPort + '/proxy.pac';
      proxyActive = true;
      proxyStartReported = false;
      proxySniReported = false;
      logActivity(makeEntry('daemon', 'proxy_started', null, 'HTTPS host blocking on 127.0.0.1:' + proxyPort));
      log('info', 'proxy listening on 127.0.0.1:' + proxyPort);
    } else {
      proxyActive = false;
      if (!proxyStartReported) {
        logActivity(makeEntry('daemon', 'error', null, 'could not start HTTPS blocking proxy (port ' + PROXY_PORT + ' busy?)'));
        proxyStartReported = true;
      }
    }
  } else if (!wantProxy && proxyActive) {
    await proxyServer.stop();
    proxyActive = false;
    proxySniReported = false;
    proxyPort = PROXY_PORT;
    pacUrl = 'http://127.0.0.1:' + proxyPort + '/proxy.pac';
    logActivity(makeEntry('daemon', 'proxy_stopped'));
    log('info', 'proxy stopped');
  }

  // Cheap change detection (no subprocesses): the app writes config.json only
  // when something actually changed, so an mtime diff means a reconcile is due.
  // A missing config is treated as a change on the transition (the read above
  // already degraded us); updating lastCfgMtime either way stops a vanished
  // file from re-triggering a full reconcile on every tick.
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

    // System proxy: point HTTPS at the loopback blocking proxy while it is
    // actually listening (otherwise leave the system proxy alone — HTTPS that
    // falls through still hits the DNS layer). Restore the user's original
    // proxy config when protection is off or the proxy is unavailable.
    const wantProxyNet = PROXY_NET_ENABLED && PROXY_ENABLED && proxyActive && proxyBlock && (mode === 'on' || failClosed);
    const proxyRes = wantProxyNet ? proxyops.applyProxy(state, pacUrl) : proxyops.clearProxy(state, pacUrl);
    if (proxyRes.changed) {
      // Persist the per-service proxy records (and their removal) so the PAC is
      // restorable after a daemon restart — without this, a restart while
      // protection is ON loses the user's original proxy config and turning
      // protection off leaves the system pointed at a stopped proxy.
      saveState();
      if (wantProxyNet) {
        logActivity(makeEntry('daemon', 'proxy_applied'));
        log('info', 'system HTTPS proxy pointed at ' + pacUrl);
      } else {
        logActivity(makeEntry('daemon', 'proxy_restored'));
        log('info', 'system proxy restored');
      }
    }
    if (proxyRes.failed) {
      log('error', 'system proxy reconcile failed (will retry)');
    }
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
  const rules = osBlock ? pf.buildAnchorRules({ allowPorts: terminalAllowlist.ports, allowHosts: terminalAllowlist.hosts, dohBlock, dohHosts, proxyBlock }) : [];
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
  if (mode === 'on' || failClosed) await enforceAppBlocks();

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
    // Protection is live (or explicitly deny-all): leave system DNS pointed at
    // the local resolver. Nothing answers while we're down, so outbound stays
    // denied until launchd restarts us — never hand the machine back open.
    log('info', 'protection was on: leaving DNS pointed at local resolver (denied while down)');
  } else {
    restoreDns();
    try { proxyops.clearProxy(state, pacUrl); } catch (err) { log('error', 'proxy restore failed: ' + err.message); }
  }
  if (proxyActive) proxyServer.stop().catch(() => {});
  if (resolver) resolver.stop().catch(() => {});
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
// Windows: also handle exit signals from GenerateConsoleCtrlEvent when stdio is ignored
if (process.platform === 'win32') {
  process.on('exit', (code) => { if (code !== 0) shutdown(); });
}

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
