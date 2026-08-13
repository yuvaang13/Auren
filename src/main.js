/* Auren - main.js
 *
 * Electron main process. Owns the single window, the IPC surface, and — since
 * the storage hardening — the ONLY copy of block state that may be written.
 *
 * Storage model:
 *   - The canonical block state (mode, block list, lock/unlock metadata) lives
 *     in this process, persisted to an encrypted store (guardrail.dat) that the
 *     renderer can never read directly.
 *   - The renderer and any agent-traffic bridge talk ONLY to this process via
 *     IPC (state:get, guardrail:is-blocked, agent:inspect-action, mode:set,
 *     blocklist:add/remove, appblock:search/add/remove).
 *   - The root DNS daemon is a separate process that cannot do Electron IPC,
 *     so it consumes a signed read-only snapshot (config.json + config.sig)
 *     written here. It verifies the signature before trusting a single byte and
 *     fails closed if verification fails. It has no independent, writable copy.
 *
 * Fail-closed model (see README "Fail-closed guarantees and limits"):
 *   - Config tamper, corrupt encrypted store, missing key, or a silent daemon
 *     all surface as `degraded` and cause every gated surface (DNS via the
 *     daemon's deny-all mode, agent:inspect-action) to refuse by default.
 *
 * DNS enforcement itself lives in the root daemon (see src/dns/daemon.js),
 * which runs independently of this process. On a graceful quit this process
 * writes a signed "mode: off" config so the daemon restores system DNS and
 * nothing stays blocked after Auren closes; killing the daemon itself leaves
 * system DNS pointed at a dead resolver (deny-all), not open access.
 */

'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { app, BrowserWindow, ipcMain, Menu, nativeTheme, nativeImage, Notification } = require('electron');

const config = require('./core/config');
const activity = require('./core/activity');
const store = require('./core/store');
const agentgate = require('./core/agentgate');
const agentdetect = require('./core/agentdetect');
const autoprotect = require('./core/autoprotect');
const pf = require('./dns/pf');
const virt = require('./core/virt');
const httpBridge = require('./bridge/http');
const { normalizeDomain, validateBlockDomain } = require('./core/domains');
const { normalizeAppBlocklist, validateBlockApp } = require('./core/apps');
const { quitRequiresAuth } = require('./core/quit');
const dnsController = require('./platform/dns-controller');
const appResolver = require('./platform/app-resolver');
const { requireAuthentication, requireNativeAuth } = require('./platform/biometrics');
const procs = require('./platform/procs');
const shield = require('./core/shield');
const paths = require('./platform/paths');

const USER_DATA = paths.userDataDir();
const SYSTEM_SPOOL = paths.systemSpoolDir();
const CONFIG_FILE = path.join(USER_DATA, 'config.json');
const ACTIVITY_FILE = path.join(USER_DATA, 'activity.jsonl');
const SETTINGS_FILE = path.join(USER_DATA, 'settings.json');
const SETTINGS_SIG_FILE = SETTINGS_FILE + '.sig';
const STATE_FILE = paths.stateFile();
const KEY_FILE = path.join(USER_DATA, store.KEY_FILE);
const STORE_FILE = path.join(USER_DATA, store.STORE_FILE);
const HEARTBEAT_FILE = paths.heartbeatFile();
const BRIDGE_TOKEN_FILE = path.join(USER_DATA, 'bridge.token');

app.setName('auren');
app.setPath('userData', USER_DATA);

// Dev builds run the generic Electron binary, so give the Dock the auren
// identity at runtime: custom icon + lowercase name. Packaged builds inherit
// both from the app bundle instead.
const ICON_PATH = path.join(__dirname, '..', 'build', 'icon.png');
if (process.platform === 'darwin') {
  try { app.dock.setIcon(nativeImage.createFromPath(ICON_PATH)); } catch { /* best-effort */ }
}

// Auren ships a dark UI; keep native chrome and dialogs consistent with it.
nativeTheme.themeSource = 'dark';

let mainWindow = null;
let lastSent = '';
const POLL_MS = 1000;

// Keystroke-shield state (see core/shield.js). Tracked here so the repeated
// 1s poll only calls the native APIs when the value actually changes.
let shieldContentProtection = null;
let shieldSecureInput = false;

/* --------------------------- fail-closed state --------------------------- */

// After a successful unlock (Touch ID / passcode), the block list stays active
// for this long before protection actually turns off. Gives a human a moment to
// confirm the unlock; an agent can't get at the sites instantly.
const OFF_COOLDOWN_MS = 10 * 1000;
let offCooldownTimer = null;
let offCooldownUntil = 0;
// Set once a graceful quit has cleared the protection gate, so the follow-up
// app.quit() can't re-prompt. force-quit / kill paths never set this AND never
// run liftProtectionOnQuit, so protection stays ON there.
let forceQuit = false;

// The canonical, main-process-owned block state.
let blockState = { version: 1, mode: 'off', blocklist: [], appBlocklist: [], failClosed: false, terminalBlock: true, terminalAllowlist: { ports: [], hosts: [] }, dohBlock: true, dohHosts: [], proxyBlock: true, autofillBlock: true, lock: { state: 'locked', unlockExpiry: 0 } };
let storeIntegrityKey = null;

// True when enforcement can't be trusted (daemon silent, tampered/corrupt
// store, unverified config). Every gated surface refuses while this is set.
let degraded = false;

// State of the loopback agent bridge (src/bridge/http.js). Surfaced in the UI
// state so the dashboard can show where agents hook in.
let bridgeInfo = { running: false, port: null, tokenFile: null };

// Watchdog parameters: daemon heartbeats every 2s; the stale threshold below
// trips after roughly two missed beats.
const WATCHDOG_MS = 3000;
const HEARTBEAT_STALE_MS = 8000;

// The daemon can be legitimately quiet while it's being installed/refreshed
// (bootstrap, port rebind, first slow reconcile) or in the first seconds after
// the app launches. During those windows we don't flash "degraded" — only a
// stale heartbeat once the daemon should be settled trips the watchdog.
const WATCHDOG_GRACE_MS = 12000;
const STARTED_AT = Date.now();
let daemonBusy = false;

// Auto-protect (see src/core/agentdetect.js + autoprotect.js). While protection
// is OFF, a live AI-agent session engages it automatically. One-directional:
// it can only raise protection; turning it off is always the biometric-gated
// user path, and a detected session that disappears never turns protection off.
const AUTOPROTECT_POLL_MS = 2000;
let autoProtectLastJson = '';
let autoProtectEngagedBy = [];
let lastAutoProtectSessions = [];
let autoProtectPromptAt = 0;
let autoProtectBusy = false;

function clearOffCooldown() {
  if (offCooldownTimer) { clearTimeout(offCooldownTimer); offCooldownTimer = null; }
  offCooldownUntil = 0;
  blockState.lock = { state: 'locked', unlockExpiry: 0 };
}

/* ---------------------------- daemon lifecycle ---------------------------- */

function installDaemon() {
  return dnsController.installDaemon({
    nodeBin: dnsController.findNodeBin(app.getPath('exe')),
    configPath: CONFIG_FILE,
    activityPath: ACTIVITY_FILE,
    statePath: STATE_FILE,
    keyPath: KEY_FILE,
    heartbeatPath: HEARTBEAT_FILE
  });
}

// A launchd job from an older build (before the heartbeat + signed-config
// contract) stays running forever and never writes heartbeats, which the
// watchdog would read as "service down" and degrade. Detect that and re-run
// the installer — with an OS-native admin prompt — so the running daemon
// matches this build. At startup we only prompt unprompted when protection is
// expected to be enforced; turning protection ON always re-verifies.
let daemonRefreshAttempted = false;
async function refreshDaemonIfStale() {
  if (daemonRefreshAttempted) return true;
  if (!dnsController.isDaemonInstalled() || dnsController.isDaemonCurrent()) return true;
  if (blockState.mode !== 'on' && !blockState.failClosed) return true;
  daemonRefreshAttempted = true;
  daemonBusy = true;
  try {
    const res = await installDaemon();
    if (!res.ok) {
      logActivity(activity.makeEntry('daemon', 'refresh_failed', null, 'installed background service is stale and could not be updated'));
      return false;
    }
    logActivity(activity.makeEntry('daemon', 'refreshed', null, 'background service updated to match this build'));
    return true;
  } finally {
    daemonBusy = false;
  }
}

/* ------------------------------ settings ----------------------------- */

// settings.json is a user-tunable file whose security-relevant values
// (terminalBlock, terminalAllowlist, dohBlock, dohHosts, policy overrides) are
// baked into the signed config the root daemon trusts. It is HMAC-signed
// (settings.sig, same integrity key as config.json) so edits made outside the
// app are detected and dropped: on a signature mismatch every security-relevant
// value resets to safe defaults and the UI warns. Honest limit: auren.key is
// user-readable, so a same-user process could forge the sig — the root daemon's
// safetyFloor is the actual enforcement boundary; this signature is detection
// and defense-in-depth.
let settingsTampered = false;
let settingsTamperedReported = false;
let settingsCache = { ts: 0, data: null };
const SETTINGS_CACHE_MS = 1000;

function readSettings() {
  const now = Date.now();
  if (settingsCache.data && now - settingsCache.ts < SETTINGS_CACHE_MS) return settingsCache.data;
  let s = {};
  try { s = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch { s = {}; }
  if (!s || typeof s !== 'object') s = {};
  if (storeIntegrityKey) {
    const sig = fs.existsSync(SETTINGS_SIG_FILE) ? fs.readFileSync(SETTINGS_SIG_FILE, 'utf8') : '';
    if (sig) {
      if (config.verifyData(fs.readFileSync(SETTINGS_FILE, 'utf8'), storeIntegrityKey, sig)) {
        settingsTampered = false;
      } else {
        // Signature present but invalid: tampered. Drop every security-relevant
        // value and refuse to re-sign, so the mismatch (and the UI warning)
        // persists until the app itself writes settings again.
        settingsTampered = true;
        if (!settingsTamperedReported) {
          settingsTamperedReported = true;
          logActivity(activity.makeEntry('daemon', 'settings_tampered', null, 'settings.json failed signature verification; security-relevant settings reset to defaults'));
        }
        s = { onboardingDone: !!s.onboardingDone };
      }
    } else {
      // No signature yet: pre-existing file from an older build. One-time
      // migration — sign the current content so future edits are verifiable.
      writeSettingsSig();
    }
  }
  settingsCache = { ts: now, data: s };
  return s;
}

function writeSettingsSig() {
  try {
    fs.writeFileSync(SETTINGS_SIG_FILE, config.signData(fs.readFileSync(SETTINGS_FILE, 'utf8'), storeIntegrityKey) + '\n', { mode: 0o600 });
    settingsTampered = false;
    settingsTamperedReported = false;
  } catch { /* best-effort */ }
}

function writeSettings(patch) {
  const s = Object.assign({}, readSettings(), patch);
  fs.mkdirSync(USER_DATA, { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(s, null, 2) + '\n', { mode: 0o600 });
  writeSettingsSig();
  settingsCache = { ts: Date.now(), data: s };
  return s;
}

function policyRulesFromSettings() {
  const p = readSettings().sensitivePolicy;
  return (p && typeof p === 'object') ? p : undefined;
}

function commandPolicyFromSettings() {
  const p = readSettings().commandPolicy;
  return (p && typeof p === 'object') ? p : undefined;
}

// The loopback agent bridge (HTTP API for agent frameworks) is ON by default.
// settings.json can disable it (agentBridge: false) or pick a fixed port
// (agentBridgePort) — e.g. { "agentBridge": false }. Read at startup.
function bridgeEnabled() {
  return readSettings().agentBridge !== false;
}

function bridgePort() {
  const p = Number(readSettings().agentBridgePort);
  return Number.isInteger(p) && p > 0 && p <= 65535 ? p : undefined;
}

// Per-machine bearer token for the bridge, persisted owner-only. Any local
// process that can read the file can ask Auren for a decision — bounded and
// documented (read/gate-only surface, no writes exposed).
function loadBridgeToken() {
  try {
    const existing = fs.existsSync(BRIDGE_TOKEN_FILE) ? fs.readFileSync(BRIDGE_TOKEN_FILE, 'utf8').trim() : '';
    if (existing) return existing;
    const t = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(BRIDGE_TOKEN_FILE, t + '\n', { mode: 0o600 });
    fs.chmodSync(BRIDGE_TOKEN_FILE, 0o600);
    return t;
  } catch (err) {
    logActivity(activity.makeEntry('bridge', 'token_failed', null, 'could not read/write bridge token: ' + err.message));
    return '';
  }
}

// The one ctx shared by the IPC gates and the HTTP bridge, so a decision made
// over either surface is identical. Only the auth checkpoint and activity log
// differ between surfaces — both live in this process by design.
function agentGateCtx() {
  return {
    mode: blockState.mode,
    degraded: degraded,
    failClosed: blockState.failClosed,
    sensitiveRules: policyRulesFromSettings(),
    commandRules: commandPolicyFromSettings(),
    blocklist: blockState.blocklist,
    authFn: (reason) => requireNativeAuth(reason),
    logFn: logActivity,
    notifyFn: pushState
  };
}

// Start the loopback agent bridge. Best-effort: a bind failure (port in use,
// etc.) is logged and surfaced in the UI, never fatal.
async function startAgentBridge() {
  if (!bridgeEnabled()) {
    logActivity(activity.makeEntry('bridge', 'disabled', null, 'agent bridge disabled by settings.json'));
    return;
  }
  try {
    const res = await httpBridge.start({
      port: bridgePort() || httpBridge.DEFAULT_PORT,
      token: loadBridgeToken(),
      handlers: {
        getStatus: () => ({
          app: 'auren',
          version: require('../package.json').version,
          mode: blockState.mode,
          degraded: degraded || blockState.failClosed,
          bridge: { running: true, port: httpBridge.status().port, tokenFile: BRIDGE_TOKEN_FILE }
        }),
        checkAction: (payload) => agentgate.inspectAction(payload, agentGateCtx()),
        checkCommand: (cmd) => agentgate.inspectCommand(cmd, agentGateCtx()),
        isBlocked: (domain) => agentgate.isBlocked(domain, agentGateCtx())
      }
    });
    bridgeInfo = { running: true, port: res.port, tokenFile: BRIDGE_TOKEN_FILE };
    logActivity(activity.makeEntry('bridge', 'started', null, 'agent bridge listening on 127.0.0.1:' + res.port));
  } catch (err) {
    bridgeInfo = { running: false, port: null, tokenFile: BRIDGE_TOKEN_FILE };
    logActivity(activity.makeEntry('bridge', 'start_failed', null, 'agent bridge could not listen: ' + err.message));
  }
  pushState();
}

async function stopAgentBridge() {
  try { await httpBridge.stop(); } catch { /* best-effort */ }
  if (bridgeInfo.running) {
    bridgeInfo = { running: false, port: null, tokenFile: null };
    logActivity(activity.makeEntry('bridge', 'stopped', null, 'agent bridge stopped'));
  }
}

// Terminal/OS-level blocking is tied to Protection Mode and ON by default.
// A user can add an allowlist via settings.json — the same tunable-policy
// convention as sensitivePolicy. The daemon only ever trusts the signed config,
// so the effective values are baked into the snapshot here. While settings.json
// failed verification, every security-relevant value falls back to defaults.
function effectiveTerminalAllowlist() {
  if (settingsTampered) return { ports: [], hosts: [] };
  const s = readSettings().terminalAllowlist;
  if (!s || typeof s !== 'object') return blockState.terminalAllowlist;
  return {
    ports: Array.isArray(s.ports) ? s.ports : blockState.terminalAllowlist.ports,
    hosts: Array.isArray(s.hosts) ? s.hosts : blockState.terminalAllowlist.hosts
  };
}

function effectiveTerminalBlock() {
  const s = readSettings();
  return s.terminalBlock !== false;
}

// DoH/DoT endpoint blocking is tied to Protection Mode and ON by default.
// settings.json can disable it (dohBlock) or extend the endpoint list
// (dohHosts); an empty list falls back to the built-in known DoH/DoT servers.
function effectiveDohBlock() {
  return readSettings().dohBlock !== false;
}

// Browser autofill blocking is tied to Protection Mode and ON by default.
// settings.json can disable it (autofillBlock: false), like terminalBlock.
function effectiveAutofillBlock() {
  return readSettings().autofillBlock !== false;
}

// HTTPS hostname blocking (the loopback SNI proxy + QUIC drop) is tied to
// Protection Mode and ON by default. settings.json can disable it
// (proxyBlock: false); the daemon's safety floor re-forces it while
// protection is ON, exactly like terminalBlock/dohBlock.
function effectiveProxyBlock() {
  return readSettings().proxyBlock !== false;
}

function effectiveDohHosts() {
  const s = readSettings().dohHosts;
  if (Array.isArray(s) && s.length) {
    return Array.from(new Set(s.map((h) => String(h).trim()).filter(Boolean)));
  }
  return pf.DEFAULT_DOH_HOSTS.slice();
}

function logActivity(entry) {
  activity.appendActivity(ACTIVITY_FILE, entry);
}

/* --------------------------- storage & persist --------------------------- */

function normalizeLoadedState(loaded) {
  const allowlist = (loaded.terminalAllowlist && typeof loaded.terminalAllowlist === 'object')
    ? {
        ports: Array.isArray(loaded.terminalAllowlist.ports) ? loaded.terminalAllowlist.ports.filter((p) => Number(p) >= 1 && Number(p) <= 65535) : [],
        hosts: Array.isArray(loaded.terminalAllowlist.hosts) ? loaded.terminalAllowlist.hosts.map((h) => String(h).trim()).filter(Boolean) : []
      }
    : { ports: [], hosts: [] };
  const s = {
    version: 1,
    mode: loaded.mode === 'on' ? 'on' : 'off',
    blocklist: Array.isArray(loaded.blocklist) ? loaded.blocklist.map(normalizeDomain).filter(Boolean) : [],
    appBlocklist: normalizeAppBlocklist(loaded.appBlocklist),
    failClosed: loaded.failClosed === true,
    terminalBlock: loaded.terminalBlock !== false,
    terminalAllowlist: allowlist,
    dohBlock: loaded.dohBlock !== false,
    dohHosts: Array.isArray(loaded.dohHosts) ? Array.from(new Set(loaded.dohHosts.map((h) => String(h).trim()).filter(Boolean))) : [],
    proxyBlock: loaded.proxyBlock !== false,
    autofillBlock: loaded.autofillBlock !== false,
    lock: { state: 'locked', unlockExpiry: 0 }
  };
  if (loaded.lock && loaded.lock.unlockExpiry && loaded.lock.unlockExpiry > Date.now()) {
    // A cooldown was in flight when the app closed; treat it as complete (the
    // store still says mode 'on', which is the safe state).
    s.lock = { state: 'locked', unlockExpiry: 0 };
  }
  return s;
}

// Tighten the on-disk storage files to owner read/write only. Returns a list of
// files that were loosened and had to be fixed.
function enforceStoragePermissions() {
  const fixed = [];
  for (const f of [STORE_FILE, KEY_FILE, CONFIG_FILE, CONFIG_FILE + '.sig', SETTINGS_FILE, SETTINGS_SIG_FILE, BRIDGE_TOKEN_FILE]) {
    if (fs.existsSync(f) && store.ensurePermissions(f)) fixed.push(path.basename(f));
  }
  for (const name of fixed) logActivity(activity.makeEntry('daemon', 'permissions_fixed', null, name + ' permissions tightened to 0600'));
}

// Persist canonical state: encrypted store (authoritative) + signed plaintext
// snapshot (consumed by the root daemon, verified on every read). Terminal/OS
// blocking and DoH/DoT endpoint blocking default ON; settings.json may disable
// them or add an allowlist / override endpoints, and the effective values are
// what the daemon sees.
function persist() {
  const terminalBlock = effectiveTerminalBlock();
  const terminalAllowlist = effectiveTerminalAllowlist();
  const dohBlock = effectiveDohBlock();
  const dohHosts = effectiveDohHosts();
  const proxyBlock = effectiveProxyBlock();
  const autofillBlock = effectiveAutofillBlock();
  store.saveSecureStore(USER_DATA, storeIntegrityKey, {
    version: 1,
    mode: blockState.mode,
    blocklist: blockState.blocklist,
    appBlocklist: blockState.appBlocklist,
    failClosed: blockState.failClosed,
    terminalBlock,
    terminalAllowlist,
    dohBlock,
    dohHosts,
    proxyBlock,
    autofillBlock,
    lock: blockState.lock
  });
  config.writeSignedConfig(CONFIG_FILE, {
    version: 1,
    mode: blockState.mode,
    blocklist: blockState.blocklist,
    appBlocklist: blockState.appBlocklist,
    failClosed: blockState.failClosed,
    terminalBlock,
    terminalAllowlist,
    dohBlock,
    dohHosts,
    proxyBlock,
    autofillBlock
  }, storeIntegrityKey);
}

// Make sure the user-owned data dir and both shared files exist up front.
// The dir must be owned by the user (not root) so the app can keep writing to
// it even if the privileged daemon is installed later.
function ensureFiles() {
  fs.mkdirSync(USER_DATA, { recursive: true });
  storeIntegrityKey = store.loadOrCreateKey(USER_DATA);
  if (!fs.existsSync(CONFIG_FILE)) config.writeConfig(USER_DATA, config.DEFAULT_CONFIG);
  try { fs.writeFileSync(ACTIVITY_FILE, '', { flag: 'a' }); } catch {}

  // Verify settings.json's signature up front so the tampered flag and its
  // activity entry exist before the first persist() bakes effective values
  // into the signed config.
  readSettings();

  let loaded = null;
  let loadError = null;
  try {
    loaded = store.loadSecureStore(USER_DATA, storeIntegrityKey);
  } catch (err) {
    loadError = err;
  }

  if (loaded) {
    blockState = normalizeLoadedState(loaded);
  } else if (store.storeFileExists(USER_DATA)) {
    // The store exists but refuses to decrypt: tampered or corrupt. Fail closed
    // — we can't trust whatever was in there. Preserve the corrupt file for
    // inspection, then start deny-all (mode ON + failClosed).
    try { fs.copyFileSync(STORE_FILE, STORE_FILE + '.corrupt'); } catch { /* best-effort */ }
    blockState = { version: 1, mode: 'on', blocklist: [], appBlocklist: [], failClosed: true, terminalBlock: true, terminalAllowlist: { ports: [], hosts: [] }, dohBlock: true, dohHosts: [], proxyBlock: true, autofillBlock: true, lock: { state: 'locked', unlockExpiry: 0 } };
    degraded = true;
    logActivity(activity.makeEntry('daemon', 'integrity_failed', null, 'encrypted store could not be verified: ' + (loadError && loadError.message)));
    notifyDegraded('auren could not verify its encrypted block list and has failed closed. Nothing will be allowed through until you review it.');
  }

  enforceStoragePermissions();
  persist(); // writes the encrypted store + signed config for the daemon
  return getState();
}

function notifyDegraded(body) {
  if (Notification.isSupported()) {
    try { new Notification({ title: 'Auren: protection degraded', body }).show(); } catch { /* ignore */ }
  }
}

/* ------------------------------- state ------------------------------- */

function getState() {
  return {
    platform: process.platform,
    mode: blockState.mode,
    blocklist: blockState.blocklist.slice(),
    appBlocklist: blockState.appBlocklist.slice(),
    activity: activity.readActivity(ACTIVITY_FILE, 100).reverse().map((e) => Object.assign({}, e, { text: activity.toPlainText(e) })),
    modeCooldownUntil: offCooldownUntil,
    enforcement: dnsController.isEnforcing(),
    daemonInstalled: dnsController.isDaemonInstalled(),
    onboardingDone: !!(readSettings().onboardingDone),
    degraded: degraded || blockState.failClosed,
    terminalBlock: effectiveTerminalBlock(),
    dohBlock: effectiveDohBlock(),
    dohHosts: effectiveDohHosts(),
    proxyBlock: effectiveProxyBlock(),
    proxyActive: !!(lastHeartbeat && lastHeartbeat.proxyActive),
    proxyPort: lastHeartbeat && lastHeartbeat.proxyActive ? (lastHeartbeat.proxyPort || 42792) : null,
    dnsConflict: lastHeartbeat && lastHeartbeat.dnsConflict ? lastHeartbeat.dnsConflict : null,
    autofillBlock: effectiveAutofillBlock(),
    vmsDetected: virt.runningVirtualization(),
    settingsTampered: settingsTampered,
    keystrokeShield: shield.keystrokeShieldActive(blockState),
    agentBridge: bridgeInfo,
    autoProtect: autoProtectState(),
    lock: blockState.lock
  };
}

// Effective auto-protect settings plus what a live scan is seeing right now,
// so the UI can show the toggle state and the "auto-engaged" banner.
function autoProtectState() {
  const ap = autoprotect.normalizeAutoProtect(readSettings().autoProtect);
  return {
    enabled: ap.enabled,
    mode: ap.mode,
    engagedBy: autoProtectEngagedBy.slice(),
    sessions: lastAutoProtectSessions.map((s) => ({ pid: s.pid, tool: s.tool }))
  };
}

// Log VM/container detections while Protection is ON (only on state changes,
// so the log doesn't fill with repeats). The detection itself is polled inside
// getState (virt.js caches it for 10 s), so this just compares snapshots.
let lastVmsJson = null;
function checkVirtualization() {
  const vms = virt.runningVirtualization();
  const json = JSON.stringify(vms);
  if (json === lastVmsJson) return;
  lastVmsJson = json;
  if (blockState.mode !== 'on') return;
  if (vms.length > 0) {
    logActivity(activity.makeEntry('daemon', 'vm_detected', null, vms.join(', ')));
  } else {
    logActivity(activity.makeEntry('daemon', 'vm_cleared', null));
  }
}

// Hide the human's keystrokes while Protection is on (part of Protection Mode).
//   - Window content protection: Auren's window can't be screen-captured by an
//     AI agent, so nothing typed in Auren ever appears in a recording.
//   - Secure Event Input (macOS only): while Auren's window has keyboard focus,
//     keyboard-intercept processes (accessibility / event-tap keyloggers) can't
//     read the user's keys. Disabled the moment focus leaves so other apps'
//     keyboard-observing features keep working (Apple's "use it fairly" rule).
function applyKeystrokeShield() {
  const active = shield.keystrokeShieldActive(blockState);
  if (!mainWindow || mainWindow.isDestroyed()) {
    if (shieldSecureInput) {
      shieldSecureInput = false;
      try { if (typeof app.setSecureKeyboardEntryEnabled === 'function') app.setSecureKeyboardEntryEnabled(false); } catch { /* best-effort */ }
    }
    return;
  }
  if (shieldContentProtection !== active) {
    shieldContentProtection = active;
    try { mainWindow.setContentProtection(active); } catch { /* best-effort */ }
  }
  const wantSecure = shield.secureInputWanted(blockState, mainWindow.isFocused());
  if (wantSecure !== shieldSecureInput) {
    shieldSecureInput = wantSecure;
    try { if (typeof app.setSecureKeyboardEntryEnabled === 'function') app.setSecureKeyboardEntryEnabled(wantSecure); } catch { /* best-effort */ }
  }
}

function pushState() {
  checkVirtualization();
  applyKeystrokeShield();
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const s = getState();
  const key = JSON.stringify(s);
  if (key === lastSent) return;
  lastSent = key;
  mainWindow.webContents.send('state', s);
}

function startPolling() {
  pushState();
  setInterval(pushState, POLL_MS);
}

/* --------------------------- graceful quit --------------------------- */

// Lift protection when the app quits: write a signed "mode: off" config so the
// root daemon restores system DNS and stops blocking within its next poll
// (~1 s). The block list itself is preserved in the store, so a later session
// starts with protection OFF but the same list ready to re-enable. This is
// best-effort — a crash or force-quit skips it, and failures must never block
// the quit, so nothing here throws out of the handler.
function liftProtectionOnQuit() {
  try {
    if (offCooldownTimer) { clearTimeout(offCooldownTimer); offCooldownTimer = null; }
    offCooldownUntil = 0;
    if (blockState.mode === 'on' || blockState.failClosed) {
      blockState.mode = 'off';
      blockState.failClosed = false;
      blockState.lock = { state: 'locked', unlockExpiry: 0 };
      autoProtectLastJson = '';
      autoProtectEngagedBy = [];
      persist();
      logActivity(activity.makeEntry('toggle', 'off', null, 'app quit — protection lifted, DNS restored'));
    }
  } catch (err) {
    try { logActivity(activity.makeEntry('daemon', 'error', null, 'could not lift protection on quit: ' + err.message)); } catch { /* ignore */ }
  }
}

/* ------------------------------ watchdog ----------------------------- */

// The daemon writes a heartbeat every 2s. If we miss enough of them, or the
// daemon reports its own integrity as bad, enforcement is assumed compromised
// and the app degrades (fail-closed surfaces refuse; user gets a notification).
let lastHeartbeat = null;
function checkHeartbeat() {
  const expected = blockState.mode === 'on' || blockState.failClosed;
  let hb = null;
  try { hb = JSON.parse(fs.readFileSync(HEARTBEAT_FILE, 'utf8')); } catch { /* no heartbeat yet */ }
  lastHeartbeat = hb;
  const fresh = !!hb && typeof hb.ts === 'number' && (Date.now() - hb.ts) < HEARTBEAT_STALE_MS && hb.integrityOk !== false;
  // A port-53 conflict means the daemon is alive but its DNS resolver never
  // bound, so domain blocking silently does nothing — that's degraded even
  // though the heartbeat itself is fresh.
  const conflict = expected && !!(hb && hb.dnsConflict && hb.dnsConflict.port === 53);
  const next = expected ? (!fresh || conflict) : false;
  const was = degraded;
  const inGrace = daemonBusy || (Date.now() - STARTED_AT) < WATCHDOG_GRACE_MS;
  // During the grace window a missing heartbeat is expected (install in flight
  // or daemon still booting) — don't enter degraded, but DO exit it if the
  // daemon recovers. Once the window passes, a stale heartbeat degrades.
  degraded = next ? (inGrace ? was : true) : false;
  if (next && !was && !inGrace) {
    if (conflict && hb && hb.dnsConflict) {
      const who = hb.dnsConflict.name ? hb.dnsConflict.name + ' (pid ' + hb.dnsConflict.pid + ')' : 'another process';
      logActivity(activity.makeEntry('daemon', 'enforcement_degraded', null, 'port 53 conflict with ' + who));
      notifyDegraded('Auren\u2019s DNS resolver could not start: ' + who + ' is already using port 53. Domain blocking is off until that process is stopped and protection is toggled; nothing gated by Auren will be allowed through in the meantime.');
    } else {
      logActivity(activity.makeEntry('daemon', 'enforcement_degraded'));
      notifyDegraded('Auren\u2019s background service stopped responding. Protection is degraded until it recovers; nothing gated by Auren will be allowed through in the meantime.');
    }
  } else if (!next && was) {
    logActivity(activity.makeEntry('daemon', 'enforcement_restored'));
  }
  if (next !== was) pushState();
  maybeRecoverDaemon();
}

// A silent service death (launchd teardown race, crashed process) leaves the
// label "installed" but nothing running, so the normal mode:set reinstall never
// fires again. When the watchdog is actually degraded with protection expected,
// try ONE automatic reinstall (bounded — no prompt loops). The OS-native prompt
// is the same one the user already accepted when they turned protection on.
let daemonRecoveryAttempted = false;
function maybeRecoverDaemon() {
  if (daemonRecoveryAttempted || !degraded) return;
  if (blockState.mode !== 'on' && !blockState.failClosed) return;
  if (daemonBusy || (Date.now() - STARTED_AT) < WATCHDOG_GRACE_MS) return;
  daemonRecoveryAttempted = true;
  logActivity(activity.makeEntry('daemon', 'recovery_attempted', null, 'service stopped responding; reinstalling the background service'));
  installDaemon().then((res) => {
    if (res.ok) {
      logActivity(activity.makeEntry('daemon', 'recovered', null, 'background service restarted'));
    } else {
      logActivity(activity.makeEntry('daemon', 'recovery_failed', null, 'automatic reinstall failed: ' + res.error));
    }
  });
}

function startWatchdog() {
  checkHeartbeat();
  setInterval(checkHeartbeat, WATCHDOG_MS);
}

/* ------------------------------ auto-protect --------------------------- */

// Engage protection (the same path as flipping the toggle ON). Extracted from
// the mode:set handler so auto-protect shares exactly one implementation.
// Returns { ok, cancelled, error, mode } — same shape as the IPC response.
async function engageProtection() {
  clearOffCooldown();
  if (!dnsController.isDaemonInstalled() || !dnsController.isDaemonCurrent()) {
    daemonBusy = true;
    try {
      const res = await installDaemon();
      if (!res.ok) {
        logActivity(activity.makeEntry('toggle', 'on_failed', null, 'background service setup declined'));
        pushState();
        return { ok: false, cancelled: !!res.cancelled, error: 'setup', mode: blockState.mode };
      }
    } finally {
      daemonBusy = false;
    }
  }
  blockState.mode = 'on';
  persist();
  logActivity(activity.makeEntry('toggle', 'on'));
  pushState();
  return { ok: true, mode: 'on' };
}

// Auto-protect engaged protection because an agent session was detected. Logs
// the trigger, remembers what engaged it (for the UI banner), and notifies.
async function engageAutoProtect(sessions) {
  const tools = autoprotect.uniqueToolNames(sessions);
  const res = await engageProtection();
  if (!res.ok) {
    logActivity(activity.makeEntry('toggle', 'auto_engage_failed', null, 'auto-protect could not engage (' + tools.join(', ') + ')'));
    return;
  }
  autoProtectEngagedBy = tools;
  logActivity(activity.makeEntry('toggle', 'auto_engaged', null, tools.join(', ')));
  if (Notification.isSupported()) {
    try {
      new Notification({ title: 'auren', body: 'AI agent activity detected (' + tools.join(', ') + ') \u2014 protection turned ON automatically.' }).show();
    } catch { /* ignore */ }
  }
  pushState();
}

// Poll: is a live AI-agent session running while protection is off?
//   - no change since the last scan -> nothing (avoids log/notification spam);
//   - a session appeared while OFF -> engage (or prompt, per settings);
//   - a session disappeared -> NOTHING: auto-protect never turns protection off.
async function checkAutoProtect() {
  if (autoProtectBusy) return;
  autoProtectBusy = true;
  try {
    const ap = autoprotect.normalizeAutoProtect(readSettings().autoProtect);
    if (!ap.enabled) {
      autoProtectLastJson = '';
      lastAutoProtectSessions = [];
      return;
    }
    const list = procs.list();
    if (!list) return;
    const tools = agentdetect.normalizeTools(readSettings().autoProtect && readSettings().autoProtect.tools);
    const sessions = agentdetect.detectSessions(list, tools);
    const json = JSON.stringify(sessions);
    lastAutoProtectSessions = sessions;
    if (json === autoProtectLastJson) return;
    autoProtectLastJson = json;
    if (sessions.length === 0) return;
    if (blockState.mode === 'on' || blockState.failClosed) return;

    if (ap.mode === 'prompt') {
      const now = Date.now();
      if (now - autoProtectPromptAt < 30000) return;
      autoProtectPromptAt = now;
      logActivity(activity.makeEntry('daemon', 'auto_protect_prompt', null, 'detected agent session: ' + autoprotect.uniqueToolNames(sessions).join(', ')));
      pushState();
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('autoprotect:prompt', autoprotect.uniqueToolNames(sessions));
      }
      return;
    }

    await engageAutoProtect(sessions);
  } finally {
    autoProtectBusy = false;
  }
}

function startAutoProtect() {
  checkAutoProtect();
  setInterval(checkAutoProtect, AUTOPROTECT_POLL_MS);
}

/* ------------------------------- window ------------------------------ */

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1160,
    height: 840,
    minWidth: 760,
    minHeight: 640,
    title: 'auren',
    icon: ICON_PATH,
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#0a0d12',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.on('focus', applyKeystrokeShield);
  mainWindow.on('blur', applyKeystrokeShield);
  mainWindow.on('closed', () => { mainWindow = null; applyKeystrokeShield(); });
  applyKeystrokeShield();
}

/* -------------------------------- IPC -------------------------------- */

ipcMain.handle('state:get', () => getState());
ipcMain.handle('onboarding:done', () => { writeSettings({ onboardingDone: true }); pushState(); return true; });

// The single writable path for the block list. The renderer never touches the
// file; it sends the domain over IPC and this process persists + re-signs.
ipcMain.handle('blocklist:add', (_e, input) => {
  const v = validateBlockDomain(input);
  if (!v.ok) return { ok: false, error: v.error, blocklist: null };
  if (!blockState.blocklist.includes(v.domain)) blockState.blocklist.push(v.domain);
  persist();
  pushState();
  return { ok: true, blocklist: blockState.blocklist.slice() };
});

ipcMain.handle('blocklist:remove', (_e, domain) => {
  const d = normalizeDomain(domain);
  blockState.blocklist = blockState.blocklist.filter((x) => x !== d);
  persist();
  pushState();
  return { ok: true, blocklist: blockState.blocklist.slice() };
});

// App-blocking surface, mirroring the domain list. Search resolves a query to
// installed apps (main process only — mdfind + plutil need a user session);
// add/remove persist through the same encrypted store + signed config the
// daemon reads, so a blocked app is enforced the moment the daemon polls.
ipcMain.handle('appblock:search', (_e, query) => {
  const own = app.getPath('exe');
  return appResolver.searchApps(query, { excludePaths: own ? [path.resolve(own)] : [] });
});

ipcMain.handle('appblock:add', (_e, input) => {
  const v = validateBlockApp(input);
  if (!v.ok) return { ok: false, error: v.error, appBlocklist: null };
  const entry = v.entry;
  // Never offer to block Auren itself (the daemon re-enforces this at kill
  // time via its own interpreter path; this is defense-in-depth at the UI).
  const own = path.resolve(app.getPath('exe'));
  if (entry.path && path.resolve(entry.path) === own) {
    return { ok: false, error: 'Auren can\u2019t block itself.', appBlocklist: null };
  }
  if (!blockState.appBlocklist.some((a) => a.id === entry.id)) {
    blockState.appBlocklist.push(entry);
    persist();
    pushState();
  }
  return { ok: true, appBlocklist: blockState.appBlocklist.slice() };
});

ipcMain.handle('appblock:remove', (_e, id) => {
  const key = String(id || '').trim();
  blockState.appBlocklist = blockState.appBlocklist.filter((a) => a.id !== key);
  persist();
  pushState();
  return { ok: true, appBlocklist: blockState.appBlocklist.slice() };
});

// Read-only query for any component that needs to know whether a site is
// blocked: the renderer, the loopback agent bridge, a future browser-bridge or
// native-messaging host, etc. While degraded, everything is reported as
// blocked (fail-closed).
ipcMain.handle('guardrail:is-blocked', (_e, domain) => agentgate.isBlocked(domain, agentGateCtx()));

// Policy-gated checkpoint for outgoing agent actions (form submissions etc.).
// classifier -> policy -> native auth, fully inside the main process. The
// decision logic lives in core/agentgate.js and is shared with the HTTP bridge.
ipcMain.handle('agent:inspect-action', async (_e, payload) => agentgate.inspectAction(payload, agentGateCtx()));

// Policy-gated checkpoint for OS/terminal-level agent commands (ssh, ping,
// curl, nc, ...). Mirrors agent:inspect-action but ties enforcement to
// Protection Mode: when protection is OFF the gate does not stand in the way.
// While degraded (or the encrypted store is unverified) it refuses — fail-
// closed. The loopback agent bridge routes commands through this same gate;
// the pf firewall in the root daemon covers everything else.
ipcMain.handle('agent:inspect-command', async (_e, payload) => {
  const cmd = (payload && payload.command != null) ? payload.command : payload;
  return agentgate.inspectCommand(cmd, agentGateCtx());
});

ipcMain.handle('mode:set', async (_e, mode) => {
  const next = mode === 'on' ? 'on' : 'off';

  if (next === 'on') {
    // Turning protection ON is instant and un-gated. It also cancels any
    // pending unlock cooldown, so protection can't flip off a moment later.
    return engageProtection();
  }

  // Turning protection OFF is gated by an OS-native biometric / passcode
  // check. Only a pass/fail result ever comes back from that call.
  const auth = await requireAuthentication('Turn off auren protection');
  if (!auth.ok) {
    logActivity(activity.makeEntry('toggle', auth.cancelled ? 'off_cancelled' : 'off_failed'));
    pushState();
    return { ok: false, cancelled: !!auth.cancelled, error: 'auth', mode: blockState.mode };
  }

  // Verification passed. Protection does NOT flip off instantly: the block
  // list stays live through a 10s cooldown, then protection turns off. Turning
  // it back ON in that window cancels the pending unlock.
  clearOffCooldown();
  offCooldownUntil = Date.now() + OFF_COOLDOWN_MS;
  blockState.lock = { state: 'unlocking', unlockExpiry: offCooldownUntil };
  persist();
  logActivity(activity.makeEntry('toggle', 'off_pending', null, 'verified — 10s cooldown before sites unlock'));
  offCooldownTimer = setTimeout(() => {
    offCooldownTimer = null;
    offCooldownUntil = 0;
    blockState.mode = 'off';
    blockState.lock = { state: 'locked', unlockExpiry: 0 };
    // A manual turn-off is user intent: forget any auto-protect trigger so a
    // still-running agent session doesn't immediately re-engage protection.
    autoProtectLastJson = '';
    autoProtectEngagedBy = [];
    persist();
    logActivity(activity.makeEntry('toggle', 'off'));
    pushState();
  }, OFF_COOLDOWN_MS);
  pushState();
  return { ok: true, mode: blockState.mode, cooldownUntil: offCooldownUntil };
});

// Auto-protect surfaces: confirm a "prompt" engagement from the UI, and
// enable/disable the feature (both write through settings.json).
ipcMain.handle('autoprotect:confirm', async () => {
  await engageAutoProtect(lastAutoProtectSessions);
  return { ok: true };
});

ipcMain.handle('settings:set-auto-protect', (_e, patch) => {
  const ap = autoprotect.normalizeAutoProtect(readSettings().autoProtect);
  const next = {
    enabled: patch && patch.enabled != null ? !!patch.enabled : ap.enabled,
    mode: patch && patch.mode ? patch.mode : ap.mode
  };
  writeSettings({ autoProtect: next });
  pushState();
  return { ok: true, autoProtect: next };
});

/* ------------------------------- startup ----------------------------- */

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) { if (mainWindow.isMinimized()) mainWindow.restore(); mainWindow.focus(); }
  });

  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { role: 'appMenu' },
    { role: 'fileMenu' },
    { role: 'editMenu' },
    { role: 'windowMenu' }
  ]));

  app.whenReady().then(() => {
    ensureFiles();
    createWindow();
    startPolling();
    startWatchdog();
    startAutoProtect();
    startAgentBridge();
    refreshDaemonIfStale();
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });

  // Graceful quit (Cmd+Q / menu quit / AppleScript quit). While Protection is
  // ON (or the app is fail-closed), quitting lifts protection, so it is gated
  // by the same OS-native biometric/passcode check as turning protection off —
  // an agent that simply quits the app no longer gets an unauthenticated off.
  // A cancelled/failed check cancels the quit and protection stays ON.
  // force-quit (kill, force-quit menu, crash) bypasses this handler but ALSO
  // skips liftProtectionOnQuit below, so protection stays ON there too — only
  // an authenticated graceful quit can hand the machine back.
  app.on('before-quit', (event) => {
    // Never leave Secure Event Input enabled behind this app.
    if (shieldSecureInput) {
      shieldSecureInput = false;
      try { if (typeof app.setSecureKeyboardEntryEnabled === 'function') app.setSecureKeyboardEntryEnabled(false); } catch { /* best-effort */ }
    }
    stopAgentBridge();
    if (forceQuit || !quitRequiresAuth(blockState)) {
      liftProtectionOnQuit();
      return;
    }
    event.preventDefault();
    requireAuthentication('Quit auren and turn protection off?').then((r) => {
      if (r.ok) {
        forceQuit = true;
        app.quit();
      } else {
        logActivity(activity.makeEntry('toggle', 'quit_cancelled', null, 'quit blocked by protection gate'));
        if (Notification.isSupported()) {
          try { new Notification({ title: 'auren', body: 'Quit cancelled \u2014 protection stays ON.' }).show(); } catch { /* ignore */ }
        }
        pushState();
      }
    });
  });
}
