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
 *     IPC (state:get, guardrail:is-blocked, agent:inspect-action, mode:set).
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
 * which runs independently of this process — closing Auren does not stop
 * blocking, and killing the daemon leaves system DNS pointed at a dead resolver
 * (deny-all), not open access.
 */

'use strict';
const path = require('path');
const os = require('os');
const fs = require('fs');
const { app, BrowserWindow, ipcMain, Menu, nativeTheme, nativeImage, Notification } = require('electron');

const config = require('./core/config');
const activity = require('./core/activity');
const store = require('./core/store');
const sensitive = require('./core/sensitive');
const policy = require('./core/policy');
const { normalizeDomain, domainMatches, validateBlockDomain } = require('./core/domains');
const dnsController = require('./platform/dns-controller');
const { requireAuthentication, requireNativeAuth } = require('./platform/biometrics');

const USER_DATA = path.join(os.homedir(), 'Library', 'Application Support', 'Auren');
const CONFIG_FILE = path.join(USER_DATA, 'config.json');
const ACTIVITY_FILE = path.join(USER_DATA, 'activity.jsonl');
const SETTINGS_FILE = path.join(USER_DATA, 'settings.json');
const STATE_FILE = '/Library/Application Support/Auren/state.json';
const KEY_FILE = path.join(USER_DATA, store.KEY_FILE);
const STORE_FILE = path.join(USER_DATA, store.STORE_FILE);
const HEARTBEAT_FILE = '/Library/Application Support/Auren/heartbeat.json';

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

/* --------------------------- fail-closed state --------------------------- */

// After a successful unlock (Touch ID / passcode), the block list stays active
// for this long before protection actually turns off. Gives a human a moment to
// confirm the unlock; an agent can't get at the sites instantly.
const OFF_COOLDOWN_MS = 10 * 1000;
let offCooldownTimer = null;
let offCooldownUntil = 0;

// The canonical, main-process-owned block state.
let blockState = { version: 1, mode: 'off', blocklist: [], failClosed: false, lock: { state: 'locked', unlockExpiry: 0 } };
let storeIntegrityKey = null;

// True when enforcement can't be trusted (daemon silent, tampered/corrupt
// store, unverified config). Every gated surface refuses while this is set.
let degraded = false;

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

function readSettings() {
  try { return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch { return {}; }
}

function writeSettings(patch) {
  const s = Object.assign({}, readSettings(), patch);
  fs.mkdirSync(USER_DATA, { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(s, null, 2) + '\n');
  return s;
}

function policyRulesFromSettings() {
  const p = readSettings().sensitivePolicy;
  return (p && typeof p === 'object') ? p : undefined;
}

function logActivity(entry) {
  activity.appendActivity(ACTIVITY_FILE, entry);
}

/* --------------------------- storage & persist --------------------------- */

function normalizeLoadedState(loaded) {
  const s = {
    version: 1,
    mode: loaded.mode === 'on' ? 'on' : 'off',
    blocklist: Array.isArray(loaded.blocklist) ? loaded.blocklist.map(normalizeDomain).filter(Boolean) : [],
    failClosed: loaded.failClosed === true,
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
  for (const f of [STORE_FILE, KEY_FILE, CONFIG_FILE, CONFIG_FILE + '.sig']) {
    if (fs.existsSync(f) && store.ensurePermissions(f)) fixed.push(path.basename(f));
  }
  for (const name of fixed) logActivity(activity.makeEntry('daemon', 'permissions_fixed', null, name + ' permissions tightened to 0600'));
}

// Persist canonical state: encrypted store (authoritative) + signed plaintext
// snapshot (consumed by the root daemon, verified on every read).
function persist() {
  store.saveSecureStore(USER_DATA, storeIntegrityKey, {
    version: 1,
    mode: blockState.mode,
    blocklist: blockState.blocklist,
    failClosed: blockState.failClosed,
    lock: blockState.lock
  });
  config.writeSignedConfig(CONFIG_FILE, {
    version: 1,
    mode: blockState.mode,
    blocklist: blockState.blocklist,
    failClosed: blockState.failClosed
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
    blockState = { version: 1, mode: 'on', blocklist: [], failClosed: true, lock: { state: 'locked', unlockExpiry: 0 } };
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
    activity: activity.readActivity(ACTIVITY_FILE, 100).reverse().map((e) => Object.assign({}, e, { text: activity.toPlainText(e) })),
    modeCooldownUntil: offCooldownUntil,
    enforcement: dnsController.isEnforcing(),
    daemonInstalled: dnsController.isDaemonInstalled(),
    onboardingDone: !!(readSettings().onboardingDone),
    degraded: degraded || blockState.failClosed,
    lock: blockState.lock
  };
}

function pushState() {
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

/* ------------------------------ watchdog ----------------------------- */

// The daemon writes a heartbeat every 2s. If we miss enough of them, or the
// daemon reports its own integrity as bad, enforcement is assumed compromised
// and the app degrades (fail-closed surfaces refuse; user gets a notification).
function checkHeartbeat() {
  const expected = blockState.mode === 'on' || blockState.failClosed;
  let hb = null;
  try { hb = JSON.parse(fs.readFileSync(HEARTBEAT_FILE, 'utf8')); } catch { /* no heartbeat yet */ }
  const fresh = !!hb && typeof hb.ts === 'number' && (Date.now() - hb.ts) < HEARTBEAT_STALE_MS && hb.integrityOk !== false;
  const next = expected ? !fresh : false;
  const was = degraded;
  const inGrace = daemonBusy || (Date.now() - STARTED_AT) < WATCHDOG_GRACE_MS;
  // During the grace window a missing heartbeat is expected (install in flight
  // or daemon still booting) — don't enter degraded, but DO exit it if the
  // daemon recovers. Once the window passes, a stale heartbeat degrades.
  degraded = next ? (inGrace ? was : true) : false;
  if (next && !was && !inGrace) {
    logActivity(activity.makeEntry('daemon', 'enforcement_degraded'));
    notifyDegraded('Auren\u2019s background service stopped responding. Protection is degraded until it recovers; nothing gated by Auren will be allowed through in the meantime.');
  } else if (!next && was) {
    logActivity(activity.makeEntry('daemon', 'enforcement_restored'));
  }
  if (next !== was) pushState();
}

function startWatchdog() {
  checkHeartbeat();
  setInterval(checkHeartbeat, WATCHDOG_MS);
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
  mainWindow.on('closed', () => { mainWindow = null; });
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

// Read-only query for any component that needs to know whether a site is
// blocked: the renderer, a future browser-bridge, native-messaging host, etc.
// While degraded, everything is reported as blocked (fail-closed).
ipcMain.handle('guardrail:is-blocked', (_e, domain) => {
  if (degraded || blockState.failClosed) return true;
  if (blockState.mode !== 'on') return false;
  const d = normalizeDomain(domain);
  return blockState.blocklist.some((x) => domainMatches(d, x));
});

// Policy-gated checkpoint for outgoing agent actions (form submissions etc.).
// classifier -> policy -> native auth, fully inside the main process.
ipcMain.handle('agent:inspect-action', async (_e, payload) => {
  const signal = sensitive.classifySensitivePayload(payload);
  // Fail-closed while degraded OR while the encrypted store is unverified.
  const decision = policy.decidePolicy(signal, { degraded: degraded || blockState.failClosed, rules: policyRulesFromSettings() });

  let allowed = false;
  let outcome;
  if (decision.action === 'allow') {
    allowed = true;
    outcome = 'allowed';
  } else if (decision.action === 'log') {
    allowed = true;
    outcome = 'logged';
  } else if (decision.action === 'block') {
    outcome = 'blocked';
  } else {
    // require_auth
    const typesLabel = signal.types.join(', ') || 'sensitive data';
    const reason = 'Approve sending ' + typesLabel + (payload && payload.url ? ' to ' + payload.url : '');
    const ok = await requireNativeAuth(reason);
    if (ok) { allowed = true; outcome = 'allowed'; }
    else outcome = 'blocked';
  }

  const note = 'types=' + (signal.types.join(',') || 'none');
  logActivity(activity.makeEntry('agent', outcome, null, note));
  pushState();
  return { allowed, action: decision.action, types: signal.types, reason: decision.reason };
});

ipcMain.handle('mode:set', async (_e, mode) => {
  const next = mode === 'on' ? 'on' : 'off';

  if (next === 'on') {
    // Turning protection ON is instant and un-gated. It also cancels any
    // pending unlock cooldown, so protection can't flip off a moment later.
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
    persist();
    logActivity(activity.makeEntry('toggle', 'off'));
    pushState();
  }, OFF_COOLDOWN_MS);
  pushState();
  return { ok: true, mode: blockState.mode, cooldownUntil: offCooldownUntil };
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
    refreshDaemonIfStale();
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
