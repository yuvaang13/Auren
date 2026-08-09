/* Auren — main.js
 *
 * Electron main process. Owns the single window, the IPC surface, and the
 * small bit of glue between the UI and the core/platform layers. The actual
 * DNS enforcement lives in the root daemon (see src/dns/daemon.js), which
 * runs independently of this process — closing Auren does not stop blocking.
 */

'use strict';
const path = require('path');
const os = require('os');
const fs = require('fs');
const { app, BrowserWindow, ipcMain, Menu, nativeTheme } = require('electron');

const config = require('./core/config');
const activity = require('./core/activity');
const dnsController = require('./platform/dns-controller');
const { requireAuthentication } = require('./platform/biometrics');

const USER_DATA = path.join(os.homedir(), 'Library', 'Application Support', 'Auren');
const CONFIG_FILE = path.join(USER_DATA, 'config.json');
const ACTIVITY_FILE = path.join(USER_DATA, 'activity.jsonl');
const SETTINGS_FILE = path.join(USER_DATA, 'settings.json');
const STATE_FILE = '/Library/Application Support/Auren/state.json';

app.setName('Auren');
app.setPath('userData', USER_DATA);

// Auren ships a dark UI; keep native chrome and dialogs consistent with it.
nativeTheme.themeSource = 'dark';

let mainWindow = null;
let lastSent = '';
const POLL_MS = 1000;

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

// Make sure the user-owned data dir and both shared files exist up front.
// The dir must be owned by the user (not root) so the app can keep writing to
// it even if the privileged daemon is installed later.
function ensureFiles() {
  fs.mkdirSync(USER_DATA, { recursive: true });
  if (!fs.existsSync(CONFIG_FILE)) config.writeConfig(USER_DATA, config.DEFAULT_CONFIG);
  try { fs.writeFileSync(ACTIVITY_FILE, '', { flag: 'a' }); } catch {}
  return getState();
}

/* ------------------------------- state ------------------------------- */

function getState() {
  const cfg = config.readConfig(USER_DATA);
  return {
    platform: process.platform,
    mode: cfg.mode,
    blocklist: cfg.blocklist,
    activity: activity.readActivity(ACTIVITY_FILE, 100).reverse().map((e) => Object.assign({}, e, { text: activity.toPlainText(e) })),
    enforcement: dnsController.isEnforcing(),
    daemonInstalled: dnsController.isDaemonInstalled(),
    onboardingDone: !!(readSettings().onboardingDone)
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

/* ------------------------------- window ------------------------------ */

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 720,
    height: 760,
    minWidth: 560,
    minHeight: 620,
    title: 'Auren',
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

ipcMain.handle('blocklist:add', (_e, input) => {
  const r = config.addDomain(USER_DATA, input);
  pushState();
  return r;
});

ipcMain.handle('blocklist:remove', (_e, domain) => {
  const r = config.removeDomain(USER_DATA, domain);
  pushState();
  return r;
});

ipcMain.handle('mode:set', async (_e, mode) => {
  const next = mode === 'on' ? 'on' : 'off';

  if (next === 'on') {
    // Turning protection ON is instant and un-gated.
    if (!dnsController.isDaemonInstalled()) {
      const res = await dnsController.installDaemon({
        nodeBin: dnsController.findNodeBin(app.getPath('exe')),
        configPath: CONFIG_FILE,
        activityPath: ACTIVITY_FILE,
        statePath: STATE_FILE
      });
      if (!res.ok) {
        activity.appendActivity(ACTIVITY_FILE, activity.makeEntry('toggle', 'on_failed', null, 'background service setup declined'));
        pushState();
        return { ok: false, cancelled: !!res.cancelled, error: 'setup', mode: config.readConfig(USER_DATA).mode };
      }
    }
    config.setMode(USER_DATA, 'on');
    activity.appendActivity(ACTIVITY_FILE, activity.makeEntry('toggle', 'on'));
    pushState();
    return { ok: true, mode: 'on' };
  }

  // Turning protection OFF is gated by an OS-native biometric / passcode
  // check. Only a pass/fail result ever comes back from that call.
  const auth = await requireAuthentication('Turn off Auren protection');
  if (!auth.ok) {
    activity.appendActivity(ACTIVITY_FILE, activity.makeEntry('toggle', auth.cancelled ? 'off_cancelled' : 'off_failed'));
    pushState();
    return { ok: false, cancelled: !!auth.cancelled, error: 'auth', mode: config.readConfig(USER_DATA).mode };
  }
  config.setMode(USER_DATA, 'off');
  activity.appendActivity(ACTIVITY_FILE, activity.makeEntry('toggle', 'off'));
  pushState();
  return { ok: true, mode: 'off' };
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
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
