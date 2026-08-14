/* Auren — dns-controller-mac.js
 *
 * macOS side of orchestrating the privileged DNS daemon from the
 * (unprivileged) desktop app.
 *
 * Model:
 *   - The daemon is a root LaunchDaemon (com.auren.guardrail) installed once
 *     via an OS-native admin prompt. After that it runs persistently and
 *     needs no privileges from this process to toggle Protection Mode — the
 *     app just writes config.json and the daemon reconciles system DNS.
 *   - Toggling the block list or mode never requires root here; only the
 *     one-time daemon install does.
 */

'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, execFile } = require('child_process');
const dnsops = require('./dnsops-mac');

const PLIST = '/Library/LaunchDaemons/com.auren.guardrail.plist';
const DAEMON_LIB = '/usr/local/lib/auren';

// Bump whenever the daemon contract changes (env vars, code, behavior). The
// app compares the installed daemon's version against this and re-runs the
// installer when they disagree, so a running launchd job never silently keeps
// old behavior after an app update. Keep in sync with daemon.js DAEMON_VERSION.
const DAEMON_VERSION = 22;

function isDaemonInstalled() {
  return fs.existsSync(PLIST);
}

// Reads what is actually installed (plist env + program) so the app can tell a
// stale daemon apart from a healthy one. Returns null if the plist is missing
// or unparseable.
function installedDaemonInfo() {
  if (!fs.existsSync(PLIST)) return null;
  try {
    const out = execFileSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', PLIST], { encoding: 'utf8' });
    const parsed = JSON.parse(out);
    const env = (parsed && parsed.EnvironmentVariables) || {};
    const args = Array.isArray(parsed && parsed.ProgramArguments) ? parsed.ProgramArguments : [];
    return {
      version: env.AUREN_DAEMON_VERSION || null,
      nodeBin: args[0] || null,
      daemonPath: args[1] || null,
      keyPath: env.AUREN_KEY || null,
      heartbeatPath: env.AUREN_HEARTBEAT || null
    };
  } catch {
    return null;
  }
}

// The installed daemon is current only when it carries the version this app
// bundles AND the env vars the hardened daemon depends on (integrity key +
// heartbeat). An old launchd job from before those existed is stale.
function isDaemonCurrent() {
  const info = installedDaemonInfo();
  return !!info &&
    info.version === String(DAEMON_VERSION) &&
    !!info.heartbeatPath &&
    !!info.keyPath;
}

// Whether the system is actually resolving through our local resolver.
function isEnforcing() {
  return dnsops.isEnforcing();
}

function shellQuote(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

function findNodeBin(exePath) {
  try {
    const node = execFileSync('/usr/bin/which', ['node'], { encoding: 'utf8' }).trim();
    if (node) return node;
  } catch { /* fall through */ }
  // Fall back to running Electron itself in node mode (ELECTRON_RUN_AS_NODE).
  return exePath;
}

function buildInstallerScript(opts) {
  // `srcDir` must contain all daemon modules flat (daemon, resolver,
  // dns-message, cache, pf, domains, config, activity, apps, autofill + the
  // platform seams). The app stages them into a temp dir first so the
  // privileged installer can read them (root can't always read files under
  // TCC-protected folders like ~/Desktop).
  const src = opts.srcDir;
  const cfg = opts.configPath;
  const act = opts.activityPath;
  const st = opts.statePath;
  const key = opts.keyPath;
  const hb = opts.heartbeatPath;
  const spool = '/Library/Application Support/Auren';
  return [
    '#!/bin/bash',
    'set -euo pipefail',
    'LIB=' + shellQuote(DAEMON_LIB),
    'SPOOL=' + shellQuote(spool),
    'SRC=' + shellQuote(src),
    'mkdir -p "$LIB" "$SPOOL"',
    'cp "$SRC/dns-message.js" "$SRC/resolver.js" "$SRC/daemon.js" "$SRC/cache.js" "$SRC/pf.js" "$SRC/sni.js" "$SRC/server.js" "$SRC/domains.js" "$SRC/config.js" "$SRC/activity.js" "$SRC/state.js" "$SRC/apps.js" "$SRC/autofill.js" "$SRC/autofill-mac.js" "$SRC/dnsops.js" "$SRC/dnsops-mac.js" "$SRC/proxyops.js" "$SRC/proxyops-mac.js" "$SRC/procs.js" "$SRC/procs-mac.js" "$LIB/"',
    'chmod 755 "$LIB/daemon.js"',
    'cat > ' + shellQuote(PLIST) + ' <<PLIST',
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<dict>',
    '  <key>Label</key>',
    '  <string>com.auren.guardrail</string>',
    '  <key>ProgramArguments</key>',
    '  <array>',
    '    <string>' + opts.nodeBin + '</string>',
    '    <string>$LIB/daemon.js</string>',
    '  </array>',
    '  <key>EnvironmentVariables</key>',
    '  <dict>',
    '    <key>AUREN_CONFIG</key>',
    '    <string>' + cfg + '</string>',
    '    <key>AUREN_KEY</key>',
    '    <string>' + key + '</string>',
    '    <key>AUREN_HEARTBEAT</key>',
    '    <string>' + hb + '</string>',
    '    <key>AUREN_ACTIVITY</key>',
    '    <string>' + act + '</string>',
    '    <key>AUREN_STATE</key>',
    '    <string>' + st + '</string>',
    '    <key>AUREN_DAEMON_LOG</key>',
    '    <string>$SPOOL/daemon.log</string>',
    '    <key>ELECTRON_RUN_AS_NODE</key>',
    '    <string>1</string>',
    '    <key>AUREN_DAEMON_VERSION</key>',
    '    <string>' + DAEMON_VERSION + '</string>',
    '  </dict>',
    '  <key>RunAtLoad</key>',
    '  <true/>',
    '  <key>KeepAlive</key>',
    '  <true/>',
    '  <key>ProcessType</key>',
    '  <string>Background</string>',
    '  <key>StandardOutPath</key>',
    '  <string>$SPOOL/daemon.log</string>',
    '  <key>StandardErrorPath</key>',
    '  <string>$SPOOL/daemon.log</string>',
    '</dict>',
    '</plist>',
    'PLIST',
    'exec >> "$SPOOL/install.log" 2>&1',
    'echo "=== auren installer $(/bin/date -u +%FT%TZ) pid $$ ==="',
    // grep lives at /usr/bin/grep on modern macOS and /bin/grep on older ones.
    // Resolve it before the heartbeat-wait below, so a wrong path can't make a
    // successful install look like a failed one (a 15s timeout + AUREN_INSTALL_FAILED).
    'GREP=/usr/bin/grep',
    '[ -x /bin/grep ] && GREP=/bin/grep',
    'HB=' + shellQuote(hb),
    'OLD_M=0',
    'if [ -f "$HB" ]; then OLD_M=$(/usr/bin/stat -f %m "$HB" 2>/dev/null || echo 0); fi',
    '/bin/launchctl bootout system/com.auren.guardrail 2>/dev/null || /bin/launchctl unload ' + shellQuote(PLIST) + ' 2>/dev/null || true',
    // bootout tears the old service down asynchronously; its label can linger
    // for seconds. Bootstrapping over it fails, and the old daemon keeps
    // writing fresh heartbeats in the meantime — which used to make a failed
    // install look successful. Wait for the label to fully disappear before
    // bootstrapping.
    'i=0',
    'while /bin/launchctl print system/com.auren.guardrail >/dev/null 2>&1 && [ "$i" -lt 15 ]; do /bin/sleep 1; i=$((i + 1)); done',
    'i=0',
    'OK=0',
    'while [ "$i" -lt 5 ] && [ "$OK" -eq 0 ]; do',
    '  if /bin/launchctl bootstrap system ' + shellQuote(PLIST) + ' 2>/dev/null || /bin/launchctl load -w ' + shellQuote(PLIST) + ' 2>/dev/null; then OK=1; fi',
    '  if [ "$OK" -eq 0 ]; then /bin/sleep 1; fi',
    '  i=$((i + 1))',
    'done',
    'if [ "$OK" -eq 0 ]; then echo "bootstrap failed after retries" >&2; echo AUREN_INSTALL_FAILED >&2; exit 1; fi',
    'echo "bootstrapped — waiting for a v' + DAEMON_VERSION + ' heartbeat"',
    // A loaded label is not a running daemon: launchd can know the service while
    // the process fails to actually start (port 53 still busy after bootout,
    // node crash, teardown race). Success is ONLY a heartbeat written by the
    // NEW code: a file newer than the one that existed before this install AND
    // carrying the version we just installed. The old daemon's goodbye
    // heartbeat must never count. Otherwise exit non-zero so the app shows a
    // real setup failure instead of a false "installed".
    'i=0',
    'while [ "$i" -lt 15 ]; do',
    '  if [ -f "$HB" ] && [ "$(/usr/bin/stat -f %m "$HB" 2>/dev/null || echo 0)" -gt "$OLD_M" ] && $GREP -q ' + JSON.stringify('"version":' + DAEMON_VERSION + '[,}]') + ' "$HB"; then',
    '    echo AUREN_INSTALL_OK',
    '    exit 0',
    '  fi',
    '  /bin/sleep 1',
    '  i=$((i + 1))',
    'done',
    'echo "no fresh v' + DAEMON_VERSION + ' heartbeat after restart" >&2',
    'echo AUREN_INSTALL_FAILED >&2',
    'exit 1'
  ].join('\n');
}

// Stages the daemon modules into a temp dir readable by the privileged
// installer. Core modules land flat in the same dir as the daemon (see
// load()/loadPlatform() in daemon.js), and the installer copies them all flat
// into /usr/local/lib/auren/.
function stageDaemonFiles() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auren-stage-'));
  const dnsDir = path.join(__dirname, '..', 'dns');
  const coreDir = path.join(__dirname, '..', 'core');
  const platformDir = path.join(__dirname, '..', 'platform');
  for (const f of ['daemon.js', 'resolver.js', 'dns-message.js', 'cache.js', 'pf.js']) {
    fs.copyFileSync(path.join(dnsDir, f), path.join(dir, f));
  }
  const proxyDir = path.join(__dirname, '..', 'proxy');
  for (const f of ['sni.js', 'server.js']) {
    fs.copyFileSync(path.join(proxyDir, f), path.join(dir, f));
  }
  for (const f of ['domains.js', 'config.js', 'activity.js', 'state.js', 'apps.js']) {
    fs.copyFileSync(path.join(coreDir, f), path.join(dir, f));
  }
  for (const f of ['autofill.js', 'autofill-mac.js', 'dnsops.js', 'dnsops-mac.js', 'proxyops.js', 'proxyops-mac.js', 'procs.js', 'procs-mac.js']) {
    fs.copyFileSync(path.join(platformDir, f), path.join(dir, f));
  }
  return dir;
}

// Runs the installer with an OS-native admin prompt. Resolves to { ok, error }.
function installDaemon(opts) {
  return new Promise((resolve) => {
    let stageDir = null;
    let tmp = null;
    try {
      stageDir = stageDaemonFiles();
      tmp = path.join(os.tmpdir(), 'auren-install-' + process.pid + '.sh');
      fs.writeFileSync(tmp, buildInstallerScript(Object.assign({}, opts, { srcDir: stageDir })), { mode: 0o700 });
    } catch (err) {
      return resolve({ ok: false, error: 'could not write installer: ' + err.message });
    }
    const cmd = '/bin/bash ' + shellQuote(tmp);
    execFile('/usr/bin/osascript', ['-e', 'do shell script ' + JSON.stringify(cmd) + ' with administrator privileges with prompt "Auren needs to install its system-wide blocking service"'], (error, stdout) => {
      try { fs.unlinkSync(tmp); } catch {}
      try { fs.rmSync(stageDir, { recursive: true, force: true }); } catch {}
      if (!error) return resolve({ ok: true, output: String(stdout || '') });
      const msg = String((error && (error.message || error.code)) || '');
      return resolve({ ok: false, error: msg, cancelled: /-128|cancel|interrupted/i.test(msg) });
    });
  });
}

// Non-interactive install path (used by scripts/install-daemon.sh as root).
function installDaemonCli(opts) {
  const stageDir = stageDaemonFiles();
  const tmp = path.join(os.tmpdir(), 'auren-install-cli-' + process.pid + '.sh');
  fs.writeFileSync(tmp, buildInstallerScript(Object.assign({}, opts, { srcDir: stageDir })), { mode: 0o700 });
  const r = execFileSync('/bin/bash', [tmp], { encoding: 'utf8' });
  try { fs.unlinkSync(tmp); } catch {}
  try { fs.rmSync(stageDir, { recursive: true, force: true }); } catch {}
  return r;
}

module.exports = { PLIST, DAEMON_LIB, DAEMON_VERSION, isDaemonInstalled, installedDaemonInfo, isDaemonCurrent, isEnforcing, findNodeBin, buildInstallerScript, installDaemon, installDaemonCli };
