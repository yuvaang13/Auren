/* Auren — dns-controller.js
 *
 * Orchestrates the privileged DNS daemon from the (unprivileged) desktop app.
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

const PLIST = '/Library/LaunchDaemons/com.auren.guardrail.plist';
const DAEMON_LIB = '/usr/local/lib/auren';

function isDaemonInstalled() {
  return fs.existsSync(PLIST);
}

// Whether the system is actually resolving through our local resolver.
function isEnforcing() {
  try {
    const out = execFileSync('/usr/sbin/scutil', ['--dns'], { encoding: 'utf8' });
    return /nameserver\[\d+\]\s*:\s*127\.0\.0\.1/.test(out);
  } catch (err) {
    return false;
  }
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
  // `srcDir` must contain all six modules flat (daemon, resolver, dns-message,
  // domains, config, activity). The app stages them into a temp dir first so
  // the privileged installer can read them (root can't always read files under
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
    'cp "$SRC/dns-message.js" "$SRC/resolver.js" "$SRC/daemon.js" "$SRC/domains.js" "$SRC/config.js" "$SRC/activity.js" "$LIB/"',
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
    '/bin/launchctl bootout system/com.auren.guardrail 2>/dev/null || /bin/launchctl unload ' + shellQuote(PLIST) + ' 2>/dev/null || true',
    '/bin/launchctl bootstrap system ' + shellQuote(PLIST) + ' || /bin/launchctl load -w ' + shellQuote(PLIST),
    'echo AUREN_INSTALL_OK'
  ].join('\n');
}

// Stages the six flat daemon modules into a temp dir readable by the
// privileged installer.
function stageDaemonFiles() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auren-stage-'));
  const dnsDir = path.join(__dirname, '..', 'dns');
  const coreDir = path.join(__dirname, '..', 'core');
  for (const f of ['daemon.js', 'resolver.js', 'dns-message.js']) {
    fs.copyFileSync(path.join(dnsDir, f), path.join(dir, f));
  }
  for (const f of ['domains.js', 'config.js', 'activity.js']) {
    fs.copyFileSync(path.join(coreDir, f), path.join(dir, f));
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

module.exports = { PLIST, DAEMON_LIB, isDaemonInstalled, isEnforcing, findNodeBin, buildInstallerScript, installDaemon, installDaemonCli };
