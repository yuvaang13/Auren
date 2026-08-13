/* Auren — dns-controller-win.js
 *
 * Windows side of orchestrating the privileged DNS daemon from the
 * (unprivileged) desktop app. Same model as macOS, different mechanism:
 *
 *   - The daemon is a SYSTEM Scheduled Task (AurenGuardrailDaemon) registered
 *     once via a UAC elevation prompt. It runs persistently with highest
 *     privileges, so toggling Protection Mode never needs elevation — the app
 *     just writes config.json and the daemon reconciles the adapters.
 *   - Tasks can't carry env vars cleanly, so the daemon takes its settings as
 *     --AUREN_*=... argv (see argValue() in daemon.js). A small run-daemon.ps1
 *     in the daemon dir sets ELECTRON_RUN_AS_NODE (so the packaged Electron
 *     exe acts as plain node) and execs the daemon with the baked-in args.
 *
 * Bump DAEMON_VERSION with daemon.js whenever the daemon contract changes.
 */

'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile, execFileSync } = require('child_process');
const dnsops = require('./dnsops-win');
const paths = require('./paths');

const TASK_NAME = 'AurenGuardrailDaemon';
const DAEMON_LIB = paths.daemonDir();
const SPOOL = paths.systemSpoolDir();
const RUNNER = path.join(DAEMON_LIB, 'run-daemon.ps1');
const DAEMON_VERSION = 18;

function psBin() {
  return process.env.AUREN_PS || 'powershell.exe';
}

function runPS(script) {
  const r = execFileSync(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  return String(r || '').trim();
}

function psQuote(s) {
  return "'" + String(s).replace(/'/g, "''") + "'";
}

function isDaemonInstalled() {
  try {
    const out = runPS("$t = Get-ScheduledTask -TaskName '" + TASK_NAME + "' -ErrorAction SilentlyContinue; if ($t) { 'YES' } else { 'NO' }");
    return out === 'YES';
  } catch {
    return false;
  }
}

// Reads the installed runner script (which bakes in version + the hardened
// env-like args) so the app can tell a stale daemon apart from a healthy one.
// Returns null when the task or runner is missing.
function installedDaemonInfo() {
  if (!isDaemonInstalled() || !fs.existsSync(RUNNER)) return null;
  try {
    const body = fs.readFileSync(RUNNER, 'utf8');
    const get = (name) => {
      const m = new RegExp('--' + name + '=([^\\s\']+)').exec(body);
      return m ? m[1] : null;
    };
    return {
      version: get('AUREN_DAEMON_VERSION'),
      nodeBin: null,
      daemonPath: null,
      keyPath: get('AUREN_KEY'),
      heartbeatPath: get('AUREN_HEARTBEAT')
    };
  } catch {
    return null;
  }
}

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

function findNodeBin(exePath) {
  try {
    const node = execFileSync('where', ['node'], { encoding: 'utf8' }).split('\n')[0].trim();
    if (node) return node;
  } catch { /* fall through */ }
  // Fall back to running the packaged Electron exe in node mode.
  return exePath;
}

// PowerShell installer. Prints AUREN_INSTALL_OK / AUREN_INSTALL_FAILED and,
// when opts.outputFile is set, writes the same line there (the elevated
// wrapper redirects console output awkwardly, so the script reports via file).
function buildInstallerScript(opts) {
  const src = opts.srcDir;
  const lib = DAEMON_LIB;
  const spool = SPOOL;
  const cfg = opts.configPath;
  const act = opts.activityPath;
  const st = opts.statePath;
  const key = opts.keyPath;
  const hb = opts.heartbeatPath;
  const log = paths.daemonLogFile();
  const runner = RUNNER;
  const nodeBin = opts.nodeBin;
  const out = opts.outputFile || '';
  const daemonArgs = [
    '--AUREN_CONFIG=' + cfg,
    '--AUREN_KEY=' + key,
    '--AUREN_HEARTBEAT=' + hb,
    '--AUREN_ACTIVITY=' + act,
    '--AUREN_STATE=' + st,
    '--AUREN_DAEMON_LOG=' + log,
    '--AUREN_DAEMON_VERSION=' + DAEMON_VERSION
  ].map(psQuote).join(',\n      ');
  const runnerBody = [
    '$env:ELECTRON_RUN_AS_NODE = "1"',
    '& ' + psQuote(nodeBin) + ' ' + psQuote(path.join(lib, 'daemon.js')) + ' @(\n      ' + daemonArgs + '\n    )'
  ].join('\n');
  const lines = [
    '$ErrorActionPreference = "Stop"',
    '$ok = $false',
    'try {',
    '  New-Item -ItemType Directory -Force -Path ' + psQuote(lib) + ', ' + psQuote(spool) + ' | Out-Null',
    '  Copy-Item -Path ' + psQuote(path.join(src, '*')) + ' -Destination ' + psQuote(lib) + ' -Force',
    '  Set-Content -Path ' + psQuote(runner) + ' -Value ' + psQuote(runnerBody) + ' -Encoding ASCII',
    '  $old = 0',
    '  if (Test-Path ' + psQuote(hb) + ') { $old = (Get-Item ' + psQuote(hb) + ').LastWriteTimeUtc.Ticks }',
    '  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ' + psQuote('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + runner + '"'),
    '  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest',
    '  $trigger = New-ScheduledTaskTrigger -AtStartup',
    '  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)',
    '  Register-ScheduledTask -TaskName ' + psQuote(TASK_NAME) + ' -Action $action -Principal $principal -Trigger $trigger -Settings $settings -Force | Out-Null',
    '  Start-ScheduledTask -TaskName ' + psQuote(TASK_NAME),
    '  $cut = (Get-Date).AddSeconds(20)',
    '  while ((Get-Date) -lt $cut) {',
    '    if (Test-Path ' + psQuote(hb) + ') {',
    '      $f = Get-Item ' + psQuote(hb),
    '      if ($f.LastWriteTimeUtc.Ticks -gt $old -and (Get-Content ' + psQuote(hb) + ' -Raw) -match ' + JSON.stringify('"version":' + DAEMON_VERSION + '[,}]') + ') { $ok = $true; break }',
    '    }',
    '    Start-Sleep -Seconds 1',
    '  }',
    '  if ($ok) { "AUREN_INSTALL_OK" } else { "AUREN_INSTALL_FAILED: no fresh v' + DAEMON_VERSION + ' heartbeat" }',
    '} catch {',
    '  "AUREN_INSTALL_FAILED: " + $_.Exception.Message',
    '}'
  ];
  if (out) {
    lines.push(' | Tee-Object -FilePath ' + psQuote(out));
  }
  return lines.join('\n');
}

// Stages the daemon modules flat into a temp dir, exactly like the mac side
// (see stageDaemonFiles in dns-controller-mac.js). Includes the win variants
// the dispatchers resolve at runtime.
function stageDaemonFiles() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auren-stage-'));
  const dnsDir = path.join(__dirname, '..', 'dns');
  const coreDir = path.join(__dirname, '..', 'core');
  const platformDir = path.join(__dirname, '..', 'platform');
  for (const f of ['daemon.js', 'resolver.js', 'dns-message.js', 'cache.js', 'pf.js', 'pf-win.js']) {
    fs.copyFileSync(path.join(dnsDir, f), path.join(dir, f));
  }
  const proxyDir = path.join(__dirname, '..', 'proxy');
  for (const f of ['sni.js', 'server.js']) {
    fs.copyFileSync(path.join(proxyDir, f), path.join(dir, f));
  }
  for (const f of ['domains.js', 'config.js', 'activity.js', 'apps.js']) {
    fs.copyFileSync(path.join(coreDir, f), path.join(dir, f));
  }
  for (const f of ['autofill.js', 'autofill-win.js', 'dnsops.js', 'dnsops-win.js', 'proxyops.js', 'proxyops-win.js', 'procs.js', 'procs-win.js']) {
    fs.copyFileSync(path.join(platformDir, f), path.join(dir, f));
  }
  return dir;
}

function cleanup(pathsToRemove) {
  for (const p of pathsToRemove) {
    try { fs.rmSync(p, { recursive: true, force: true }); } catch {}
  }
}

// Runs the installer with a UAC elevation prompt. Resolves to { ok, error,
// cancelled }.
function installDaemon(opts) {
  return new Promise((resolve) => {
    let stageDir = null;
    let psPath = null;
    let outPath = null;
    try {
      stageDir = stageDaemonFiles();
      psPath = path.join(os.tmpdir(), 'auren-install-' + process.pid + '.ps1');
      outPath = path.join(os.tmpdir(), 'auren-install-' + process.pid + '.out');
      fs.writeFileSync(psPath, buildInstallerScript(Object.assign({}, opts, { srcDir: stageDir, outputFile: outPath })), 'utf8');
    } catch (err) {
      return resolve({ ok: false, error: 'could not write installer: ' + err.message });
    }
    const runner = psQuote(psPath);
    const cmd = 'Start-Process ' + psBin() + ' -Verb RunAs -Wait -ArgumentList ' + psQuote('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + psPath);
    execFile(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', cmd], (error) => {
      let output = '';
      try { output = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf8') : ''; } catch {}
      cleanup([psPath, outPath, stageDir]);
      const line = String(output || '').trim().split('\n').pop() || '';
      if (/AUREN_INSTALL_OK/.test(line)) return resolve({ ok: true, output });
      if (/AUREN_INSTALL_FAILED/.test(line)) return resolve({ ok: false, error: line });
      const msg = String((error && (error.message || error.code)) || '');
      return resolve({ ok: false, error: msg, cancelled: /1223|cancel|interrupted/i.test(msg) });
    });
  });
}

// Non-interactive install path (used by scripts/install-daemon.ps1, already
// running as administrator). Returns the installer output.
function installDaemonCli(opts) {
  const stageDir = stageDaemonFiles();
  const psPath = path.join(os.tmpdir(), 'auren-install-cli-' + process.pid + '.ps1');
  fs.writeFileSync(psPath, buildInstallerScript(Object.assign({}, opts, { srcDir: stageDir })), 'utf8');
  const r = execFileSync(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', psPath], { encoding: 'utf8' });
  cleanup([psPath, stageDir]);
  return r;
}

module.exports = { TASK_NAME, DAEMON_LIB, DAEMON_VERSION, isDaemonInstalled, installedDaemonInfo, isDaemonCurrent, isEnforcing, findNodeBin, buildInstallerScript, installDaemon, installDaemonCli };
