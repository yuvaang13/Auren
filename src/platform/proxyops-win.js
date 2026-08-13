/* Auren — proxyops-win.js
 *
 * Windows system-proxy primitives for the daemon.
 *
 * WinINET (what browsers use for system proxy + PAC) is per-user, but the
 * daemon runs as SYSTEM. So this writes the AutoConfigURL / ProxyEnable keys
 * into EVERY interactive user's registry hive under HKEY_USERS, then broadcasts
 * WM_SETTINGCHANGE so WinINET re-reads its settings. The PAC URL is the same
 * loopback URL the mac side uses, so the daemon's reconciliation logic is
 * platform-neutral.
 *
 * Every command builder is a pure function (unit-testable without PowerShell);
 * the exec wrappers spawn `powershell.exe` (override with AUREN_PS).
 */

'use strict';
const { spawnSync } = require('child_process');

const INET = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

function psBin() {
  return process.env.AUREN_PS || 'powershell.exe';
}

function runPS(script) {
  const r = spawnSync(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  return { status: r.status, stdout: (r.stdout || ''), stderr: (r.stderr || '') };
}

function parseLines(out) {
  return String(out || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
}

// Interactive user hives under HKEY_USERS. Filters out the built-in
// .DEFAULT / SYSTEM / LOCAL SERVICE / NETWORK SERVICE SIDs.
function listHivesCmd() {
  return 'Get-ChildItem HKEY_USERS | '
    + 'Where-Object { $_.PSChildName -notmatch "^\\.DEFAULT$|^S-1-5-18$|^S-1-5-19$|^S-1-5-20$|_Classes$" } | '
    + 'ForEach-Object { $_.PSChildName }';
}

function listHives() {
  const r = runPS(listHivesCmd());
  if (r.status !== 0) return [];
  return parseLines(r.stdout);
}

function hivePath(hive) {
  return 'HKEY_USERS\\' + String(hive).replace(/[^A-Za-z0-9-]/g, '') + INET;
}

function getProxyStateCmd(hive) {
  const p = hivePath(hive);
  return '$p = ' + JSON.stringify(p) + '; '
    + '$e = (Get-ItemProperty -Path $p -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable; '
    + '$u = (Get-ItemProperty -Path $p -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL; '
    + 'if ($null -eq $e) { $e = 0 }; '
    + '"ENABLED=" + [int]$e; '
    + '"URL=" + [string]$u';
}

function getProxyState(hive) {
  const r = runPS(getProxyStateCmd(hive));
  if (r.status !== 0) return { enabled: false, url: '' };
  let enabled = false;
  let url = '';
  for (const line of parseLines(r.stdout)) {
    if (/^ENABLED=(1|true)$/i.test(line)) enabled = true;
    const m = /^URL=(.*)$/.exec(line);
    if (m) url = m[1].trim();
  }
  return { enabled, url };
}

function setAutoProxyCmd(hive, pacUrl) {
  const p = hivePath(hive);
  const url = String(pacUrl || '').replace(/'/g, "''");
  return '$p = ' + JSON.stringify(p) + '; '
    + 'New-Item -Path $p -Force | Out-Null; '
    + 'Set-ItemProperty -Path $p -Name AutoConfigURL -Value ' + JSON.stringify(url) + '; '
    + 'Set-ItemProperty -Path $p -Name ProxyEnable -Value 1';
}

function setAutoProxy(hive, pacUrl) {
  return runPS(setAutoProxyCmd(hive, pacUrl)).status === 0;
}

// Restore the exact prior { enabled, url } for a hive.
function setProxyStateCmd(hive, prior) {
  const p = hivePath(hive);
  const parts = ['$p = ' + JSON.stringify(p) + ';', 'New-Item -Path $p -Force | Out-Null;'];
  if (prior && prior.url) {
    parts.push('Set-ItemProperty -Path $p -Name AutoConfigURL -Value ' + JSON.stringify(String(prior.url).replace(/'/g, "''")) + ';');
  } else {
    parts.push('Remove-ItemProperty -Path $p -Name AutoConfigURL -ErrorAction SilentlyContinue;');
  }
  parts.push('Set-ItemProperty -Path $p -Name ProxyEnable -Value ' + ((prior && prior.enabled) ? '1' : '0') + ';');
  return parts.join(' ');
}

function setProxyState(hive, prior) {
  return runPS(setProxyStateCmd(hive, prior)).status === 0;
}

// Take over every interactive user hive: remember prior state, then point the
// AutoConfigURL at Auren's PAC.
function applyProxy(state, pacUrl) {
  if (!state || typeof state !== 'object') state = {};
  if (!state.proxy) state.proxy = {};
  let changed = false;
  let failed = false;
  for (const hive of listHives()) {
    if (!(hive in state.proxy)) {
      const cur = getProxyState(hive);
      state.proxy[hive] = cur;
    }
    const st = getProxyState(hive);
    if (st.enabled && st.url === pacUrl) continue;
    if (setAutoProxy(hive, pacUrl)) changed = true;
    else failed = true;
  }
  if (changed) refresh();
  return { changed, failed };
}

// Restore every hive we took over to its original WinINET proxy state.
function clearProxy(state, pacUrl) {
  if (!state || typeof state !== 'object' || !state.proxy) return { changed: false, failed: false };
  let changed = false;
  let failed = false;
  for (const hive of Object.keys(state.proxy)) {
    const prior = state.proxy[hive] || {};
    const st = getProxyState(hive);
    const ours = !!pacUrl ? st.url === pacUrl : /^http:\/\/127\.0\.0\.1:4279\d\/proxy\.pac$/.test(st.url);
    if (ours) {
      if (setProxyState(hive, prior)) changed = true;
      else failed = true;
    }
    delete state.proxy[hive];
  }
  if (changed) refresh();
  return { changed, failed };
}

// True when at least one interactive user hive points at our PAC.
function isProxyActive(pacUrl) {
  for (const hive of listHives()) {
    const st = getProxyState(hive);
    if (st.enabled && st.url === pacUrl) return true;
  }
  return false;
}

// Broadcast WM_SETTINGCHANGE so already-running WinINET clients (browsers)
// re-read their proxy settings immediately.
function refreshCmd() {
  return 'Add-Type -Namespace Auren -Name NetRefresh -MemberDefinition @\"\n'
    + '[DllImport(\"user32.dll\", SetLastError = true, CharSet = CharSet.Auto)]\n'
    + 'public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);\n'
    + '\"@\n'
    + '$r = [UIntPtr]::Zero\n'
    + '[Auren.NetRefresh]::SendMessageTimeout([IntPtr]::Zero, 0x1A, [UIntPtr]::Zero, \"InternetSettings\", 2, 5000, [ref]$r) | Out-Null';
}

function refresh() {
  runPS(refreshCmd());
}

module.exports = {
  listHivesCmd, listHives, getProxyStateCmd, getProxyState,
  setAutoProxyCmd, setAutoProxy, setProxyStateCmd, setProxyState,
  applyProxy, clearProxy, isProxyActive, refreshCmd, refresh
};
