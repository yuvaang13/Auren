/* Auren — dnsops-win.js
 *
 * Windows DNS primitives for the daemon. The same job dnsops-mac.js does with
 * networksetup/scutil, done with PowerShell's DnsClient cmdlets:
 *
 *   - services  = DnsClientServerAddress entries, keyed by InterfaceIndex.
 *                 We use "INDEX:ALIAS" as the service id so it round-trips
 *                 through state.json just like a macOS service name.
 *   - get/set   = Get-DnsClientServerAddress / Set-DnsClientServerAddress.
 *   - discover  = current non-loopback servers on any adapter.
 *   - enforcing = at least one adapter whose effective servers are all
 *                 loopback (127.0.0.1), meaning we own its resolution.
 *
 * Every command builder is a pure function (unit-testable without PowerShell);
 * the exec wrappers spawn `powershell.exe` (override with AUREN_PS).
 */

'use strict';
const { spawnSync } = require('child_process');

function psBin() {
  return process.env.AUREN_PS || 'powershell.exe';
}

function runPS(script) {
  try {
    const r = spawnSync(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
    return { status: r.status ?? -1, stdout: (r.stdout || ''), stderr: (r.stderr || '') };
  } catch (err) {
    return { status: -1, stdout: '', stderr: err.message || String(err) };
  }
}

function parseLines(out) {
  return String(out || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
}

// INDEX:ALIAS per adapter that actually has server addresses configured.
function listServicesCmd() {
  return 'Get-DnsClientServerAddress -AddressFamily IPv4 | '
    + 'Group-Object InterfaceIndex | '
    + 'Where-Object { $_.Group[0].ServerAddresses } | '
    + 'ForEach-Object { "{0}:{1}" -f $_.Name, $_.Group[0].InterfaceAlias }';
}

function listServices() {
  const r = runPS(listServicesCmd());
  if (r.status !== 0) return [];
  return parseLines(r.stdout);
}

function getServersCmd(index) {
  return '(Get-DnsClientServerAddress -InterfaceIndex ' + index + ' -AddressFamily IPv4).ServerAddresses';
}

function getServers(service) {
  const index = String(service || '').split(':')[0];
  const r = runPS(getServersCmd(index));
  if (r.status !== 0) return [];
  return parseLines(r.stdout).filter((l) => /^\d{1,3}(\.\d{1,3}){3}$/.test(l));
}

function setServersCmd(index, ips) {
  if (ips && ips.length) {
    const quoted = ips.map((ip) => "'" + String(ip).replace(/'/g, "''") + "'").join(', ');
    return 'Set-DnsClientServerAddress -InterfaceIndex ' + index + ' -ServerAddresses @(' + quoted + ')';
  }
  return 'Set-DnsClientServerAddress -InterfaceIndex ' + index + ' -ResetServerAddresses';
}

function setServers(service, ips) {
  const index = String(service || '').split(':')[0];
  return runPS(setServersCmd(index, ips)).status === 0;
}

function discoverUpstreamCmd() {
  return 'Get-DnsClientServerAddress -AddressFamily IPv4 | '
    + 'Where-Object { $_.ServerAddresses } | '
    + 'Select-Object -ExpandProperty ServerAddresses | '
    + 'Where-Object { $_ -ne "127.0.0.1" } | '
    + 'Select-Object -Unique';
}

function discoverUpstream(stateServices, fallback) {
  const fromState = [];
  for (const svc of Object.values(stateServices || {})) {
    for (const ip of svc || []) if (ip !== '127.0.0.1' && !fromState.includes(ip)) fromState.push(ip);
  }
  if (fromState.length) return fromState;

  const r = runPS(discoverUpstreamCmd());
  if (r.status === 0) {
    const found = parseLines(r.stdout).filter((l) => /^\d{1,3}(\.\d{1,3}){3}$/.test(l));
    if (found.length) return found;
  }
  return fallback;
}

function isEnforcingCmd() {
  return '$adapters = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses }; '
    + '$count = 0; '
    + 'foreach ($a in $adapters) { $ips = @($a.ServerAddresses); '
    + 'if ($ips.Count -gt 0 -and (@($ips | Where-Object { $_ -ne "127.0.0.1" })).Count -eq 0) { $count++ } }; '
    + '$count';
}

function isEnforcing() {
  const r = runPS(isEnforcingCmd());
  if (r.status !== 0) return false;
  return parseInt(String(r.stdout).trim(), 10) > 0;
}

function portOwnerCmd(port) {
  return 'Get-NetTCPConnection -LocalPort ' + port + ' -State Listen -ErrorAction SilentlyContinue | '
    + 'ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; '
    + 'if ($p) { "{0}:{1}" -f $p.Id, $p.ProcessName } } | Select-Object -First 1';
}

// Parse one "pid:ProcessName" line from the port-owner probe. Pure.
function parsePortOwnerLine(line) {
  const m = /^(\d+):(.+)$/.exec(String(line || '').trim());
  if (!m) return null;
  return { pid: parseInt(m[1], 10), name: m[2] };
}

// Identify the process listening on a TCP port (names a port-53 conflict when
// our resolver can't bind). Returns { pid, name } or null.
function portOwner(port) {
  const r = runPS(portOwnerCmd(port));
  if (r.status !== 0) return null;
  return parsePortOwnerLine(parseLines(r.stdout)[0]);
}

module.exports = { listServices, getServers, setServers, discoverUpstream, isEnforcing, portOwner, parsePortOwnerLine, listServicesCmd, getServersCmd, setServersCmd, discoverUpstreamCmd, isEnforcingCmd, portOwnerCmd };
