/* Auren — pf-win.js
 *
 * Windows Firewall implementation of the same "OS/terminal-level network
 * blocking" contract that macOS implements with a pf anchor (src/dns/pf.js).
 *
 * The RULE ENGINE is shared: pf.js's buildAnchorRules() emits the same rule
 * lines on both platforms, and this module translates them into Windows
 * Firewall outbound BLOCK rules via New-NetFirewallRule. There are no allow
 * rules — Windows Firewall's default outbound policy is Allow, so everything
 * not explicitly blocked (80/443, DNS, loopback) passes by default, and there
 * is never an allow-vs-block precedence fight. The root safetyFloor already
 * strips allowlist entries that would carve out a blocked port/host, so the
 * effective posture matches macOS.
 *
 * Honest limits (documented in README): Windows Firewall exposes no packet
 * counters via cmdlets, so ruleStats() returns an empty array and the DoH
 * packet-counter telemetry (doh_blocked activity) is macOS-only. Windows logs
 * rule application instead.
 *
 * All execs are injectable via AUREN_PS (the PowerShell binary) so the test
 * suite can exercise the flow with a fake runner, never touching a real
 * machine's firewall.
 */

'use strict';
const fs = require('fs');
const { spawnSync } = require('child_process');

const RULE_GROUP = 'Auren';

function psBin() {
  return process.env.AUREN_PS || 'powershell.exe';
}

function runPS(script) {
  try {
    return spawnSync(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8' });
  } catch (err) {
    return { status: -1, stdout: '', stderr: err.message || String(err) };
  }
}

// Parse the shared buildAnchorRules() output into Windows Firewall rule
// descriptors. Pure and unit-testable. `pass` lines (loopback, DNS, 80/443,
// allowlist) are deliberately ignored — Windows default outbound allow covers
// them; only `block` lines become rules.
function parseRuleLines(lines) {
  const out = [];
  for (const raw of (Array.isArray(lines) ? lines : [])) {
    const t = String(raw || '').trim();
    if (!t || t.startsWith('#')) continue;
    if (/^pass\b/.test(t)) continue;
    let m;
    // Both-protocols port block: `block out proto { tcp udp } to port { 21 22 }`
    if ((m = /^block out proto \{ tcp udp \} to port \{ ([^}]+) \}$/.exec(t))) {
      const ports = m[1].trim().split(/\s+/).map((n) => Number(n)).filter((n) => n >= 1 && n <= 65535);
      out.push({ proto: 'tcp', remotePort: ports });
      out.push({ proto: 'udp', remotePort: ports });
    } else if ((m = /^block out proto (tcp|udp) to port (\d+)$/.exec(t))) {
      out.push({ proto: m[1], remotePort: [Number(m[2])] });
    } else if ((m = /^block out proto (icmp|icmp6)$/.exec(t))) {
      out.push({ icmp: m[1] === 'icmp6' ? 'ICMPv6' : 'ICMPv4' });
    } else if ((m = /^block out proto \{ tcp udp \} to (.+)$/.exec(t))) {
      for (const h of m[1].trim().split(/\s+/).filter(Boolean)) {
        out.push({ proto: 'tcp', remoteAddress: h });
        out.push({ proto: 'udp', remoteAddress: h });
      }
    } else if ((m = /^block out proto (tcp|udp) to (.+)$/.exec(t))) {
      for (const h of m[1].trim().split(/\s+/).filter(Boolean)) {
        out.push({ proto: m[2], remoteAddress: h });
      }
    }
  }
  return out;
}

// A PowerShell fragment that creates one rule for a descriptor. Pure, so tests
// can assert the exact firewall commands without a machine.
function ruleFragment(rule, index) {
  const args = ['-DisplayName', '"Auren ' + index + '"', '-Group', RULE_GROUP, '-Direction', 'Outbound', '-Action', 'Block', '-Profile', 'Any', '-ErrorAction', 'Stop'];
  if (rule.icmp) {
    args.push('-Protocol', rule.icmp);
  } else {
    args.push('-Protocol', rule.proto === 'udp' ? 'UDP' : 'TCP');
    if (rule.remotePort && rule.remotePort.length) args.push('-RemotePort', '"' + rule.remotePort.join(',') + '"');
    if (rule.remoteAddress) args.push('-RemoteAddress', '"' + rule.remoteAddress + '"');
  }
  return 'New-NetFirewallRule ' + args.join(' ');
}

// The full script that clears any existing Auren rules and recreates the
// desired set. Pure.
function buildPSScript(ruleLines) {
  const rules = parseRuleLines(ruleLines);
  const parts = [
    'Remove-NetFirewallRule -Group ' + RULE_GROUP + ' -ErrorAction SilentlyContinue',
    '$ErrorActionPreference = "Stop"'
  ];
  rules.forEach((r, i) => parts.push(ruleFragment(r, i)));
  parts.push('"AUREN_FW_OK " + ' + rules.length);
  return parts.join('\n');
}

// Apply (or re-apply) the rule set. `rulesFile` is the shared pf-format file
// the daemon writes; we translate and load it, mirroring the mac anchor flow.
function applyAnchor(rulesFile) {
  let content = '';
  try { content = fs.readFileSync(rulesFile, 'utf8'); } catch (err) { return { ok: false, error: 'rules file unreadable: ' + err.message }; }
  if (!content || !content.trim()) return { ok: false, error: 'empty rules file' };
  const r = runPS(buildPSScript(content.split('\n')));
  if (r.status !== 0) {
    return { ok: false, error: (r.stderr || r.stdout || '').trim() || 'New-NetFirewallRule failed' };
  }
  if (!/AUREN_FW_OK/.test(r.stdout || '')) return { ok: false, error: 'firewall rules did not load (no confirmation)' };
  return { ok: true };
}

function clearAnchor() {
  const r = runPS('Remove-NetFirewallRule -Group ' + RULE_GROUP + ' -ErrorAction SilentlyContinue');
  return r.status === 0 ? { ok: true } : { ok: false, error: (r.stderr || r.stdout || '').trim() || 'firewall clear failed' };
}

function isAnchorLoaded() {
  const r = runPS('(Get-NetFirewallRule -Group ' + RULE_GROUP + ' -ErrorAction SilentlyContinue | Measure-Object).Count');
  return r.status === 0 && /^[1-9]/m.test(r.stdout || '');
}

// Windows Firewall exposes no per-rule packet counters via cmdlets; the DoH
// packet-counter telemetry is macOS-only. Returns an empty stats array so the
// daemon's sweep no-ops.
function ruleStats() {
  return { ok: true, stats: [] };
}

module.exports = { RULE_GROUP, psBin, runPS, parseRuleLines, ruleFragment, buildPSScript, applyAnchor, clearAnchor, isAnchorLoaded, ruleStats };
