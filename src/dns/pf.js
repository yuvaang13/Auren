/* Auren — pf.js
 *
 * macOS packet-filter firewall management for OS/terminal-level network
 * blocking. While Protection Mode is ON the root daemon loads a dedicated pf
 * anchor (name: `auren`) that blocks the traffic patterns terminal commands
 * use — ICMP echo (ping), outbound command ports (SSH/FTP/Telnet/SMB/…), and
 * cloud-metadata IPs — while always passing loopback, DNS, and browsing
 * (80/443) so the machine is never stranded.
 *
 * SAFETY CONTRACT (do not violate):
 *   - We ONLY touch the `auren` anchor. Never run `pfctl -f` against the main
 *     ruleset and never `pfctl -F all` globally — the user may have their own
 *     pf configuration we must not flush.
 *   - We never run `pfctl -d`. If pf was already enabled by the user, disabling
 *     it would be destructive. An enabled pf with an empty anchor passes
 *     everything, so on teardown we just clear our anchor and leave pf as it
 *     was.
 *   - Allow rules always precede block rules: pf evaluates an anchor
 *     first-match-wins, so allowlisted ports/hosts win over the defaults.
 *
 * Rule generation is a pure function (buildAnchorRules) so it is unit-testable
 * without root; only applyAnchor/clearAnchor/isAnchorLoaded shell out to
 * /sbin/pfctl.
 */

'use strict';
const fs = require('fs');
const { spawnSync } = require('child_process');

const ANCHOR = 'auren';
const PFCTL = '/sbin/pfctl';

// Command-tool ports we block outbound by default while Protection is ON.
// 21 ftp, 22 ssh/scp/sftp, 23 telnet, 25 smtp, 110 pop3, 135/137/138/139 netbios,
// 143 imap, 445 smb, 465 smtps, 587 submission, 993 imaps, 995 pop3s,
// 1080 socks proxy, 3389 rdp, 5900 vnc.
const BLOCKED_PORTS = [21, 22, 23, 25, 110, 135, 137, 138, 139, 143, 445, 465, 587, 993, 995, 1080, 3389, 5900];

// Cloud-instance metadata endpoints. Never reachable via DNS (they are IPs),
// so this is the only place we can block them. Reaching them is how an agent
// steals instance credentials.
const BLOCKED_HOSTS = ['169.254.169.254', '169.254.169.253', '100.100.100.200'];

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV4_CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const IPV6_RE = /^[0-9a-f:]+$/i;

function isValidHostEntry(entry) {
  const h = String(entry || '').trim();
  if (!h) return false;
  if (IPV4_RE.test(h)) {
    return h.split('.').every((o) => Number(o) >= 0 && Number(o) <= 255);
  }
  if (IPV4_CIDR_RE.test(h)) {
    const [ip, bits] = h.split('/');
    return ip.split('.').every((o) => Number(o) >= 0 && Number(o) <= 255) && Number(bits) >= 1 && Number(bits) <= 32;
  }
  return IPV6_RE.test(h) && h.length > 2;
}

function normalizePorts(ports) {
  const out = [];
  for (const p of (Array.isArray(ports) ? ports : [])) {
    const n = parseInt(p, 10);
    if (n >= 1 && n <= 65535 && !out.includes(n)) out.push(n);
  }
  return out.sort((a, b) => a - b);
}

// Pure rule generation. Returns an array of pf anchor rule lines.
function buildAnchorRules(opts) {
  const allowPorts = normalizePorts(opts && opts.allowPorts);
  const allowHosts = (Array.isArray(opts && opts.allowHosts) ? opts.allowHosts : [])
    .map((h) => String(h).trim())
    .filter(isValidHostEntry);
  const rules = [
    '# Auren OS-level terminal/network guard (auto-generated).',
    '# Allow rules precede block rules (pf evaluates first-match wins).',
    'pass in  on lo0 all',
    'pass out on lo0 all',
    'pass out proto { tcp udp } to port 53',
    'pass out proto tcp to port 80',
    'pass out proto tcp to port 443'
  ];
  for (const p of allowPorts) rules.push('pass out proto { tcp udp } to port ' + p);
  for (const h of allowHosts) rules.push('pass out proto { tcp udp } to ' + h);
  rules.push('block out proto icmp');
  rules.push('block out proto icmp6');
  if (BLOCKED_PORTS.length) rules.push('block out proto { tcp udp } to port { ' + BLOCKED_PORTS.join(' ') + ' }');
  for (const h of BLOCKED_HOSTS) rules.push('block out proto { tcp udp } to ' + h);
  return rules;
}

function pfctl(args) {
  return spawnSync(PFCTL, args, { encoding: 'utf8' });
}

// Returns { enabled: boolean } — whether pf itself is running at all.
function status() {
  const r = pfctl(['-s', 'info']);
  return { enabled: r.status === 0 && /^Status:\s*Enabled/m.test((r.stdout || '') + (r.stderr || '')) };
}

// Load (or reload) the auren anchor from a rules file. Idempotent; safe to run
// on every reconcile — pfctl is cheap and re-inserting the same anchor is a
// no-op apart from a brief rule flush.
function applyAnchor(rulesFile) {
  try {
    const content = fs.readFileSync(rulesFile, 'utf8');
    if (!content || content.trim().length === 0) return { ok: false, error: 'empty rules file' };
  } catch (err) {
    return { ok: false, error: 'rules file unreadable: ' + err.message };
  }
  const steps = [
    ['-e'],
    ['-a', ANCHOR, '-F', 'all'],
    ['-A', ANCHOR, '-f', rulesFile]
  ];
  for (const args of steps) {
    const r = pfctl(args);
    if (r.status !== 0) {
      const msg = (r.stderr || r.stdout || '').trim();
      return { ok: false, error: 'pfctl ' + args.join(' ') + ' failed' + (msg ? ': ' + msg : '') };
    }
  }
  const check = pfctl(['-a', ANCHOR, '-sr']);
  if (check.status !== 0 || !String(check.stdout || '').trim()) {
    return { ok: false, error: 'anchor rules did not load (nothing present)' };
  }
  return { ok: true };
}

// Remove the auren anchor's rules. pf itself stays enabled (see SAFETY
// CONTRACT); an enabled pf with no rules passes everything.
function clearAnchor() {
  const r = pfctl(['-a', ANCHOR, '-F', 'all']);
  return r.status === 0 ? { ok: true } : { ok: false, error: (r.stderr || r.stdout || '').trim() || 'pfctl flush failed' };
}

function isAnchorLoaded() {
  const r = pfctl(['-a', ANCHOR, '-sr']);
  return r.status === 0 && String(r.stdout || '').trim().length > 0;
}

module.exports = {
  ANCHOR,
  BLOCKED_PORTS,
  BLOCKED_HOSTS,
  isValidHostEntry,
  normalizePorts,
  buildAnchorRules,
  status,
  applyAnchor,
  clearAnchor,
  isAnchorLoaded
};
