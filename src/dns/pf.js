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
// 853 dot (DNS-over-TLS), 1080 socks proxy, 3389 rdp, 5900 vnc.
const BLOCKED_PORTS = [21, 22, 23, 25, 110, 135, 137, 138, 139, 143, 445, 465, 587, 853, 993, 995, 1080, 3389, 5900];

// Cloud-instance metadata endpoints. Never reachable via DNS (they are IPs),
// so this is the only place we can block them. Reaching them is how an agent
// steals instance credentials.
const BLOCKED_HOSTS = ['169.254.169.254', '169.254.169.253', '100.100.100.200'];

// Known public DNS-over-HTTPS / DNS-over-TLS endpoints (IPv4 + common IPv6),
// blocked at the IP layer. DoH/DoT always bypasses the local resolver (Auren),
// so blocking the well-known servers closes the most common bypass path. This
// is a best-effort blocklist — a complete catalog of every DoH/DoT server on
// the internet is not possible (see README "Honest limits"). Operators can
// override it via settings.json (dohEndpoints) or config.json (dohHosts).
const DEFAULT_DOH_HOSTS = [
  '1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001', // Cloudflare
  '8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844', // Google
  '9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9', // Quad9
  '45.90.28.190', '45.90.30.190', // NextDNS
  '94.140.14.14', '94.140.15.15', '2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff' // AdGuard
];

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

// Header comment lines precede the real rules in buildAnchorRules' output.
// Keep them in sync with the builder below — they shift every rule index.
const HEADER_COMMENTS = [
  '# Auren OS-level terminal/network guard (auto-generated).',
  '# Allow rules precede block rules (pf evaluates first-match wins).'
];

// Resolve the allow/DoH inputs exactly as buildAnchorRules will lay them out,
// and report where the DoH block rules land in the final rule array. Pure.
// The daemon uses dohBlockRange() to watch pf packet counters for those rules,
// so it must never drift from what buildAnchorRules() actually emitted.
function ruleLayout(opts) {
  const allowPorts = normalizePorts(opts && opts.allowPorts);
  const allowHosts = (Array.isArray(opts && opts.allowHosts) ? opts.allowHosts : [])
    .map((h) => String(h).trim())
    .filter(isValidHostEntry);
  const dohBlock = (opts && opts.dohBlock) !== false;
  const proxyBlock = (opts && opts.proxyBlock) !== false;
  let dohHosts = (Array.isArray(opts && opts.dohHosts) ? opts.dohHosts : [])
    .map((h) => String(h).trim())
    .filter(isValidHostEntry);
  if (dohBlock && dohHosts.length === 0) dohHosts = DEFAULT_DOH_HOSTS.slice();
  // Header comments, then the two lo0 passes, then allowlisted ports, then
  // allowlisted hosts, then the DoH block rules.
  const dohStart = HEADER_COMMENTS.length + 2 + allowPorts.length + allowHosts.length;
  return { allowPorts, allowHosts, dohBlock, dohHosts, proxyBlock, dohStart };
}

// Index range (into buildAnchorRules' output) of the DoH block rules, or null
// when DoH blocking is disabled. Uses the same layout logic as the builder.
function dohBlockRange(opts) {
  const { dohBlock, dohHosts, dohStart } = ruleLayout(opts);
  if (!dohBlock || dohHosts.length === 0) return null;
  return { start: dohStart, count: dohHosts.length };
}

// True when the CIDR covers the given IPv4 address. Used by the safety floor to
// drop allowlist entries that would carve out a blocked IP via a range
// (e.g. 169.254.0.0/16 over the metadata endpoints, or 1.1.1.0/24 over
// Cloudflare DoH).
function cidrContainsIp(cidr, ip) {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(String(cidr || ''));
  if (!m) return false;
  const bits = Number(m[2]);
  if (!(bits >= 1 && bits <= 32)) return false;
  const octets = (s) => s.split('.').map(Number);
  const net = octets(m[1]);
  const host = octets(ip);
  let n = 0;
  let h = 0;
  for (let i = 0; i < 4; i++) {
    n = (n << 8) | net[i];
    h = (h << 8) | host[i];
  }
  const mask = bits === 32 ? 0xffffffff : ((~0) << (32 - bits)) >>> 0;
  return (n & mask) === (h & mask);
}

// Minimum-safety floor, enforced by the ROOT daemon while Protection is ON.
//
// The terminal/DoH tunables reach the daemon through a signed config that a
// same-user process can forge (auren.key is user-readable), so the daemon must
// not trust them blindly. This floor is compiled into the root-owned daemon and
// cannot be weakened by anything the user account writes or signs:
//   - terminalBlock / dohBlock can never be disabled while the anchor is loaded;
//   - the allowlist is additive ONLY — any entry that carves out a built-in
//     blocked port (BLOCKED_PORTS), a cloud-metadata endpoint, or a DoH
//     endpoint (or a CIDR containing one) is dropped;
//   - dohHosts EXTENDS the built-in list (union), so an override can never
//     shrink DoH coverage.
// Returns the sanitized inputs plus `changed` (true when anything was dropped
// or forced). Pure and unit-testable.
function safetyFloor(opts) {
  const inTerminalBlock = (opts && opts.terminalBlock) !== false;
  const inProxyBlock = (opts && opts.proxyBlock) !== false;
  const inAllowPorts = normalizePorts(opts && opts.allowPorts);
  const inAllowHosts = (Array.isArray(opts && opts.allowHosts) ? opts.allowHosts : [])
    .map((h) => String(h).trim())
    .filter(isValidHostEntry);
  const inDohBlock = (opts && opts.dohBlock) !== false;
  const inDohHosts = (Array.isArray(opts && opts.dohHosts) ? opts.dohHosts : [])
    .map((h) => String(h).trim())
    .filter(isValidHostEntry);

  const dohUnion = Array.from(new Set(DEFAULT_DOH_HOSTS.concat(inDohHosts)));
  const protectedHosts = BLOCKED_HOSTS.concat(dohUnion);

  // While HTTPS host blocking (proxyBlock) is enforced, QUIC (UDP 443) must
  // stay blocked so HTTPS falls back to TCP and therefore through the proxy.
  // A port-443 allow entry would pass UDP 443 too and silently bypass that.
  // The floor always re-forces proxyBlock on while protection is on, so 443 is
  // dropped from the allowlist unconditionally here.
  const outAllowPorts = inAllowPorts.filter((p) => !BLOCKED_PORTS.includes(p) && p !== 443);
  const outAllowHosts = inAllowHosts.filter((h) => {
    if (protectedHosts.includes(h)) return false;
    return !protectedHosts.some((ip) => cidrContainsIp(h, ip));
  });
  const outDohHosts = dohUnion;

  const changed =
    !inTerminalBlock || !inDohBlock || !inProxyBlock ||
    inAllowPorts.length !== outAllowPorts.length ||
    inAllowHosts.length !== outAllowHosts.length ||
    JSON.stringify(inDohHosts) !== JSON.stringify(outDohHosts);

  return {
    terminalBlock: true,
    dohBlock: true,
    proxyBlock: true,
    allowPorts: outAllowPorts,
    allowHosts: outAllowHosts,
    dohHosts: outDohHosts,
    changed: !!changed
  };
}

// Pure rule generation. Returns an array of pf anchor rule lines.
function buildAnchorRules(opts) {
  const { allowPorts, allowHosts, dohBlock, dohHosts, proxyBlock } = ruleLayout(opts);
  const rules = HEADER_COMMENTS.slice();
  rules.push('pass in  on lo0 all');
  rules.push('pass out on lo0 all');
  for (const p of allowPorts) rules.push('pass out proto { tcp udp } to port ' + p);
  for (const h of allowHosts) rules.push('pass out proto { tcp udp } to ' + h);
  if (dohBlock) {
    for (const h of dohHosts) rules.push('block out proto { tcp udp } to ' + h);
  }
  rules.push('pass out proto { tcp udp } to port 53');
  rules.push('pass out proto tcp to port 80');
  rules.push('pass out proto tcp to port 443');
  // QUIC (HTTP/3) runs over UDP 443 and bypasses both DNS and the HTTPS proxy.
  // While HTTPS host blocking is on, UDP 443 is dropped so HTTPS falls back to
  // TCP — which the PAC routes through the blocking proxy.
  if (proxyBlock) rules.push('block out proto udp to port 443');
  rules.push('block out proto icmp');
  rules.push('block out proto icmp6');
  if (BLOCKED_PORTS.length) rules.push('block out proto { tcp udp } to port { ' + BLOCKED_PORTS.join(' ') + ' }');
  for (const h of BLOCKED_HOSTS) rules.push('block out proto { tcp udp } to ' + h);
  return rules;
}

// Parse `pfctl -a auren -vsr` output into per-rule packet counters, in rule
// order (one entry per rule block, INCLUDING zeroed rules, so array indices
// align with rule indices — the daemon maps DoH rules by index). Format on
// macOS:
//   @0 pass in on lo0 all
//     [ Evaluations: 12 Packets: 300 Bytes: 10000 ]
function parsePfRuleStats(text) {
  const stats = [];
  const blocks = String(text || '').split(/\n\s*\n/);
  for (const block of blocks) {
    if (!block.trim()) continue;
    const m = block.match(/\[\s*Evaluations:\s*(\d+)\s+Packets:\s*(\d+)\s+Bytes:\s*(\d+)\s*\]/);
    if (m) {
      stats.push({ evaluations: Number(m[1]), packets: Number(m[2]), bytes: Number(m[3]) });
    } else if (/^(?:@\d+\s+)?(?:pass|block|rdr|match|no|anchor|nat)\b/.test(block.trim())) {
      stats.push({ evaluations: 0, packets: 0, bytes: 0 });
    }
  }
  return stats;
}

// The pfctl binary is injectable (AUREN_PFCTL) so the test suite can exercise
// the anchor load/clear flow with a fake binary instead of requiring root.
function pfctl(args) {
  return spawnSync(process.env.AUREN_PFCTL || PFCTL, args, { encoding: 'utf8' });
}

// Per-rule counters for the auren anchor (see parsePfRuleStats).
function ruleStats() {
  const r = pfctl(['-a', ANCHOR, '-vsr']);
  if (r.status !== 0) return { ok: false, error: (r.stderr || r.stdout || '').trim() || 'pfctl -vsr failed' };
  return { ok: true, stats: parsePfRuleStats(r.stdout || '') };
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
  // `pfctl -e` only when pf is not already enabled. On macOS an already-running
  // pf makes `-e` exit non-zero with "pf already enabled" (plus ALTQ warnings
  // on Apple Silicon), which used to fail the whole anchor load forever — the
  // rules were never inserted and the daemon retried every poll.
  const steps = [];
  if (!status().enabled) steps.push(['-e']);
  steps.push(['-a', ANCHOR, '-F', 'all']);
  steps.push(['-a', ANCHOR, '-f', rulesFile]);
  for (const args of steps) {
    const r = pfctl(args);
    if (r.status !== 0) {
      const msg = (r.stderr || r.stdout || '').trim();
      // Belt-and-suspenders: even if the status pre-check raced or misread the
      // info output, "pf already enabled" is not a failure — the anchor load
      // can proceed against an enabled pf.
      if (args[0] === '-e' && /already enabled/i.test(msg)) continue;
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
  DEFAULT_DOH_HOSTS,
  isValidHostEntry,
  normalizePorts,
  buildAnchorRules,
  ruleLayout,
  dohBlockRange,
  cidrContainsIp,
  safetyFloor,
  parsePfRuleStats,
  ruleStats,
  status,
  applyAnchor,
  clearAnchor,
  isAnchorLoaded
};

// Windows: the same pure rule engine + safety floor, but enforcement is
// Windows Firewall, not pfctl. Swapped in after module.exports is set so
// pf-win.js can require('./pf') for the shared pure functions without a
// circular-require deadlock.
if (process.platform === 'win32') {
  Object.assign(module.exports, require('./pf-win'));
}
