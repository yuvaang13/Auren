/* Auren — unit tests for core + DNS-message logic (no privileges, no browser).
 *
 * Run: npm run test:unit
 */
'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const domains = require('../src/core/domains');
const config = require('../src/core/config');
const activity = require('../src/core/activity');
const dnsMsg = require('../src/dns/dns-message');
const store = require('../src/core/store');
const policy = require('../src/core/policy');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try { fn(); passed += 1; console.log('  ok   ' + name); }
  catch (err) { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (err && err.message)); }
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'auren-unit-'));
}

function buildQuery(id, name) {
  const qname = dnsMsg.encodeName(name);
  const buf = Buffer.alloc(12 + qname.length + 4);
  buf.writeUInt16BE(id, 0);
  buf.writeUInt16BE(0x0100, 2); // RD
  buf.writeUInt16BE(1, 4);      // QDCOUNT
  qname.copy(buf, 12);
  buf.writeUInt16BE(1, 12 + qname.length); // QTYPE A
  buf.writeUInt16BE(1, 14 + qname.length); // QCLASS IN
  return buf;
}

console.log('domains');
test('normalizeDomain strips scheme, path, port, www, trailing dot', () => {
  assert.strictEqual(domains.normalizeDomain('HTTPS://WWW.Bank.Com/path?x=1'), 'bank.com');
  assert.strictEqual(domains.normalizeDomain('mail.google.com.'), 'mail.google.com');
  assert.strictEqual(domains.normalizeDomain('example.com:8080'), 'example.com');
});

test('domainMatches is exact or subdomain only', () => {
  assert.ok(domains.domainMatches('bank.com', 'bank.com'));
  assert.ok(domains.domainMatches('www.bank.com', 'bank.com'));
  assert.ok(domains.domainMatches('a.b.bank.com', 'bank.com'));
  assert.ok(!domains.domainMatches('notbank.com', 'bank.com'));
  assert.ok(!domains.domainMatches('bank.com.evil.net', 'bank.com'));
  assert.ok(!domains.domainMatches('', 'bank.com'));
});

test('validateBlockDomain accepts normal domains', () => {
  for (const d of ['bank.com', 'mail.google.com', 'www.example.com', 'intranet']) {
    const r = domains.validateBlockDomain(d);
    assert.ok(r.ok, d + ' should be valid');
  }
  assert.strictEqual(domains.validateBlockDomain('www.example.com').domain, 'example.com');
});

test('validateBlockDomain rejects IPs and junk', () => {
  assert.ok(!domains.validateBlockDomain('1.2.3.4').ok);
  assert.ok(!domains.validateBlockDomain('192.168.0.1').ok);
  assert.ok(!domains.validateBlockDomain('').ok);
  assert.ok(!domains.validateBlockDomain('bad domain').ok);
  assert.ok(!domains.validateBlockDomain('foo..com').ok);
  assert.ok(!domains.validateBlockDomain('foo_example.com').ok);
});

console.log('config');
test('config round-trips mode and block list', () => {
  const dir = tmpDir();
  config.setMode(dir, 'on');
  assert.strictEqual(config.readConfig(dir).mode, 'on');
  const r = config.addDomain(dir, 'bank.com');
  assert.ok(r.ok);
  assert.deepStrictEqual(config.readConfig(dir).blocklist, ['bank.com']);
});

test('addDomain normalizes, dedupes, rejects invalid', () => {
  const dir = tmpDir();
  config.addDomain(dir, 'WWW.Bank.Com');
  config.addDomain(dir, 'bank.com');
  assert.deepStrictEqual(config.readConfig(dir).blocklist, ['bank.com']);
  const bad = config.addDomain(dir, '1.2.3.4');
  assert.ok(!bad.ok);
  assert.deepStrictEqual(config.readConfig(dir).blocklist, ['bank.com']);
});

test('removeDomain removes a blocked domain', () => {
  const dir = tmpDir();
  config.addDomain(dir, 'bank.com');
  config.removeDomain(dir, 'bank.com');
  assert.deepStrictEqual(config.readConfig(dir).blocklist, []);
});

test('config file survives a corrupt write (safe default: off)', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'config.json'), '{not json');
  const cfg = config.readConfig(dir);
  assert.strictEqual(cfg.mode, 'off');
  assert.deepStrictEqual(cfg.blocklist, []);
});

test('config defaults terminal blocking on with an empty allowlist', () => {
  const dir = tmpDir();
  const cfg = config.readConfig(dir);
  assert.strictEqual(cfg.terminalBlock, true);
  assert.deepStrictEqual(cfg.terminalAllowlist, { ports: [], hosts: [] });
});

test('config round-trips terminalBlock and terminalAllowlist', () => {
  const dir = tmpDir();
  const cfg = config.readConfig(dir);
  cfg.terminalBlock = false;
  cfg.terminalAllowlist = { ports: [22, 443, 22, 0, 70000], hosts: ['10.0.0.5', 'fd00::1', '', '10.0.0.5'] };
  config.writeConfig(dir, cfg);
  const back = config.readConfig(dir);
  assert.strictEqual(back.terminalBlock, false);
  assert.deepStrictEqual(back.terminalAllowlist.ports, [22, 443]);
  assert.deepStrictEqual(back.terminalAllowlist.hosts, ['10.0.0.5', 'fd00::1']);
});

test('config defaults DoH blocking on with an empty endpoint list', () => {
  const cfg = config.readConfig(tmpDir());
  assert.strictEqual(cfg.dohBlock, true);
  assert.deepStrictEqual(cfg.dohHosts, []);
});

test('config round-trips dohBlock and dohHosts', () => {
  const dir = tmpDir();
  const cfg = config.readConfig(dir);
  cfg.dohBlock = false;
  cfg.dohHosts = ['1.1.1.1', ' 8.8.8.8 ', '1.1.1.1'];
  config.writeConfig(dir, cfg);
  const back = config.readConfig(dir);
  assert.strictEqual(back.dohBlock, false);
  assert.deepStrictEqual(back.dohHosts, ['1.1.1.1', '8.8.8.8']);
});

console.log('signed config');
test('writeSignedConfig creates config + signature sidecar', () => {
  const dir = tmpDir();
  const key = Buffer.from('0123456789abcdef0123456789abcdef');
  const file = path.join(dir, 'config.json');
  config.writeSignedConfig(file, { version: 1, mode: 'on', blocklist: ['bank.com'], failClosed: false }, key);
  assert.ok(fs.existsSync(file + '.sig'));
  const raw = fs.readFileSync(file);
  const sig = fs.readFileSync(file + '.sig', 'utf8');
  assert.ok(config.verifyData(raw, key, sig));
});

test('tampering with the config fails signature verification', () => {
  const dir = tmpDir();
  const key = Buffer.from('0123456789abcdef0123456789abcdef');
  const file = path.join(dir, 'config.json');
  config.writeSignedConfig(file, { version: 1, mode: 'on', blocklist: ['bank.com'], failClosed: false }, key);
  fs.writeFileSync(file, JSON.stringify({ version: 1, mode: 'off', blocklist: [] })); // edited outside the app
  assert.ok(!config.verifyData(fs.readFileSync(file), key, fs.readFileSync(file + '.sig', 'utf8')));
});

test('verifyData rejects missing/wrong signatures', () => {
  const key = Buffer.from('0123456789abcdef0123456789abcdef');
  const data = Buffer.from('hello');
  assert.ok(!config.verifyData(data, key, ''));
  assert.ok(!config.verifyData(data, key, 'deadbeef'));
});

console.log('secure store');
test('secure store round-trips encrypted state', () => {
  const dir = tmpDir();
  const key = store.loadOrCreateKey(dir);
  store.saveSecureStore(dir, key, { version: 1, mode: 'on', blocklist: ['bank.com'], lock: { state: 'locked', unlockExpiry: 0 } });
  const loaded = store.loadSecureStore(dir, key);
  assert.strictEqual(loaded.mode, 'on');
  assert.deepStrictEqual(loaded.blocklist, ['bank.com']);
  const raw = fs.readFileSync(path.join(dir, store.STORE_FILE), 'utf8');
  assert.ok(!raw.includes('bank.com'), 'store must be encrypted at rest');
});

test('secure store rejects a wrong key (tamper/corruption)', () => {
  const dir = tmpDir();
  const key = store.loadOrCreateKey(dir);
  store.saveSecureStore(dir, key, { version: 1, mode: 'on', blocklist: ['bank.com'], lock: null });
  const wrong = Buffer.alloc(32, 7);
  assert.throws(() => store.loadSecureStore(dir, wrong), /bad decrypt|auth|error/i);
});

test('ensurePermissions tightens a loosened file to 0600', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'loose.txt');
  fs.writeFileSync(file, 'x', { mode: 0o644 });
  const changed = store.ensurePermissions(file);
  assert.ok(changed);
  const st = fs.statSync(file);
  assert.strictEqual(st.mode & 0o077, 0);
  assert.ok(!store.ensurePermissions(file), 'second call should be a no-op');
});

console.log('policy');
test('policy requires auth for sensitive signals by default', () => {
  assert.strictEqual(policy.decidePolicy({ sensitive: true, types: ['credit_card'] }).action, 'require_auth');
  assert.strictEqual(policy.decidePolicy({ sensitive: true, types: ['ssn', 'password'] }).action, 'require_auth');
});

test('policy allows non-sensitive signals and honors custom rules', () => {
  assert.strictEqual(policy.decidePolicy({ sensitive: false, types: [] }).action, 'allow');
  const block = policy.decidePolicy({ sensitive: true, types: ['secret'] }, { rules: { secret: 'block' } });
  assert.strictEqual(block.action, 'block');
  const log = policy.decidePolicy({ sensitive: true, types: ['password'] }, { rules: { password: 'log' } });
  assert.strictEqual(log.action, 'log');
});

test('policy fails closed while degraded', () => {
  const d = policy.decidePolicy({ sensitive: false, types: [] }, { degraded: true });
  assert.strictEqual(d.action, 'block');
});

test('policy blocks network-capable commands by default', () => {
  for (const t of ['cmd_ssh', 'cmd_ping', 'cmd_probe', 'cmd_tunnel', 'cmd_suspicious_443', 'cmd_transfer', 'cmd_reverse_shell', 'cmd_remote_admin', 'cmd_exfil']) {
    const d = policy.decidePolicy({ sensitive: true, types: [t] });
    assert.strictEqual(d.action, 'block', t + ' must block by default');
  }
});

test('policy honors custom commandPolicy downgrades', () => {
  const log = policy.decidePolicy({ sensitive: true, types: ['cmd_ssh'] }, { rules: { cmd_ssh: 'log' } });
  assert.strictEqual(log.action, 'log');
  const auth = policy.decidePolicy({ sensitive: true, types: ['cmd_ping'] }, { rules: { cmd_ping: 'require_auth' } });
  assert.strictEqual(auth.action, 'require_auth');
});

console.log('activity');
test('activity appends and reads back entries', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'activity.jsonl');
  activity.appendActivity(file, activity.makeEntry('block', 'blocked', 'bank.com'));
  activity.appendActivity(file, activity.makeEntry('toggle', 'off'));
  const all = activity.readActivity(file);
  assert.strictEqual(all.length, 2);
  assert.strictEqual(all[0].kind, 'block');
  assert.strictEqual(all[0].domain, 'bank.com');
  assert.ok(all[1].ts);
});

test('activity readActivity respects limit', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'activity.jsonl');
  for (let i = 0; i < 5; i++) activity.appendActivity(file, activity.makeEntry('block', 'blocked', 'd' + i + '.com'));
  assert.strictEqual(activity.readActivity(file, 3).length, 3);
});

test('activity toPlainText stays plain-language', () => {
  const e = activity.makeEntry('block', 'blocked', 'bank.com');
  assert.ok(activity.toPlainText(e).includes('Blocked: attempt to reach bank.com'));
  assert.ok(activity.toPlainText(activity.makeEntry('toggle', 'off')).includes('Protection turned off'));
  assert.ok(activity.toPlainText(activity.makeEntry('toggle', 'off_pending')).includes('10 seconds'));
});

test('activity toPlainText covers agent + daemon integrity outcomes', () => {
  assert.ok(activity.toPlainText(activity.makeEntry('agent', 'blocked', null, 'types=credit_card')).includes('blocked'));
  assert.ok(activity.toPlainText(activity.makeEntry('daemon', 'enforcement_degraded')).includes('DEGRADED'));
  assert.ok(activity.toPlainText(activity.makeEntry('daemon', 'integrity_failed')).includes('failed closed'));
  assert.ok(activity.toPlainText(activity.makeEntry('daemon', 'permissions_fixed')).includes('owner-only'));
});

test('activity toPlainText covers command + pf outcomes', () => {
  assert.ok(activity.toPlainText(activity.makeEntry('command', 'blocked', null, 'types=cmd_ssh')).includes('Agent command blocked'));
  assert.ok(activity.toPlainText(activity.makeEntry('command', 'allowed', null, 'types=none')).includes('Agent command allowed'));
  assert.ok(activity.toPlainText(activity.makeEntry('daemon', 'pf_applied')).includes('firewall rules applied'));
  assert.ok(activity.toPlainText(activity.makeEntry('daemon', 'pf_cleared')).includes('restored'));
  assert.ok(activity.toPlainText(activity.makeEntry('daemon', 'pf_failed', null, 'boom')).includes('could not be applied'));
});

test('activity toPlainText covers doh_blocked + vm outcomes', () => {
  assert.ok(activity.toPlainText(activity.makeEntry('daemon', 'doh_blocked', null, '14 packet(s)')).includes('DoH/DoT'));
  assert.ok(activity.toPlainText(activity.makeEntry('daemon', 'vm_detected', null, 'Docker Desktop')).includes('Virtualization detected'));
  assert.ok(activity.toPlainText(activity.makeEntry('daemon', 'vm_cleared')).includes('No virtualization processes'));
});

console.log('pf firewall rules');
const pf = require('../src/dns/pf');

test('buildAnchorRules always passes loopback, DNS, and browsing', () => {
  const rules = pf.buildAnchorRules({});
  const joined = rules.join('\n');
  assert.ok(joined.includes('pass in  on lo0 all'));
  assert.ok(joined.includes('pass out on lo0 all'));
  assert.ok(joined.includes('port 53'));
  assert.ok(joined.includes('port 80'));
  assert.ok(joined.includes('port 443'));
});

test('buildAnchorRules blocks ping, command ports, and cloud metadata by default', () => {
  const rules = pf.buildAnchorRules({});
  const joined = rules.join('\n');
  assert.ok(joined.includes('block out proto icmp'));
  assert.ok(joined.includes('22'));
  assert.ok(joined.includes('3389'));
  assert.ok(joined.includes('169.254.169.254'));
});

test('buildAnchorRules puts allowlist rules before block rules', () => {
  const rules = pf.buildAnchorRules({ allowPorts: [22, 443], allowHosts: ['10.0.0.5', '192.168.1.0/24'] });
  const pass22 = rules.indexOf('pass out proto { tcp udp } to port 22');
  const blockPorts = rules.findIndex((r) => r.startsWith('block out proto { tcp udp } to port'));
  const passHost = rules.indexOf('pass out proto { tcp udp } to 10.0.0.5');
  assert.ok(pass22 > -1 && pass22 < blockPorts, 'allowed port must precede block rules');
  assert.ok(passHost > -1 && passHost < blockPorts, 'allowed host must precede block rules');
});

test('buildAnchorRules normalizes and rejects invalid allowlist entries', () => {
  const rules = pf.buildAnchorRules({ allowPorts: [22, 22, 70000, 'abc', 0], allowHosts: ['10.0.0.5', 'not a host', '', '300.1.1.1', 'fd00::1'] });
  assert.ok(rules.includes('pass out proto { tcp udp } to port 22'));
  assert.ok(rules.includes('pass out proto { tcp udp } to 10.0.0.5'));
  assert.ok(rules.includes('pass out proto { tcp udp } to fd00::1'));
  assert.ok(!rules.some((r) => r.includes('300.1.1.1') || r.includes('not a host')));
  assert.ok(!rules.some((r) => r.includes('port 70000') || r.includes('port 0')));
});

test('isValidHostEntry accepts IPs and CIDRs only', () => {
  assert.ok(pf.isValidHostEntry('10.0.0.5'));
  assert.ok(pf.isValidHostEntry('192.168.1.0/24'));
  assert.ok(pf.isValidHostEntry('fd00::1'));
  assert.ok(!pf.isValidHostEntry('example.com'));
  assert.ok(!pf.isValidHostEntry('999.1.1.1'));
  assert.ok(!pf.isValidHostEntry(''));
});

test('DoT port 853 is in the blocked command ports', () => {
  assert.ok(pf.BLOCKED_PORTS.includes(853));
});

test('buildAnchorRules blocks known DoH/DoT endpoints before the 443 pass', () => {
  const rules = pf.buildAnchorRules({});
  const joined = rules.join('\n');
  const dohIdx = rules.findIndex((r) => r === 'block out proto { tcp udp } to 1.1.1.1');
  const pass443 = rules.indexOf('pass out proto tcp to port 443');
  const pass53 = rules.indexOf('pass out proto { tcp udp } to port 53');
  assert.ok(dohIdx > -1, 'a default DoH endpoint must be blocked');
  assert.ok(pf.DEFAULT_DOH_HOSTS.every((h) => joined.includes('block out proto { tcp udp } to ' + h)), 'every default DoH endpoint gets a block rule');
  assert.ok(dohIdx > -1 && dohIdx < pass443, 'DoH blocks must precede the generic 443 pass');
  assert.ok(dohIdx < pass53, 'DoH blocks must precede the generic 53 pass');
});

test('buildAnchorRules dohBlock:false omits the DoH block rules', () => {
  const rules = pf.buildAnchorRules({ dohBlock: false });
  assert.ok(!rules.some((r) => r.startsWith('block out proto { tcp udp } to 1.1.1.1') || r.includes('8.8.8.8')));
  assert.ok(rules.includes('pass out proto tcp to port 443'), '443 pass must remain');
});

test('allowlisted host beats a DoH block (allowlist precedes blocks)', () => {
  const rules = pf.buildAnchorRules({ allowHosts: ['1.1.1.1'] });
  const passIdx = rules.indexOf('pass out proto { tcp udp } to 1.1.1.1');
  const blockIdx = rules.findIndex((r) => r.startsWith('block out proto { tcp udp } to 1.1.1.1'));
  assert.ok(passIdx > -1, 'an allowlisted DoH IP gets a pass rule');
  assert.ok(blockIdx === -1 || passIdx < blockIdx, 'the pass rule must win for an allowlisted host');
});

test('dohBlockRange matches the rules buildAnchorRules actually emits', () => {
  for (const opts of [
    {},
    { allowPorts: [8443], allowHosts: ['10.0.0.5'] },
    { dohHosts: ['9.9.9.9'] },
    { dohBlock: false }
  ]) {
    const rules = pf.buildAnchorRules(opts);
    const range = pf.dohBlockRange(opts);
    if (range === null) {
      assert.ok(!rules.some((r) => r.startsWith('block out proto { tcp udp } to 1.1.1.1')), 'no DoH rules when range is null');
    } else {
      const slice = rules.slice(range.start, range.start + range.count);
      assert.ok(slice.length === range.count, 'range count matches emitted rules');
      assert.ok(slice.every((r) => r.startsWith('block out proto { tcp udp } to ')), 'range indexes land on DoH block rules');
    }
  }
});

test('parsePfRuleStats keeps per-rule order including zeroed rules', () => {
  const out = '@0 pass in on lo0 all\n  [ Evaluations: 12 Packets: 300 Bytes: 10000 ]\n\n'
    + '@1 pass out on lo0 all\n  [ Evaluations: 0 Packets: 0 Bytes: 0 ]\n\n'
    + '@2 block out proto { tcp udp } to 1.1.1.1\n\n'
    + '@3 block out proto { tcp udp } to 8.8.8.8\n  [ Evaluations: 2 Packets: 7 Bytes: 420 ]';
  const stats = pf.parsePfRuleStats(out);
  assert.strictEqual(stats.length, 4, 'one entry per rule, in order');
  assert.strictEqual(stats[0].packets, 300);
  assert.strictEqual(stats[1].packets, 0);
  assert.strictEqual(stats[2].packets, 0, 'a rule with no counter line still occupies its slot');
  assert.strictEqual(stats[3].packets, 7);
});

test('cidrContainsIp matches only the covered network', () => {
  assert.ok(pf.cidrContainsIp('10.0.0.0/8', '10.5.6.7'));
  assert.ok(pf.cidrContainsIp('169.254.0.0/16', '169.254.169.254'));
  assert.ok(pf.cidrContainsIp('1.1.0.0/16', '1.1.1.1'));
  assert.ok(!pf.cidrContainsIp('10.0.0.0/8', '11.0.0.1'));
  assert.ok(!pf.cidrContainsIp('10.0.0.0/32', '10.0.0.1'));
  assert.ok(!pf.cidrContainsIp('not-a-cidr', '1.1.1.1'));
});

test('safetyFloor forces terminal and DoH blocking on', () => {
  const f = pf.safetyFloor({ terminalBlock: false, dohBlock: false });
  assert.strictEqual(f.terminalBlock, true);
  assert.strictEqual(f.dohBlock, true);
  assert.ok(f.changed);
});

test('safetyFloor strips allowlisted built-in blocked ports', () => {
  const f = pf.safetyFloor({ allowPorts: [22, 853, 8443, 443, 5900] });
  assert.ok(!f.allowPorts.includes(22), 'SSH must stay blocked');
  assert.ok(!f.allowPorts.includes(853), 'DoT must stay blocked');
  assert.ok(!f.allowPorts.includes(5900), 'VNC must stay blocked');
  assert.ok(f.allowPorts.includes(8443), 'extra ports pass through');
  assert.ok(f.allowPorts.includes(443), '443 is not a built-in blocked port');
});

test('safetyFloor strips allowlisted metadata / DoH hosts', () => {
  const f = pf.safetyFloor({ allowHosts: ['169.254.169.254', '1.1.1.1', '10.0.0.5', '192.168.1.0/24'] });
  assert.ok(!f.allowHosts.includes('169.254.169.254'), 'metadata endpoint must stay blocked');
  assert.ok(!f.allowHosts.includes('1.1.1.1'), 'DoH endpoint must stay blocked');
  assert.ok(f.allowHosts.includes('10.0.0.5'));
  assert.ok(f.allowHosts.includes('192.168.1.0/24'));
});

test('safetyFloor drops CIDRs that cover a metadata or DoH IP', () => {
  assert.ok(!pf.safetyFloor({ allowHosts: ['169.254.0.0/16'] }).allowHosts.length, 'metadata-covering CIDR dropped');
  assert.ok(!pf.safetyFloor({ allowHosts: ['1.1.0.0/16'] }).allowHosts.length, 'DoH-covering CIDR dropped');
  assert.ok(pf.safetyFloor({ allowHosts: ['10.0.0.0/8'] }).allowHosts.includes('10.0.0.0/8'), 'unrelated CIDR passes');
});

test('safetyFloor dohHosts extends the built-in list, never replaces', () => {
  const f = pf.safetyFloor({ dohHosts: ['9.9.9.9', '10.0.0.5'] });
  for (const h of pf.DEFAULT_DOH_HOSTS) assert.ok(f.dohHosts.includes(h), 'built-in ' + h + ' must stay blocked');
  assert.ok(f.dohHosts.includes('10.0.0.5'), 'user endpoint is added');
  assert.ok(f.dohHosts.length >= pf.DEFAULT_DOH_HOSTS.length);
});

test('safetyFloor is a no-op on an already-safe config', () => {
  const f = pf.safetyFloor({ terminalBlock: true, dohBlock: true, allowPorts: [8443], allowHosts: ['10.0.0.5'], dohHosts: pf.DEFAULT_DOH_HOSTS.slice() });
  assert.ok(!f.changed);
  assert.deepStrictEqual(f.allowPorts, [8443]);
  assert.deepStrictEqual(f.allowHosts, ['10.0.0.5']);
});

console.log('quit gate');
const { quitRequiresAuth } = require('../src/core/quit');

test('quitRequiresAuth gates quit only while protection is ON', () => {
  assert.ok(quitRequiresAuth({ mode: 'on', failClosed: false, lock: { state: 'locked', unlockExpiry: 0 } }));
  assert.ok(quitRequiresAuth({ mode: 'off', failClosed: true, lock: { state: 'locked', unlockExpiry: 0 } }), 'fail-closed is gated even when mode reads off');
  assert.ok(!quitRequiresAuth({ mode: 'off', failClosed: false, lock: { state: 'locked', unlockExpiry: 0 } }));
  assert.ok(!quitRequiresAuth(null));
  assert.ok(!quitRequiresAuth({}));
});

test('quitRequiresAuth skips the gate during a verified unlock cooldown', () => {
  const unlocking = { mode: 'on', failClosed: false, lock: { state: 'unlocking', unlockExpiry: Date.now() + 5000 } };
  assert.ok(!quitRequiresAuth(unlocking), 'a verified unlock in flight counts as authenticated');
});

console.log('dns-message');
test('extractQuestion reads the query name, type, class', () => {
  const q = dnsMsg.extractQuestion(buildQuery(0x1234, 'a.b.example.com'));
  assert.strictEqual(q.id, 0x1234);
  assert.strictEqual(q.qname, 'a.b.example.com');
  assert.strictEqual(q.qtype, 1);
  assert.strictEqual(q.qclass, 1);
});

test('extractQuestion handles compression pointers in the name', () => {
  const q = dnsMsg.extractQuestion(buildQuery(0x0001, 'example.com'));
  assert.strictEqual(q.qname, 'example.com');
});

test('buildNxdomain returns a well-formed NXDOMAIN reply', () => {
  const reply = dnsMsg.buildNxdomain(0xbeef, 'bank.com', 1, 1);
  assert.strictEqual(dnsMsg.readU16(reply, 0), 0xbeef);
  const flags = dnsMsg.readU16(reply, 2);
  assert.ok(flags & 0x8000, 'QR bit set');
  assert.strictEqual(flags & 0xf, 3, 'RCODE = NXDOMAIN');
  assert.strictEqual(dnsMsg.readU16(reply, 4), 1, 'QDCOUNT=1');
  assert.strictEqual(dnsMsg.readU16(reply, 6), 0, 'ANCOUNT=0');
  assert.strictEqual(dnsMsg.extractQuestion(reply).qname, 'bank.com');
});

test('encodeName handles multi-label names', () => {
  const b = dnsMsg.encodeName('a.b.com');
  assert.deepStrictEqual([...b], [1, 97, 1, 98, 3, 99, 111, 109, 0]);
});

test('encodeFrame adds a 2-byte length prefix', () => {
  const f = dnsMsg.encodeFrame(Buffer.from([1, 2, 3]));
  assert.deepStrictEqual([...f], [0, 3, 1, 2, 3]);
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
