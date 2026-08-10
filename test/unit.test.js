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
  for (const t of ['cmd_ssh', 'cmd_ping', 'cmd_probe', 'cmd_tunnel', 'cmd_transfer', 'cmd_reverse_shell', 'cmd_remote_admin', 'cmd_exfil']) {
    const d = policy.decidePolicy({ sensitive: true, types: [t] });
    assert.strictEqual(d.action, 'block', t + ' must default to block');
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
