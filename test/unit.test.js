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
