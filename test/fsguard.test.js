/* Auren — FS Guard unit tests (no privileges, no browser). Run: node test/fsguard.test.js */
'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const pn = require('../src/core/path-normalize');
const fsg = require('../src/core/fsguard');

let passed = 0; let failed = 0;
function test(name, fn) {
  try { fn(); passed += 1; console.log('  ok   ' + name); }
  catch (e) { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (e && e.message)); console.error(e && e.stack && e.stack.split('\n').slice(1,3).join('\n')); }
}
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'auren-fs-')); }

console.log('path-normalize');
test('lexicalNormalize expands ~ and collapses // and trailing slash', () => {
  const home = os.homedir();
  assert.strictEqual(pn.lexicalNormalize('~/a//b/', 'posix'), path.posix.resolve(home, 'a/b'));
  assert.strictEqual(pn.lexicalNormalize('/tmp/foo/', 'posix'), '/tmp/foo');
  assert.strictEqual(pn.lexicalNormalize('/tmp/foo//bar', 'posix'), '/tmp/foo/bar');
});
test('lexicalNormalize rejects null byte and empty', () => {
  assert.strictEqual(pn.lexicalNormalize('a\0b', 'posix'), null);
  assert.strictEqual(pn.lexicalNormalize('  ', 'posix'), null);
});
test('lexicalNormalize resolves . and .. lexically', () => {
  assert.strictEqual(pn.lexicalNormalize('/a/b/../c/./d', 'posix'), '/a/c/d');
  assert.strictEqual(pn.lexicalNormalize('/workspace/../etc/passwd', 'posix'), '/etc/passwd');
});
test('canonicalize validates empty and null byte', () => {
  assert.ok(!pn.canonicalize('', {platform:'posix'}).ok);
  assert.ok(!pn.canonicalize('a\0b', {platform:'posix'}).ok);
  assert.ok(!pn.canonicalize('   ', {platform:'posix'}).ok);
});
test('canonicalize resolves symlink leaf via ancestor walk-up', () => {
  const d = fs.realpathSync(tmp());
  const real = path.join(d, 'real'); fs.mkdirSync(real);
  const link = path.join(d, 'link'); try { fs.symlinkSync(real, link); } catch { return; }
  const file = path.join(real, 'file.txt'); fs.writeFileSync(file, 'x');
  const viaLink = path.join(link, 'file.txt');
  const c = pn.canonicalize(viaLink);
  assert.ok(c.ok);
  const expected = fs.realpathSync(file);
  assert.strictEqual(c.canonical, expected);
  const missing = path.join(link, 'missing.txt');
  const m = pn.canonicalize(missing);
  assert.ok(m.ok);
  const realCanonical = fs.realpathSync(real);
  assert.strictEqual(m.canonical, path.join(realCanonical, 'missing.txt'));
});
test('isWithinMount is exact-or-prefix, not substring', () => {
  assert.ok(pn.isWithinMount('/a/b', '/a/b', 'posix'));
  assert.ok(pn.isWithinMount('/a/b/c/d', '/a/b', 'posix'));
  assert.ok(!pn.isWithinMount('/a/bc', '/a/b', 'posix'));
  assert.ok(!pn.isWithinMount('/a/b', '/a/b/c', 'posix'));
  assert.ok(!pn.isWithinMount('/x', '/a/b', 'posix'));
});
test('hasTraversalSequence detects .. segments after decode', () => {
  assert.ok(pn.hasTraversalSequence('a/../b'));
  assert.ok(pn.hasTraversalSequence('a%2F..%2Fb'));
  assert.ok(!pn.hasTraversalSequence('a/b/c'));
  assert.ok(!pn.hasTraversalSequence('a..b'));
});

console.log('fsguard forced exclusions');
test('isForcedExcluded blocks .env and .env.* basenames', () => {
  assert.ok(fsg.isForcedExcluded('/a/b/.env', 'posix').excluded);
  assert.ok(fsg.isForcedExcluded('/a/b/.env.local', 'posix').excluded);
  assert.ok(fsg.isForcedExcluded('/a/.env.example', 'posix').excluded);
  assert.ok(!fsg.isForcedExcluded('/a/b/env.txt', 'posix').excluded);
});
test('isForcedExcluded blocks key extensions', () => {
  assert.ok(fsg.isForcedExcluded('/a/x.pem', 'posix').excluded);
  assert.ok(fsg.isForcedExcluded('/a/x.key', 'posix').excluded);
  assert.ok(fsg.isForcedExcluded('/a/x.p12', 'posix').excluded);
  assert.ok(!fsg.isForcedExcluded('/a/x.txt', 'posix').excluded);
});
test('isForcedExcluded blocks sensitive dir segments', () => {
  assert.ok(fsg.isForcedExcluded('/home/u/.ssh/id_rsa', 'posix').excluded);
  assert.ok(fsg.isForcedExcluded('/home/u/.aws/credentials', 'posix').excluded);
  assert.ok(fsg.isForcedExcluded('/home/u/.kube/config', 'posix').excluded);
  assert.ok(!fsg.isForcedExcluded('/home/u/projects/app', 'posix').excluded);
});
test('isForcedExcluded blocks browser store basenames', () => {
  assert.ok(fsg.isForcedExcluded('/a/Login Data', 'posix').excluded);
  assert.ok(fsg.isForcedExcluded('/a/Cookies', 'posix').excluded);
  assert.ok(!fsg.isForcedExcluded('/a/my notes.txt', 'posix').excluded);
});

console.log('fsguard policy');
test('normalizePolicy defaults to empty mounts', () => {
  const p = fsg.normalizePolicy(null);
  assert.deepStrictEqual(p.mounts, []);
  assert.strictEqual(p.defaultDeny, true);
});
test('createDefaultPolicy is default-deny', () => {
  const p = fsg.createDefaultPolicy();
  assert.strictEqual(p.mounts.length, 0);
  assert.strictEqual(p.defaultDeny, true);
});

console.log('fsguard isAccessAllowed');
test('default-deny when no mounts', () => {
  const pol = fsg.createDefaultPolicy();
  const r = fsg.isAccessAllowed('/tmp/a.txt', pol, {platform:'posix'});
  assert.ok(!r.allowed);
  assert.ok(/no mounts/.test(r.reason));
});
test('allows inside mount and denies outside', () => {
  const d = fs.realpathSync(tmp()); fs.mkdirSync(path.join(d, 'ws'), {recursive:true});
  const ws = path.join(d, 'ws');
  let pol = fsg.createDefaultPolicy();
  const add = fsg.addMount(pol, ws); assert.ok(add.ok); pol = add.policy;
  assert.ok(fsg.isAccessAllowed(path.join(ws, 'file.txt'), pol).allowed);
  assert.ok(!fsg.isAccessAllowed(path.join(d, 'other.txt'), pol).allowed);
  assert.ok(fsg.isAccessAllowed(ws, pol).allowed);
});
test('forced exclusion denies even inside mount', () => {
  const d = tmp(); const ws = path.join(d, 'ws'); fs.mkdirSync(ws, {recursive:true});
  const pol = fsg.normalizePolicy({ mounts: [{ id: '1', path: ws, displayName: 'ws', addedAt: Date.now(), scope: 'readwrite', bookmark: null }]});
  assert.ok(!fsg.isAccessAllowed(path.join(ws, '.env'), pol, {platform:'posix'}).allowed);
  assert.ok(!fsg.isAccessAllowed(path.join(ws, 'subdir', '.ssh', 'id_rsa'), pol, {platform:'posix'}).allowed);
  assert.ok(!fsg.isAccessAllowed(path.join(ws, 'key.pem'), pol, {platform:'posix'}).allowed);
});
test('traversal via .. is collapsed before check and stays denied if outside', () => {
  const d = tmp(); const ws = path.join(d, 'ws'); fs.mkdirSync(ws, {recursive:true});
  const pol = fsg.normalizePolicy({ mounts: [{ id: '1', path: ws, displayName: 'ws', addedAt: Date.now(), scope: 'readwrite', bookmark: null }]});
  const traversal = path.join(ws, '..', 'other.txt');
  assert.ok(!fsg.isAccessAllowed(traversal, pol, {platform:'posix'}).allowed);
});
test('symlink escaping mount is denied after canonicalization', () => {
  const d = tmp(); const ws = path.join(d, 'ws'); fs.mkdirSync(ws, {recursive:true});
  const secret = path.join(d, 'secret.txt'); fs.writeFileSync(secret, 's');
  const link = path.join(ws, 'link'); try { fs.symlinkSync(secret, link); } catch { return; }
  const pol = fsg.normalizePolicy({ mounts: [{ id: '1', path: ws, displayName: 'ws', addedAt: Date.now(), scope: 'readwrite', bookmark: null }]});
  // link itself is inside ws lexically but canonical points outside — our resolver walks up to ws (exists) then rejoins suffix; since link is a file symlink, realpath would resolve link itself if leaf exists. Test ancestor-dir symlink instead:
  const realDir = path.join(d, 'realdir'); fs.mkdirSync(realDir);
  const fileInReal = path.join(realDir, 'x.txt'); fs.writeFileSync(fileInReal, 'x');
  const dirLink = path.join(ws, 'dlink'); try { fs.unlinkSync(link); } catch{}; try { fs.symlinkSync(realDir, dirLink); } catch { return; }
  const viaLink2 = path.join(dirLink, 'x.txt');
  const r = fsg.isAccessAllowed(viaLink2, pol, {platform:'posix'});
  // dirLink resolves to realDir which is outside ws => denied
  assert.ok(!r.allowed, 'dir symlink escaping mount must be denied, got: ' + JSON.stringify(r));
});
test('Windows case-insensitive mount check', () => {
  const pol = fsg.normalizePolicy({ mounts: [{ id: '1', path: 'C:\\Users\\Me\\ws', displayName: 'ws', addedAt: Date.now(), scope: 'readwrite', bookmark: null }]});
  assert.ok(fsg.isAccessAllowed('C:\\Users\\Me\\ws\\file.txt', pol, {platform:'win32'}).allowed);
  assert.ok(fsg.isAccessAllowed('c:\\users\\me\\WS\\FILE.TXT', pol, {platform:'win32'}).allowed);
});
test('checkBatch denies on first bad path', () => {
  const d = fs.realpathSync(tmp()); const ws = path.join(d, 'ws'); fs.mkdirSync(ws, {recursive:true});
  let pol = fsg.createDefaultPolicy();
  const add = fsg.addMount(pol, ws); assert.ok(add.ok); pol = add.policy;
  const ok = fsg.checkBatch([path.join(ws,'a.txt'), path.join(ws,'b.txt')], pol);
  assert.ok(ok.allowed);
  const bad = fsg.checkBatch([path.join(ws,'a.txt'), path.join(ws,'.env')], pol);
  assert.ok(!bad.allowed);
});
test('addMount dedupes by canonical path', () => {
  const d = tmp(); const ws = path.join(d, 'ws'); fs.mkdirSync(ws);
  let pol = fsg.createDefaultPolicy();
  const r1 = fsg.addMount(pol, ws); assert.ok(r1.ok); pol = r1.policy;
  const r2 = fsg.addMount(pol, ws); assert.ok(!r2.ok); assert.ok(/already mounted/.test(r2.error));
  const r3 = fsg.removeMount(pol, r1.mount.id); assert.ok(r3.ok); assert.strictEqual(r3.policy.mounts.length, 0);
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
