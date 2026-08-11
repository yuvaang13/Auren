/* Auren — DNS server integration test.
 *
 * Exercises the real resolver + daemon logic (unprivileged, no system DNS
 * changes): a mock upstream resolver + real DNS queries through dig.
 *
 * Run: npm run test:dns
 */
'use strict';
const assert = require('assert');
const crypto = require('crypto');
const dgram = require('dgram');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, execFile } = require('child_process');

const dnsMsg = require('../src/dns/dns-message');
const { DnsResolver } = require('../src/dns/resolver');
const { flushDnsCache, flushDnsCacheAsync, FLUSH_COMMANDS } = require('../src/dns/cache');
const { domainMatches } = require('../src/core/domains');
const config = require('../src/core/config');

let passed = 0;
let failed = 0;

function test(name, fn) {
  return Promise.resolve().then(fn).then(() => {
    passed += 1;
    console.log('  ok   ' + name);
  }).catch((err) => {
    failed += 1;
    console.error('  FAIL ' + name);
    console.error('       ' + (err && err.stack || err));
  });
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function hasDig() {
  try { require('child_process').execFileSync('/usr/bin/dig', ['-v'], { stdio: 'ignore' }); return true; } catch { return false; }
}

function buildQuery(id, name) {
  const qname = dnsMsg.encodeName(name);
  const buf = Buffer.alloc(12 + qname.length + 4);
  buf.writeUInt16BE(id, 0);
  buf.writeUInt16BE(0x0100, 2);
  buf.writeUInt16BE(1, 4);
  qname.copy(buf, 12);
  buf.writeUInt16BE(1, 12 + qname.length);
  buf.writeUInt16BE(1, 14 + qname.length);
  return buf;
}

// A tiny mock upstream that answers every A query with 1.2.3.4.
async function startMockUpstream() {
  const srv = dgram.createSocket('udp4');
  srv.on('message', (msg, rinfo) => {
    try {
      const q = dnsMsg.extractQuestion(msg);
      const parsed = dnsMsg.parseName(msg, 12);
      if (!q || !parsed) return;
      const questionEnd = parsed.endOffset + 4;
      const header = Buffer.alloc(12);
      msg.copy(header, 0, 0, 2);
      header.writeUInt16BE(0x8180, 2);
      header.writeUInt16BE(1, 4);
      header.writeUInt16BE(1, 6);
      const answer = Buffer.alloc(16);
      answer.writeUInt16BE(0xc00c, 0);
      answer.writeUInt16BE(1, 2);
      answer.writeUInt16BE(1, 4);
      answer.writeUInt32BE(60, 6);
      answer.writeUInt16BE(4, 10);
      answer[12] = 1; answer[13] = 2; answer[14] = 3; answer[15] = 4;
      srv.send(Buffer.concat([header, msg.slice(12, questionEnd), answer]), rinfo.port, rinfo.address);
    } catch {}
  });
  await new Promise((res, rej) => { srv.once('error', rej); srv.bind(0, '127.0.0.1', res); });
  return { socket: srv, port: srv.address().port };
}

function dig(port, name) {
  return new Promise((resolve) => {
    execFile('/usr/bin/dig', ['@127.0.0.1', '-p', String(port), '+time=3', '+tries=1', name], (err, stdout) => {
      const st = /status:\s*(\w+)/.exec(stdout || '');
      const answers = ((stdout || '').match(/IN\s+A\s+[0-9.]+/g) || []).length;
      resolve({ status: st ? st[1] : (err ? 'ERROR' : 'UNKNOWN'), answers });
    });
  });
}

let mock, resolver;

async function before() {
  mock = await startMockUpstream();
  const blocked = new Set(['bank.com']);
  resolver = new DnsResolver({
    port: 0,
    host: '127.0.0.1',
    upstreamPort: mock.port,
    upstreamServers: ['127.0.0.1'],
    blockFn: (name) => [...blocked].some((d) => domainMatches(name, d)),
    onBlocked: () => {}
  });
  await resolver.start();
}

async function after() {
  if (resolver) await resolver.stop();
  if (mock) mock.socket.close();
}

/* --------------------- daemon (test mode) --------------------- */

async function daemonTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auren-daemon-'));
  const cfgFile = path.join(dir, 'config.json');
  const keyFile = path.join(dir, 'auren.key');
  const hbFile = path.join(dir, 'heartbeat.json');
  const actFile = path.join(dir, 'activity.jsonl');
  const stateFile = path.join(dir, 'state.json');
  const autofillDir = path.join(dir, 'autofill');
  const port = 53000 + (process.pid % 1000);
  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyFile, key, { mode: 0o600 });

  const writeCfg = (mode, blocklist, failClosed, appBlocklist) =>
    config.writeSignedConfig(cfgFile, { version: 1, mode, blocklist, failClosed: !!failClosed, appBlocklist: appBlocklist || [] }, key);

  writeCfg('on', ['bank.com'], false);
  fs.writeFileSync(actFile, '');

  const child = spawn(process.execPath, [path.join(__dirname, '..', 'src', 'dns', 'daemon.js')], {
    env: Object.assign({}, process.env, {
      AUREN_CONFIG: cfgFile,
      AUREN_KEY: keyFile,
      AUREN_HEARTBEAT: hbFile,
      AUREN_ACTIVITY: actFile,
      AUREN_STATE: stateFile,
      AUREN_DAEMON_LOG: path.join(dir, 'daemon.log'),
      AUREN_DNS_ENABLED: '0',
      AUREN_PF_ENABLED: '0',
      AUREN_APPS_ENABLED: '1',
      AUREN_AUTOFILL_DIR: autofillDir,
      AUREN_PORT: String(port)
    }),
    stdio: 'ignore'
  });

  const kill = () => new Promise((res) => { try { child.kill('SIGTERM'); child.once('exit', () => res()); setTimeout(res, 3000); } catch { res(); } });

  await sleep(1800); // let it bind + reconcile

  try {
    await test('daemon: blocks the configured domain in real time', async () => {
      const r = await dig(port, 'bank.com');
      assert.strictEqual(r.status, 'NXDOMAIN');
    });

    await test('daemon: writes a fresh heartbeat with integrity OK', async () => {
      const hb = JSON.parse(fs.readFileSync(hbFile, 'utf8'));
      assert.ok(Date.now() - hb.ts < 5000);
      assert.strictEqual(hb.integrityOk, true);
      assert.strictEqual(hb.pid, child.pid);
      assert.strictEqual(hb.pf, false, 'pf must stay off when AUREN_PF_ENABLED=0');
    });

    await test('daemon: blocks browser autofill via managed-prefs policies while protection is on', async () => {
      writeCfg('on', ['bank.com'], false);
      await sleep(1500);
      for (const id of ['com.google.Chrome', 'org.chromium.Chromium', 'com.brave.Browser', 'com.microsoft.Edge']) {
        const p = path.join(autofillDir, id + '.plist');
        assert.ok(fs.existsSync(p), id + ' managed-prefs plist must exist');
        const xml = fs.readFileSync(p, 'utf8');
        assert.ok(xml.includes('<key>PasswordManagerEnabled</key>'), id + ': password manager disabled');
        assert.ok(xml.includes('<key>AutofillAddressEnabled</key>'), id + ': address autofill disabled');
        assert.ok(xml.includes('<key>AutofillCreditCardEnabled</key>'), id + ': card autofill disabled');
        assert.ok(xml.includes('<false/>'), id + ': policies are false');
      }
    });

    await test('daemon: block list changes apply without restart', async () => {
      writeCfg('on', ['bank.com', 'example.net'], false);
      await sleep(1500);
      const r = await dig(port, 'example.net');
      assert.strictEqual(r.status, 'NXDOMAIN');
      const r2 = await dig(port, 'example.org');
      assert.strictEqual(r2.status, 'NOERROR');
    });

    await test('daemon: mode off stops blocking', async () => {
      writeCfg('off', ['bank.com'], false);
      await sleep(1500);
      const r = await dig(port, 'bank.com');
      assert.strictEqual(r.status, 'NOERROR');
    });

    await test('daemon: removes browser autofill policies while protection is off', async () => {
      writeCfg('off', ['bank.com'], false);
      await sleep(1500);
      assert.ok(!fs.existsSync(path.join(autofillDir, 'com.google.Chrome.plist')), 'plist must be removed when protection is off');
    });

    await test('daemon: tampered config fails closed (blocks everything)', async () => {
      // Edit the config file directly WITHOUT updating the signature, like an
      // agent would. The daemon must refuse to trust it and deny all lookups.
      fs.writeFileSync(cfgFile, JSON.stringify({ version: 1, mode: 'off', blocklist: [] }));
      await sleep(1500);
      const r = await dig(port, 'example.org');
      assert.strictEqual(r.status, 'NXDOMAIN');
      const hb = JSON.parse(fs.readFileSync(hbFile, 'utf8'));
      assert.strictEqual(hb.integrityOk, false);
    });

    await test('daemon: blocked lookups land in the activity log', async () => {
      writeCfg('on', ['bank.com'], false);
      await sleep(1500);
      await dig(port, 'bank.com');
      await sleep(300);
      const lines = fs.readFileSync(actFile, 'utf8').split('\n').filter((l) => l.trim());
      assert.ok(lines.some((l) => l.includes('"kind":"block"') && l.includes('bank.com')));
    });

    await test('daemon: kills a running app on the app block list (protection on)', async () => {
      const dummy = path.join(dir, 'dummy-app.sh');
      fs.writeFileSync(dummy, '#!/bin/sh\nwhile true; do sleep 1; done\n');
      fs.chmodSync(dummy, 0o755);
      writeCfg('on', ['bank.com'], false, [{ id: 'com.auren.test.blockedapp', name: 'blocked-app', path: dummy }]);
      await sleep(1500);
      const proc = spawn('/bin/sh', [dummy], { stdio: 'ignore' });
      await sleep(1800);
      let alive = true;
      try { process.kill(proc.pid, 0); } catch { alive = false; }
      assert.ok(!alive, 'blocked app process must be killed within ~1 s');
      try { proc.kill('SIGKILL'); } catch { /* already dead */ }
      const lines = fs.readFileSync(actFile, 'utf8').split('\n').filter((l) => l.trim());
      assert.ok(lines.some((l) => l.includes('"kind":"app"') && l.includes('blocked-app')), 'the kill must be logged in activity');
    });

    await test('daemon: leaves apps alone while protection is off', async () => {
      writeCfg('off', ['bank.com'], false, []);
      await sleep(1500);
      const dummy = path.join(dir, 'dummy-app-2.sh');
      fs.writeFileSync(dummy, '#!/bin/sh\nwhile true; do sleep 1; done\n');
      fs.chmodSync(dummy, 0o755);
      const proc = spawn('/bin/sh', [dummy], { stdio: 'ignore' });
      await sleep(1500);
      let alive = true;
      try { process.kill(proc.pid, 0); } catch { alive = false; }
      assert.ok(alive, 'app must keep running while protection is off');
      proc.kill('SIGTERM');
    });
  } finally {
    await kill();
  }
}

(async () => {
  console.log('DNS resolver + daemon integration tests');
  if (!hasDig()) {
    console.error('  SKIP: dig not available');
    return;
  }
  await before();
  await test('resolver: blocked domain returns NXDOMAIN', async () => {
    const r = await dig(resolver.udp.address().port, 'bank.com');
    assert.strictEqual(r.status, 'NXDOMAIN');
    assert.strictEqual(r.answers, 0);
  });
  await test('resolver: subdomain of blocked domain returns NXDOMAIN', async () => {
    const r = await dig(resolver.udp.address().port, 'login.bank.com');
    assert.strictEqual(r.status, 'NXDOMAIN');
  });
  await test('resolver: similar-but-different domain is NOT blocked', async () => {
    const r = await dig(resolver.udp.address().port, 'notbank.com');
    assert.strictEqual(r.status, 'NOERROR');
  });
  await test('resolver: non-blocked domain is forwarded and answered', async () => {
    const r = await dig(resolver.udp.address().port, 'example.org');
    assert.strictEqual(r.status, 'NOERROR');
    assert.strictEqual(r.answers, 1);
  });
  await after();

  await test('cache: flushDnsCache runs both flush commands', async () => {
    const calls = [];
    const res = flushDnsCache({
      execFileSync: (cmd, args) => { calls.push({ cmd, args }); return Buffer.alloc(0); }
    });
    assert.deepStrictEqual(calls, FLUSH_COMMANDS.map(([cmd, args]) => ({ cmd, args })));
    assert.strictEqual(res.flushed, true);
    assert.deepStrictEqual(res.errors, []);
    assert.ok(FLUSH_COMMANDS.length >= 2, 'both cache tools resolved');
    for (const [cmd] of FLUSH_COMMANDS) {
      assert.ok(fs.existsSync(cmd), 'cache tool resolves to a real path: ' + cmd);
    }
  });

  await test('cache: flushDnsCache swallows failures and reports them', async () => {
    const res = flushDnsCache({
      execFileSync: (cmd) => { throw new Error('permission denied for ' + cmd); }
    });
    assert.strictEqual(res.flushed, false);
    assert.strictEqual(res.errors.length, 2);
    assert.ok(res.errors[0].includes('dscacheutil'));
    assert.ok(res.errors[1].includes('killall'));
  });

  await test('cache: flushDnsCacheAsync fires both commands without blocking', async () => {
    const calls = [];
    await new Promise((resolve) => {
      flushDnsCacheAsync({
        execFile: (cmd, args, opts, cb) => { calls.push({ cmd, args }); cb(null, Buffer.alloc(0)); }
      }, (res) => {
        assert.deepStrictEqual(res, { flushed: true, errors: [] });
        resolve();
      });
    });
    assert.deepStrictEqual(calls, FLUSH_COMMANDS.map(([cmd, args]) => ({ cmd, args })));
  });

  await test('cache: flushDnsCacheAsync swallows failures and reports them', async () => {
    await new Promise((resolve) => {
      flushDnsCacheAsync({
        execFile: (cmd, args, opts, cb) => cb(new Error('denied ' + cmd))
      }, (res) => {
        assert.strictEqual(res.flushed, false);
        assert.strictEqual(res.errors.length, 2);
        assert.ok(res.errors[0].includes('dscacheutil'));
        assert.ok(res.errors[1].includes('killall'));
        resolve();
      });
    });
  });

  await daemonTest();
  console.log('');
  console.log(passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => { console.error(err); process.exit(1); });
