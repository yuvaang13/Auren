/* Auren — DNS server integration test.
 *
 * Exercises the real resolver + daemon logic (unprivileged, no system DNS
 * changes): a mock upstream resolver + real DNS queries through a tiny Node
 * DNS client (no dig dependency, so it runs on macOS and Windows CI).
 *
 * Run: npm run test:dns
 */
'use strict';
const assert = require('assert');
const crypto = require('crypto');
const dgram = require('dgram');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

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

// Poll the daemon's heartbeat until `pred` holds (or a deadline passes). The
// daemon writes its heartbeat at the end of each reconcile iteration plus on a
// fixed interval; on slow/loaded CI runners (Windows especially) the first
// reconcile — including a PowerShell port-owner probe — can take a couple of
// seconds, so a single fixed sleep was flaky. Returns the last heartbeat read.
async function waitForHb(hbFile, pred, timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 20000);
  let hb = null;
  while (Date.now() < deadline) {
    try { hb = JSON.parse(fs.readFileSync(hbFile, 'utf8')); } catch { hb = null; }
    if (hb && pred(hb)) return hb;
    await sleep(250);
  }
  return hb;
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

// Poll a query until it returns the expected status (or timeout) — hardens against
// Windows CI UDP loss / slow reconcile under load.
async function queryUntil(port, name, expected, timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 8000);
  let last = null;
  while (Date.now() < deadline) {
    last = await query(port, name);
    if (last.status === expected) return last;
    // Don't burn on TIMEOUT vs expected — wait for daemon to catch up
    await sleep(400);
  }
  return last;
}

// A tiny Node DNS client (mirrors what dig exposed to the tests): send a query
// and report the response RCODE as a status string plus the answer count.
function query(port, name) {
  return new Promise((resolve) => {
    const id = crypto.randomBytes(2).readUInt16BE(0);
    const buf = buildQuery(id, name);
    const sock = dgram.createSocket('udp4');
    const done = (res) => { clearTimeout(timer); try { sock.close(); } catch {} resolve(res); };
    const timer = setTimeout(() => done({ status: 'TIMEOUT', answers: 0 }), 3500);
    const rcodeNames = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };
    sock.on('message', (msg) => {
      try {
        if (msg.length < 4) return done({ status: 'ERROR', answers: 0 });
        const flags = msg.readUInt16BE(2);
        if (!(flags & 0x8000)) return; // keep waiting for the response
        const rcode = flags & 0xf;
        done({ status: rcodeNames[rcode] || 'RCODE' + rcode, answers: msg.readUInt16BE(6) });
      } catch { done({ status: 'ERROR', answers: 0 }); }
    });
    sock.on('error', () => done({ status: 'ERROR', answers: 0 }));
    sock.send(buf, port, '127.0.0.1', (err) => { if (err) done({ status: 'ERROR', answers: 0 }); });
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
      // Never touch the real system HTTPS proxy / port 42792 in test mode.
      AUREN_PROXY_ENABLED: '0',
      AUREN_PORT: String(port),
      // mac managed-prefs plists are the only tested autofill mechanism; on
      // Windows keep the daemon's registry policy hook out of the way.
      AUREN_AUTOFILL_ENABLED: process.platform === 'darwin' ? '1' : '0',
      ...(process.platform === 'darwin' ? { AUREN_AUTOFILL_DIR: autofillDir } : {})
    }),
    stdio: 'ignore'
  });

  const kill = () => new Promise((res) => {
    let resolved = false;
    const finish = () => { if (!resolved) { resolved = true; res(); } };
    try {
      child.kill('SIGTERM');
      child.once('exit', finish);
      setTimeout(() => {
        if (!resolved) {
          try { child.kill('SIGKILL'); } catch {}
          setTimeout(finish, 1000);
        }
      }, 2000);
    } catch { finish(); }
    setTimeout(finish, 4000);
  });

  // Wait until the daemon is actually ready (heartbeat fresh + integrity OK)
  // Fixed 3s was flaky on Windows CI under load — poll the heartbeat instead.
  // On Windows the DNS socket can lag slightly behind the first heartbeat, so
  // wait for a second fresh heartbeat as well.
  await waitForHb(hbFile, (hb) => hb.integrityOk === true && hb.pid === child.pid && typeof hb.lastReconcile === 'number' && Date.now() - hb.ts < 5000 && Date.now() - hb.lastReconcile < 5000, 20000);
  if (process.platform === 'win32') await sleep(1500);
  // Extra probe: ensure the UDP resolver is actually answering before the first
  // assertion. Windows CI can lose the first packet or still be binding.
  await waitForHb(hbFile, (hb) => hb.integrityOk === true && Date.now() - hb.ts < 5000, 10000);
  // Warm the resolver — best-effort, ignore result
  try { await query(port, 'bank.com'); } catch {}

  try {
    await test('daemon: blocks the configured domain in real time', async () => {
      const r = await queryUntil(port, 'bank.com', 'NXDOMAIN', process.platform === 'win32' ? 20000 : 8000);
      if (r.status !== 'NXDOMAIN') {
        try {
          const hb = fs.existsSync(hbFile) ? fs.readFileSync(hbFile, 'utf8') : 'no hb';
          const log = fs.existsSync(path.join(dir, 'daemon.log')) ? fs.readFileSync(path.join(dir, 'daemon.log'), 'utf8').slice(-2000) : 'no log';
          console.error('  debug hb: ' + hb);
          console.error('  debug log tail: ' + log);
        } catch {}
      }
      assert.strictEqual(r.status, 'NXDOMAIN');
    });

    await test('daemon: writes a fresh heartbeat with integrity OK', async () => {
      const hb = await waitForHb(hbFile, (h) => h.integrityOk === true && typeof h.lastReconcile === 'number' && Date.now() - h.ts < 5000 && Date.now() - h.lastReconcile < 5000, 10000);
      assert.ok(hb && Date.now() - hb.ts < 5000);
      assert.strictEqual(hb.integrityOk, true);
      assert.strictEqual(hb.pid, child.pid);
      assert.strictEqual(hb.pf, false, 'pf must stay off when AUREN_PF_ENABLED=0');
      assert.ok(typeof hb.lastReconcile === 'number' && Date.now() - hb.lastReconcile < 5000, 'reconcile loop must be completing (lastReconcile fresh)');
    });

    if (process.platform === 'darwin') {
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
    }

    await test('daemon: block list changes apply without restart', async () => {
      writeCfg('on', ['bank.com', 'example.net'], false);
      await sleep(process.platform === 'win32' ? 3000 : 1500);
      await waitForHb(hbFile, (hb) => hb.integrityOk === true && Date.now() - hb.ts < 5000, 10000);
      const r = await queryUntil(port, 'example.net', 'NXDOMAIN', process.platform === 'win32' ? 20000 : 8000);
      assert.strictEqual(r.status, 'NXDOMAIN');
      const r2 = await queryUntil(port, 'example.org', 'NOERROR', process.platform === 'win32' ? 20000 : 8000);
      assert.strictEqual(r2.status, 'NOERROR');
    });

    await test('daemon: mode off stops blocking', async () => {
      writeCfg('off', ['bank.com'], false);
      await sleep(process.platform === 'win32' ? 3000 : 1500);
      await waitForHb(hbFile, (hb) => Date.now() - hb.ts < 5000, 10000);
      const r = await queryUntil(port, 'bank.com', 'NOERROR', process.platform === 'win32' ? 20000 : 8000);
      assert.strictEqual(r.status, 'NOERROR');
    });

    if (process.platform === 'darwin') {
      await test('daemon: removes browser autofill policies while protection is off', async () => {
        writeCfg('off', ['bank.com'], false);
        await sleep(1500);
        assert.ok(!fs.existsSync(path.join(autofillDir, 'com.google.Chrome.plist')), 'plist must be removed when protection is off');
      });
    }

    await test('daemon: tampered config keeps the last verified policy (no deny-all)', async () => {
      // Establish a verified baseline: protection ON, bank.com blocked,
      // example.org allowed.
      writeCfg('on', ['bank.com'], false);
      await sleep(process.platform === 'win32' ? 3000 : 1500);
      await waitForHb(hbFile, (hb) => hb.integrityOk === true && Date.now() - hb.ts < 5000, 10000);
      const base = await queryUntil(port, 'example.org', 'NOERROR', process.platform === 'win32' ? 20000 : 8000);
      assert.strictEqual(base.status, 'NOERROR');

      // Rewrite the config directly WITHOUT updating the signature, like an
      // agent would. The daemon must refuse to trust it: the tampered content
      // (mode off, block list removed, deny-all requested) must NOT take
      // effect, the last verified policy keeps running, and — unlike a
      // deny-all — unrelated traffic keeps flowing. The heartbeat reports the
      // degraded integrity.
      fs.writeFileSync(cfgFile, JSON.stringify({ version: 1, mode: 'off', blocklist: [], failClosed: true }));
      await sleep(process.platform === 'win32' ? 3000 : 1500);
      const blocked = await queryUntil(port, 'bank.com', 'NXDOMAIN', process.platform === 'win32' ? 20000 : 8000);
      assert.strictEqual(blocked.status, 'NXDOMAIN', 'last verified block list must still be enforced');
      const allowed = await queryUntil(port, 'example.org', 'NOERROR', process.platform === 'win32' ? 20000 : 8000);
      assert.strictEqual(allowed.status, 'NOERROR', 'unrelated traffic must not be denied');
      const hb = await waitForHb(hbFile, (h) => h.integrityOk === false, 10000);
      assert.strictEqual(hb.integrityOk, false, 'heartbeat must report degraded integrity');
      assert.strictEqual(hb.failClosed, false, 'tampered failClosed must not be honored');
    });

    await test('daemon: blocked lookups land in the activity log', async () => {
      writeCfg('on', ['bank.com'], false);
      await sleep(process.platform === 'win32' ? 3000 : 1500);
      await waitForHb(hbFile, (hb) => hb.integrityOk === true && Date.now() - hb.ts < 5000, 10000);
      await queryUntil(port, 'bank.com', 'NXDOMAIN', process.platform === 'win32' ? 20000 : 8000);
      await sleep(800);
      const lines = fs.readFileSync(actFile, 'utf8').split('\n').filter((l) => l.trim());
      assert.ok(lines.some((l) => l.includes('"kind":"block"') && l.includes('bank.com')));
    });

    if (process.platform !== 'win32') {
      await test('daemon: kills a running app on the app block list (protection on)', async () => {
        const dummy = path.join(dir, 'dummy-app.sh');
        fs.writeFileSync(dummy, '#!/bin/sh\nwhile true; do sleep 1; done\n');
        fs.chmodSync(dummy, 0o755);
        writeCfg('on', ['bank.com'], false, [{ id: 'com.auren.test.blockedapp', name: 'blocked-app', path: dummy }]);
        // Poll until the daemon has picked up the new block list (heartbeat app check is implicit via kill loop)
        await sleep(1500);
        const proc = spawn('/bin/sh', [dummy], { stdio: 'ignore' });
        // Poll for kill — CI runners (especially macOS) can be ~2x slower, so don't rely on a single fixed sleep.
        let alive = true;
        const deadline = Date.now() + 6000;
        while (Date.now() < deadline) {
          await sleep(300);
          try { process.kill(proc.pid, 0); } catch { alive = false; break; }
        }
        assert.ok(!alive, 'blocked app process must be killed within ~6 s');
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
        // Ensure it stays alive for a full additional scan window (2 s)
        let alive = true;
        try { process.kill(proc.pid, 0); } catch { alive = false; }
        assert.ok(alive, 'app must keep running while protection is off');
        await sleep(2000);
        try { process.kill(proc.pid, 0); alive = true; } catch { alive = false; }
        assert.ok(alive, 'app must still be running after 2 s while protection is off');
        proc.kill('SIGTERM');
        // Give it a moment to exit so it doesn't linger into next test
        await sleep(300);
        try { proc.kill('SIGKILL'); } catch {}
      });
    }
  } finally {
    await kill();
  }
}

/* --------------------- port-53 conflict (test mode) --------------------- */

// A second daemon that can't bind its DNS port must say so in the heartbeat
// (dnsConflict + activity entry) instead of silently running without DNS
// enforcement — this is what surfaces the "port 53 taken" degraded banner.
// Squat a port (UDP + TCP) so nothing else can bind it. On macOS/Linux two
// Node sockets as the squatter are enough. On Windows that does NOT work: Node
// sockets set SO_REUSEADDR (TCP) and Windows allows multiple UDP binds on one
// port, so the daemon's resolver binds anyway, starts cleanly, and no conflict
// is ever detected — the CI failure this returns a real squatter for. Real
// port-53 squatters (VPN clients, DNS services) use exclusive binds, so on
// Windows squat with a PowerShell child using .NET sockets with
// ExclusiveAddressUse: the daemon's resolver then genuinely fails to bind, and
// Get-NetTCPConnection (dnsops.portOwner) names the squatter exactly like it
// would name a real one.
async function squatPort(port) {
  if (process.platform !== 'win32') {
    const udp = dgram.createSocket('udp4');
    const tcp = net.createServer();
    await new Promise((res, rej) => { udp.once('error', rej); udp.bind(port, '127.0.0.1', res); });
    await new Promise((res, rej) => { tcp.once('error', rej); tcp.listen(port, '127.0.0.1', res); });
    return {
      close: async () => { try { udp.close(); } catch { /* ignore */ } try { tcp.close(); } catch { /* ignore */ } }
    };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auren-squat-'));
  const script = path.join(dir, 'squat.ps1');
  const ready = path.join(dir, 'ready.txt');
  const ps = [
    'param([int]$p, [string]$ready)',
    '$udp = New-Object System.Net.Sockets.UdpClient',
    '$udp.Client.ExclusiveAddressUse = $true',
    '$udp.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("127.0.0.1"), $p)))',
    '$tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse("127.0.0.1"), $p)',
    '$tcp.ExclusiveAddressUse = $true',
    '$tcp.Start()',
    'Set-Content -Path $ready -Value "ok"',
    'Start-Sleep -Seconds 120'
  ].join('\n');
  fs.writeFileSync(script, ps, 'utf8');
  const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, String(port), ready], { stdio: 'ignore' });
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (fs.existsSync(ready)) {
      return {
        close: async () => {
          try { child.kill(); } catch { /* ignore */ }
          await new Promise((r) => { child.once('exit', r); setTimeout(r, 2000); });
          try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
        }
      };
    }
    await sleep(200);
  }
  try { child.kill(); } catch { /* ignore */ }
  throw new Error('exclusive port squatter failed to come up');
}

async function portConflictTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auren-conflict-'));
  const cfgFile = path.join(dir, 'config.json');
  const keyFile = path.join(dir, 'auren.key');
  const hbFile = path.join(dir, 'heartbeat.json');
  const actFile = path.join(dir, 'activity.jsonl');
  const stateFile = path.join(dir, 'state.json');
  const port = 55000 + (process.pid % 500);
  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyFile, key, { mode: 0o600 });
  config.writeSignedConfig(cfgFile, { version: 1, mode: 'on', blocklist: [], failClosed: false, appBlocklist: [] }, key);

  // Squat on the daemon's DNS port (UDP + TCP) so its resolver can't bind.
  const squatter = await squatPort(port);

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
      AUREN_APPS_ENABLED: '0',
      AUREN_PROXY_ENABLED: '0',
      AUREN_AUTOFILL_ENABLED: '0',
      AUREN_PORT: String(port)
    }),
    stdio: 'ignore'
  });

  try {
    const hb = await waitForHb(hbFile, (h) => !!h.dnsConflict);
    assert.ok(hb && hb.dnsConflict, 'heartbeat must report a DNS port conflict');
    assert.strictEqual(hb.dnsConflict.port, port);
    assert.ok(hb.dnsConflict.pid, 'conflict must identify the owning pid');
    assert.ok(hb.dnsConflict.name, 'conflict must name the owning process');
    const act = fs.readFileSync(actFile, 'utf8');
    assert.ok(act.includes('dns_conflict'), 'the conflict must land in the activity log');
  } finally {
    try {
      child.kill('SIGTERM');
      await new Promise((r) => { child.once('exit', r); setTimeout(r, 2000); });
    } catch {}
    await sleep(500);
    await squatter.close();
  }
}

/* --------------------- proxy port fallback (test mode) ------------------- */

// When the default HTTPS-proxy port is taken, the daemon must bind the next
// free port and report it (heartbeat proxyPort + the PAC served on that port),
// instead of silently giving up on HTTPS host blocking.
async function proxyFallbackTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auren-proxyfallback-'));
  const cfgFile = path.join(dir, 'config.json');
  const keyFile = path.join(dir, 'auren.key');
  const hbFile = path.join(dir, 'heartbeat.json');
  const actFile = path.join(dir, 'activity.jsonl');
  const stateFile = path.join(dir, 'state.json');
  const proxyPort = 56000 + (process.pid % 400);
  const dnsPort = proxyPort + 100;
  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyFile, key, { mode: 0o600 });
  config.writeSignedConfig(cfgFile, { version: 1, mode: 'on', blocklist: [], failClosed: false, appBlocklist: [] }, key);

  // Occupy the default proxy port.
  const squatter = net.createServer();
  await new Promise((res, rej) => { squatter.once('error', rej); squatter.listen(proxyPort, '127.0.0.1', res); });

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
      AUREN_APPS_ENABLED: '0',
      AUREN_AUTOFILL_ENABLED: '0',
      AUREN_PROXY_ENABLED: '1',
      AUREN_PROXY_NET_ENABLED: '0',
      AUREN_PROXY_PORT: String(proxyPort),
      AUREN_PORT: String(dnsPort)
    }),
    stdio: 'ignore'
  });

  try {
    const hb = await waitForHb(hbFile, (h) => h.proxy === true && h.proxyPort === proxyPort + 1);
    assert.ok(hb && hb.proxy === true, 'proxy must be active');
    assert.strictEqual(hb.proxyPort, proxyPort + 1, 'proxy must fall back to the next free port');

    // The PAC the daemon points the system proxy at is served on that port and
    // embeds it, so browsers route HTTPS through the right socket.
    const pac = await new Promise((resolve) => {
      const sock = net.connect(proxyPort + 1, '127.0.0.1', () => sock.write('GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'));
      let data = '';
      sock.on('data', (c) => { data += c.toString('latin1'); });
      sock.on('error', () => resolve(''));
      sock.on('end', () => resolve(data));
      sock.on('close', () => resolve(data));
      setTimeout(() => { try { sock.destroy(); } catch {} resolve(data); }, 3000);
    });
    assert.ok(pac.includes('FindProxyForURL'), 'PAC served on the fallback port');
    assert.ok(pac.includes('PROXY 127.0.0.1:' + (proxyPort + 1)), 'PAC embeds the fallback port');
  } finally {
    try {
      child.kill('SIGTERM');
      await new Promise((r) => { child.once('exit', r); setTimeout(r, 2000); });
    } catch {}
    await sleep(500);
    try { squatter.close(); } catch { /* ignore */ }
  }
}

(async () => {
  console.log('DNS resolver + daemon integration tests');
  await before();
  await test('resolver: blocked domain returns NXDOMAIN', async () => {
    const r = await query(resolver.udp.address().port, 'bank.com');
    assert.strictEqual(r.status, 'NXDOMAIN');
    assert.strictEqual(r.answers, 0);
  });
  await test('resolver: subdomain of blocked domain returns NXDOMAIN', async () => {
    const r = await query(resolver.udp.address().port, 'login.bank.com');
    assert.strictEqual(r.status, 'NXDOMAIN');
  });
  await test('resolver: similar-but-different domain is NOT blocked', async () => {
    const r = await query(resolver.udp.address().port, 'notbank.com');
    assert.strictEqual(r.status, 'NOERROR');
  });
  await test('resolver: non-blocked domain is forwarded and answered', async () => {
    const r = await query(resolver.udp.address().port, 'example.org');
    assert.strictEqual(r.status, 'NOERROR');
    assert.strictEqual(r.answers, 1);
  });
  await after();

  await test('cache: flushDnsCache runs all flush commands', async () => {
    const calls = [];
    const res = flushDnsCache({
      execFileSync: (cmd, args) => { calls.push({ cmd, args }); return Buffer.alloc(0); }
    });
    assert.deepStrictEqual(calls, FLUSH_COMMANDS.map(([cmd, args]) => ({ cmd, args })));
    assert.strictEqual(res.flushed, true);
    assert.deepStrictEqual(res.errors, []);
    assert.ok(FLUSH_COMMANDS.length >= (process.platform === 'win32' ? 1 : 2), 'cache tools resolved');
    for (const [cmd] of FLUSH_COMMANDS) {
      assert.ok(fs.existsSync(cmd) || !path.isAbsolute(cmd), 'cache tool resolves to a real path: ' + cmd);
    }
  });

  await test('cache: flushDnsCache swallows failures and reports them', async () => {
    const res = flushDnsCache({
      execFileSync: (cmd) => { throw new Error('permission denied for ' + cmd); }
    });
    assert.strictEqual(res.flushed, false);
    assert.strictEqual(res.errors.length, FLUSH_COMMANDS.length);
    assert.ok(res.errors[0].includes(process.platform === 'win32' ? 'ipconfig' : 'dscacheutil'));
  });

  await test('cache: flushDnsCacheAsync fires all commands without blocking', async () => {
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
        assert.strictEqual(res.errors.length, FLUSH_COMMANDS.length);
        assert.ok(res.errors[0].includes(process.platform === 'win32' ? 'ipconfig' : 'dscacheutil'));
        resolve();
      });
    });
  });

  await daemonTest();
  await test('daemon: reports a port-53 conflict in the heartbeat', () => portConflictTest());
  await test('daemon: HTTPS proxy falls back to the next free port', () => proxyFallbackTest());
  console.log('');
  console.log(passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => { console.error(err); process.exit(1); });
