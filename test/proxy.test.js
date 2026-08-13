/* Auren — HTTPS-blocking proxy tests.
 *
 * Covers the pure SNI parser (src/proxy/sni.js), the CONNECT proxy server
 * (src/proxy/server.js) with a real socket round-trip on an ephemeral port,
 * the pf QUIC/443 rules + safety floor (src/dns/pf.js), and the Windows
 * WinINET command builders (src/platform/proxyops-win.js). No root, no system
 * proxy changes.
 *
 * Run: npm run test:proxy (also part of npm run test:all)
 */
'use strict';
const assert = require('assert');
const net = require('net');

const { parseSni, normalize } = require('../src/proxy/sni');
const { buildPac, parseConnectLine, start, stop } = require('../src/proxy/server');
const pf = require('../src/dns/pf');
const win = require('../src/platform/proxyops-win');

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

/* ------------------------- synthetic ClientHello ------------------------- */

// Builds a minimal TLS ClientHello record carrying one SNI host_name.
function buildClientHello(hostname) {
  const name = Buffer.from(hostname, 'ascii');
  const listLen = 3 + name.length; // type(1) + len(2) + name
  const entry = Buffer.alloc(3 + name.length);
  entry[0] = 0x00;                         // host_name type
  entry.writeUInt16BE(name.length, 1);
  name.copy(entry, 3);

  const extContent = Buffer.alloc(2 + entry.length);
  extContent.writeUInt16BE(listLen, 0);
  entry.copy(extContent, 2);

  const ext = Buffer.alloc(4 + extContent.length);
  ext.writeUInt16BE(0x0000, 0);            // server_name extension
  ext.writeUInt16BE(extContent.length, 2);
  extContent.copy(ext, 4);

  const body = Buffer.alloc(2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext.length);
  let o = 0;
  body.writeUInt16BE(0x0303, o); o += 2;   // version
  o += 32;                                 // random
  body[o] = 0; o += 1;                     // session id len
  body.writeUInt16BE(2, o); o += 2;        // cipher suites len
  body.writeUInt16BE(0x1301, o); o += 2;   // TLS_AES_128_GCM_SHA256
  body[o] = 1; o += 1;                     // compression len
  body[o] = 0; o += 1;                     // compression method
  body.writeUInt16BE(ext.length, o); o += 2;
  ext.copy(body, o);

  const handshake = Buffer.alloc(4 + body.length);
  handshake[0] = 0x01;                     // ClientHello
  handshake[1] = (body.length >> 16) & 0xff;
  handshake[2] = (body.length >> 8) & 0xff;
  handshake[3] = body.length & 0xff;
  body.copy(handshake, 4);

  const record = Buffer.alloc(5 + handshake.length);
  record[0] = 0x16;                        // handshake record
  record.writeUInt16BE(0x0301, 1);
  record.writeUInt16BE(handshake.length, 3);
  handshake.copy(record, 5);
  return record;
}

(async () => {
  /* -------------------------------- SNI ----------------------------------- */

  await test('parseSni extracts a hostname from a ClientHello', () => {
    assert.strictEqual(parseSni(buildClientHello('evil.example.com')), 'evil.example.com');
  });

  await test('parseSni lowercases and strips a trailing dot', () => {
    assert.strictEqual(parseSni(buildClientHello('Evil.Example.COM.')), 'evil.example.com');
  });

  await test('parseSni returns null for non-TLS bytes and garbage', () => {
    assert.strictEqual(parseSni(Buffer.from('GET / HTTP/1.1\r\n\r\n')), null);
    assert.strictEqual(parseSni(Buffer.from([0x00, 0x01, 0x02])), null);
    assert.strictEqual(parseSni(null), null);
  });

  await test('parseSni returns null for a truncated ClientHello', () => {
    const full = buildClientHello('evil.example.com');
    assert.strictEqual(parseSni(full.slice(0, full.length - 5)), null);
  });

  await test('normalize trims/empties properly', () => {
    assert.strictEqual(normalize('Example.COM.'), 'example.com');
    assert.strictEqual(normalize('   '), null);
    assert.strictEqual(normalize('.'), null);
  });

  /* --------------------------- PAC + CONNECT line -------------------------- */

  await test('buildPac routes only https through the proxy', () => {
    const pac = buildPac(42792);
    assert.ok(pac.includes('PROXY 127.0.0.1:42792'));
    assert.ok(pac.includes('https:'));
  });

  await test('parseConnectLine parses domain and bracketed IPv6 authorities', () => {
    assert.deepStrictEqual(parseConnectLine('CONNECT evil.example.com:443 HTTP/1.1'), { host: 'evil.example.com', port: 443 });
    assert.deepStrictEqual(parseConnectLine('CONNECT [2001:db8::1]:443 HTTP/1.1'), { host: '2001:db8::1', port: 443 });
    assert.strictEqual(parseConnectLine('GET /proxy.pac HTTP/1.1'), null);
    assert.strictEqual(parseConnectLine('CONNECT evil.example.com:0 HTTP/1.1'), null);
    assert.strictEqual(parseConnectLine('CONNECT evil.example.com:70000 HTTP/1.1'), null);
  });

  /* --------------------------- proxy integration --------------------------- */

  function connectOnce(port, firstLine) {
    return new Promise((resolve, reject) => {
      const sock = net.connect(port, '127.0.0.1', () => {
        sock.write(firstLine);
      });
      let head = '';
      sock.on('data', (chunk) => {
        head += chunk.toString('latin1');
        if (head.includes('\r\n')) {
          sock.end();
          resolve(head.slice(0, head.indexOf('\r\n')));
        }
      });
      sock.on('error', reject);
    });
  }

  await test('proxy refuses a CONNECT to a blocked domain with 403', async () => {
    const { port } = await start({ port: 0, blockFn: (n) => n === 'evil.example.com' });
    try {
      const line = await connectOnce(port, 'CONNECT evil.example.com:443 HTTP/1.1\r\n\r\n');
      assert.strictEqual(line, 'HTTP/1.1 403 Forbidden');
    } finally {
      await stop();
    }
  });

  await test('proxy tunnels a non-blocked CONNECT and serves the PAC', async () => {
    const target = net.createServer();
    await new Promise((r) => target.listen(0, '127.0.0.1', r));
    const targetPort = target.address().port;
    let seen = '';
    target.on('connection', (s) => {
      s.on('data', (d) => { seen += d.toString('latin1'); s.end('pong'); });
    });

    const { port } = await start({ port: 0, blockFn: () => false });
    try {
      // PAC is served on the same port.
      const pacLine = await connectOnce(port, 'GET /proxy.pac HTTP/1.1\r\n\r\n');
      assert.strictEqual(pacLine, 'HTTP/1.1 200 OK');

      // A domain CONNECT to an allowed host gets 200 and tunnels bytes.
      // localhost resolves to 127.0.0.1, so the tunnel reaches the mock target.
      const sock = net.connect(port, '127.0.0.1');
      await new Promise((r, j) => { sock.once('connect', r); sock.once('error', j); });
      sock.write('CONNECT localhost:' + targetPort + ' HTTP/1.1\r\n\r\n');
      let got = '';
      const echoPromise = new Promise((resolve, reject) => {
        sock.on('data', (d) => { if (d.toString('latin1').includes('pong')) resolve('pong'); });
        sock.on('error', reject);
        setTimeout(() => resolve('timeout'), 3000);
      });
      await new Promise((resolve) => {
        const onData = (d) => {
          got += d.toString('latin1');
          if (got.includes('\r\n\r\n')) {
            sock.removeListener('data', onData);
            sock.write('hello-through-tunnel');
            resolve();
          }
        };
        sock.on('data', onData);
      });
      const echo = await echoPromise;
      assert.strictEqual(echo, 'pong');
      assert.ok(seen.includes('hello-through-tunnel'), 'tunneled bytes reached the upstream');
      sock.destroy();
    } finally {
      await stop();
      target.close();
    }
  });

  await test('proxy blocks an IP CONNECT by its ClientHello SNI (fail-closed decision)', async () => {
    const target = net.createServer();
    await new Promise((r) => target.listen(0, '127.0.0.1', r));
    const targetPort = target.address().port;
    let targetGotData = false;
    target.on('connection', (s) => { s.on('data', () => { targetGotData = true; }); });

    const { port } = await start({ port: 0, blockFn: (n) => n === 'evil.example.com' });
    try {
      const sock = net.connect(port, '127.0.0.1');
      await new Promise((r, j) => { sock.once('connect', r); sock.once('error', j); });
      sock.write('CONNECT 127.0.0.1:' + targetPort + ' HTTP/1.1\r\n\r\n');
      let closed = false;
      await new Promise((resolve) => {
        sock.on('data', (d) => {
          if (d.toString('latin1').includes('200 Connection established')) {
            sock.write(buildClientHello('evil.example.com'));
          }
        });
        sock.on('close', () => { closed = true; resolve(); });
        sock.on('error', () => {});
        setTimeout(() => resolve(), 4000);
      });
      assert.strictEqual(closed, true, 'blocked SNI tunnel must be closed');
      await sleep(150);
      assert.strictEqual(targetGotData, false, 'no bytes may reach the upstream for a blocked SNI');
      sock.destroy();
    } finally {
      await stop();
      target.close();
    }
  });

  /* -------------------------------- pf rules -------------------------------- */

  await test('pf rules drop UDP 443 (QUIC) only while proxyBlock is on', () => {
    const withProxy = pf.buildAnchorRules({ proxyBlock: true });
    assert.ok(withProxy.includes('block out proto udp to port 443'));
    assert.ok(withProxy.includes('pass out proto tcp to port 443'));
    const withoutProxy = pf.buildAnchorRules({ proxyBlock: false });
    assert.ok(!withoutProxy.includes('block out proto udp to port 443'));
  });

  await test('safety floor forces proxyBlock on and drops a port-443 allow entry', () => {
    const floor = pf.safetyFloor({ allowPorts: [443, 8443], proxyBlock: false });
    assert.strictEqual(floor.proxyBlock, true);
    assert.ok(!floor.allowPorts.includes(443), '443 must not be allowlisted (would pass QUIC)');
    assert.ok(floor.allowPorts.includes(8443));
    assert.strictEqual(floor.changed, true);
  });

  await test('safety floor leaves proxyBlock alone when already true', () => {
    const floor = pf.safetyFloor({ proxyBlock: true });
    assert.strictEqual(floor.proxyBlock, true);
  });

  /* --------------------------- win command builders ------------------------- */

  await test('proxyops-win setAutoProxyCmd points AutoConfigURL at the PAC', () => {
    const cmd = win.setAutoProxyCmd('S-1-5-21-123-456', 'http://127.0.0.1:42792/proxy.pac');
    // The registry path is embedded JSON-escaped (double backslashes).
    assert.ok(cmd.includes('HKEY_USERS\\\\S-1-5-21-123-456\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings'));
    assert.ok(cmd.includes('AutoConfigURL'));
    assert.ok(cmd.includes('http://127.0.0.1:42792/proxy.pac'));
    assert.ok(cmd.includes('ProxyEnable -Value 1'));
  });

  await test('proxyops-win setProxyStateCmd restores an empty prior state', () => {
    const cmd = win.setProxyStateCmd('S-1-5-21-123-456', { enabled: false, url: '' });
    assert.ok(cmd.includes('Remove-ItemProperty'));
    assert.ok(cmd.includes('ProxyEnable -Value 0'));
  });

  await test('proxyops-win listHivesCmd filters built-in SIDs', () => {
    const cmd = win.listHivesCmd();
    assert.ok(cmd.includes('S-1-5-18'));
    assert.ok(cmd.includes('.DEFAULT'));
  });

  console.log('');
  console.log(passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => { console.error(err); process.exit(1); });
