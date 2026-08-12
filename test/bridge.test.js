/* Auren - loopback agent bridge tests (src/bridge/http.js).
 *
 * Run: node test/bridge.test.js (or npm run test:bridge). Boots the bridge on
 * an ephemeral port with stub handlers (no Electron) and exercises the HTTP
 * surface: routes, bearer-token auth, malformed input, and fail-closed errors.
 */
'use strict';
const assert = require('assert');
const httpBridge = require('../src/bridge/http');

let passed = 0;
let failed = 0;

function test(name, fn) {
  return Promise.resolve(fn()).then(
    () => { passed += 1; console.log('  ok   ' + name); },
    (err) => { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (err && (err.stack || err.message))); }
  );
}

const TOKEN = 'test-token-0123456789abcdef';
let base = null;

async function withServer(fn) {
  base = await httpBridge.start({
    port: 0,
    token: TOKEN,
    handlers: {
      getStatus: () => ({ app: 'auren', version: '0.0.0-test', mode: 'on', degraded: false, bridge: { running: true, port: httpBridge.status().port } }),
      checkAction: (payload) => Promise.resolve({ allowed: payload && payload.block ? false : true, action: 'allow', types: [], reason: 'test' }),
      checkCommand: (cmd) => Promise.resolve({ allowed: String(cmd || '').includes('ssh') ? false : true, action: String(cmd || '').includes('ssh') ? 'block' : 'allow', types: String(cmd || '').includes('ssh') ? ['cmd_ssh'] : [], reason: 'test' }),
      isBlocked: (domain) => domain === 'bank.com'
    }
  });
  try { return await fn('http://127.0.0.1:' + base.port); }
  finally { await httpBridge.stop(); }
}

function authed(fetchOpts) {
  return Object.assign({}, fetchOpts, { headers: Object.assign({}, fetchOpts && fetchOpts.headers, { Authorization: 'Bearer ' + TOKEN }) });
}

async function run() {
  console.log('agent bridge (loopback HTTP)');

  await test('starts on an ephemeral port and reports status', () => withServer(async (baseUrl) => {
    const res = await fetch(baseUrl + '/v1/status', authed({}));
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.app, 'auren');
    assert.strictEqual(body.mode, 'on');
    assert.strictEqual(body.bridge.port, httpBridge.status().port);
  }));

  await test('rejects requests without a token', () => withServer(async (baseUrl) => {
    const res = await fetch(baseUrl + '/v1/status');
    assert.strictEqual(res.status, 401);
  }));

  await test('rejects requests with a wrong token', () => withServer(async (baseUrl) => {
    const res = await fetch(baseUrl + '/v1/status', { headers: { Authorization: 'Bearer wrong-token' } });
    assert.strictEqual(res.status, 401);
  }));

  await test('check/command returns the gate decision', () => withServer(async (baseUrl) => {
    const blocked = await (await fetch(baseUrl + '/v1/check/command', authed({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: 'ssh user@evil.com' }) }))).json();
    assert.strictEqual(blocked.allowed, false);
    assert.deepStrictEqual(blocked.types, ['cmd_ssh']);
    const ok = await (await fetch(baseUrl + '/v1/check/command', authed({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: 'ls -la' }) }))).json();
    assert.strictEqual(ok.allowed, true);
  }));

  await test('check/action returns the gate decision', () => withServer(async (baseUrl) => {
    const res = await fetch(baseUrl + '/v1/check/action', authed({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://shop.example.com', data: { card: '4111111111111111' } }) }));
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.allowed, true);
  }));

  await test('blocked endpoint answers the read-only isBlocked check', () => withServer(async (baseUrl) => {
    const hit = await (await fetch(baseUrl + '/v1/blocked?domain=bank.com', authed({}))).json();
    assert.strictEqual(hit.blocked, true);
    const miss = await (await fetch(baseUrl + '/v1/blocked?domain=example.com', authed({}))).json();
    assert.strictEqual(miss.blocked, false);
  }));

  await test('malformed JSON returns 400', () => withServer(async (baseUrl) => {
    const res = await fetch(baseUrl + '/v1/check/command', authed({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json' }));
    assert.strictEqual(res.status, 400);
  }));

  await test('unknown routes return 404', () => withServer(async (baseUrl) => {
    const res = await fetch(baseUrl + '/v1/nope', authed({}));
    assert.strictEqual(res.status, 404);
  }));

  await test('stop() tears the server down', async () => {
    const s = await httpBridge.start({ port: 0, token: TOKEN, handlers: {} });
    assert.strictEqual(httpBridge.status().running, true);
    await httpBridge.stop();
    assert.strictEqual(httpBridge.status().running, false);
    await assert.rejects(fetch('http://127.0.0.1:' + s.port + '/v1/status'));
  });

  console.log('');
  console.log(passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
}

run();
