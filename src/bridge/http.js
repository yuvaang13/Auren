/* Auren - bridge/http.js
 *
 * The loopback HTTP bridge: a tiny read/gate-only HTTP server bound to
 * 127.0.0.1 inside the Electron main process. It exposes Auren's agent gates
 * (the same decisions as the IPC handlers, via src/core/agentgate.js) so any
 * local agent framework or tool can route its actions and commands through
 * Auren: "watch it block a live agent action."
 *
 * This module is deliberately Electron-free so it can be unit-tested under
 * plain Node. It only needs an http.Server, a token, and a handlers object.
 *
 * Security posture:
 *   - Binds 127.0.0.1 only; non-loopback peers are rejected outright.
 *   - Every route (except errors) requires `Authorization: Bearer <token>`,
 *     compared with a constant-time check.
 *   - Read/gate-only: it exposes NO write surface (no mode:set, no blocklist
 *     edits). The worst a leaked token enables is a local process asking Auren
 *     for a decision — which is the point.
 *   - Request bodies are capped (1 MB) and must be JSON.
 *   - Any handler failure responds fail-closed ({ allowed: false }).
 *   - Every decision is logged to the activity log by the caller's logFn.
 *
 * Routes:
 *   GET  /v1/status               -> { app, version, mode, degraded, bridge }
 *   GET  /v1/blocked?domain=...   -> { blocked }
 *   POST /v1/check/action         body { url?, data? }  -> decision
 *   POST /v1/check/command        body { command } (or raw string) -> decision
 */

'use strict';

const http = require('http');
const crypto = require('crypto');

const DEFAULT_PORT = 42791;
const MAX_BODY_BYTES = 1024 * 1024;

let server = null;
let token = '';
let handlers = {};
let info = { running: false, port: null };

function isLoopback(ip) {
  const ip4 = String(ip || '').replace(/^::ffff:/, '');
  return ip4 === '127.0.0.1' || ip4 === '::1' || ip4 === 'localhost';
}

function tokenOk(req) {
  if (!token) return false;
  const auth = String(req.headers.authorization || '');
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return false;
  const a = Buffer.from(m[1]);
  const b = Buffer.from(token);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) { req.destroy(); reject(new Error('payload too large')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function route(req, res) {
  if (!isLoopback(req.socket.remoteAddress)) {
    sendJson(res, 403, { error: 'loopback only' });
    return;
  }
  if (!tokenOk(req)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }

  let url;
  try { url = new URL(req.url, 'http://127.0.0.1'); }
  catch { sendJson(res, 400, { error: 'bad request' }); return; }
  const routePath = url.pathname;

  if (req.method === 'GET' && routePath === '/v1/status') {
    sendJson(res, 200, handlers.getStatus ? handlers.getStatus() : { running: info.running, port: info.port });
    return;
  }

  if (req.method === 'GET' && routePath === '/v1/blocked') {
    const domain = url.searchParams.get('domain') || '';
    const blocked = handlers.isBlocked ? handlers.isBlocked(domain) : false;
    sendJson(res, 200, { blocked });
    return;
  }

  if (req.method === 'POST' && (routePath === '/v1/check/action' || routePath === '/v1/check/command')) {
    readBody(req).then(
      (buf) => {
        let body;
        try { body = buf.length ? JSON.parse(buf.toString('utf8')) : {}; }
        catch { sendJson(res, 400, { error: 'invalid JSON' }); return; }

        let decision;
        if (routePath === '/v1/check/action') {
          decision = handlers.checkAction ? handlers.checkAction(body) : null;
        } else {
          const cmd = (body && body.command != null) ? body.command : body;
          decision = handlers.checkCommand ? handlers.checkCommand(cmd) : null;
        }
        if (decision === null) { sendJson(res, 404, { error: 'not found' }); return; }
        Promise.resolve(decision).then(
          (r) => sendJson(res, 200, r),
          () => sendJson(res, 503, { allowed: false, action: 'block', types: [], reason: 'bridge error' })
        );
      },
      () => sendJson(res, 413, { error: 'payload too large' })
    );
    return;
  }

  sendJson(res, 404, { error: 'not found' });
}

// opts: { port, token, handlers: { getStatus, isBlocked, checkAction, checkCommand } }
// Resolves { port } with the actual bound port. port 0 (or null/undefined)
// binds an ephemeral port; anything else is used as given.
function start(opts = {}) {
  return new Promise((resolve, reject) => {
    if (server) { resolve({ port: info.port }); return; }
    token = opts.token || '';
    handlers = opts.handlers || {};
    server = http.createServer(route);
    server.on('error', (err) => { server = null; reject(err); });
    const port = opts.port == null ? DEFAULT_PORT : opts.port;
    server.listen(port, '127.0.0.1', () => {
      info = { running: true, port: server.address().port };
      resolve({ port: info.port });
    });
  });
}

function stop() {
  return new Promise((resolve) => {
    if (!server) { resolve(); return; }
    const s = server;
    // Don't let keep-alive sockets keep the server (or an app quit) hanging.
    if (typeof s.closeAllConnections === 'function') {
      try { s.closeAllConnections(); } catch { /* ignore */ }
    }
    s.close(() => {
      server = null;
      info = { running: false, port: null };
      resolve();
    });
  });
}

function status() {
  return { running: info.running, port: info.port };
}

module.exports = { DEFAULT_PORT, start, stop, status };
