/* Auren — proxy/server.js
 *
 * The loopback HTTPS-blocking proxy. Runs inside the root daemon, bound to
 * 127.0.0.1 only, and is the enforcement point for hostname blocking against
 * HTTPS traffic — which DNS (the other main gate) cannot see because HTTPS
 * encrypts the request line and URL. The block list still comes from the same
 * signed config; the proxy just makes it apply to CONNECT tunnels.
 *
 * Model:
 *   - The system proxy is pointed (via PAC) at this server while Protection
 *     Mode is ON, so browsers and proxy-honoring apps route HTTPS through it.
 *   - The proxy is a strict CONNECT tunnel. It NEVER terminates TLS and NEVER
 *     decrypts anything. For a domain CONNECT it blocks on the CONNECT host;
 *     for an IP CONNECT it reads the client's ClientHello and blocks on the
 *     SNI hostname. Non-blocked tunnels are piped through byte-for-byte.
 *   - Fail-closed: when the destination hostname cannot be determined (unread-
 *     able ClientHello, non-TLS data over a CONNECT) the tunnel is refused, and
 *     any proxy or PAC failure leaves HTTPS unable to connect at all (never
 *     silently passing traffic around the block).
 *   - Serves /proxy.pac on the same port so system proxy config points at one
 *     stable URL with no extra HTTP server.
 *
 * Security posture:
 *   - Binds 127.0.0.1; non-loopback peers are destroyed immediately.
 *   - No MITM: a blocked tunnel is refused with 403; nothing is observed.
 *   - The block decision is always the daemon's (blockFn) — this module holds
 *     no policy of its own.
 */

'use strict';

const net = require('net');
const sni = require('./sni');

const DEFAULT_PORT = 42792;
const HEADER_TIMEOUT_MS = 10000;
const MAX_HEAD_BYTES = 16384;

let server = null;
let ctx = {};
let info = { running: false, port: null };

// Pure PAC builder. HTTPS only goes to the proxy; everything else stays
// DIRECT (HTTP/80 is already blocked at the DNS layer, and forcing it through
// the proxy would add a failure point for no enforcement gain).
function buildPac(port) {
  const p = Number(port) || DEFAULT_PORT;
  return 'function FindProxyForURL(url, host) {\n'
    + "  if (url.substring(0, 6).toLowerCase() === 'https:') return 'PROXY 127.0.0.1:" + p + "';\n"
    + "  return 'DIRECT';\n"
    + '}\n';
}

// Parse a CONNECT request line. Returns { host, port } or null. Accepts
// bracketed IPv6 authorities (CONNECT [::1]:443) and strips the brackets.
function parseConnectLine(line) {
  const m = /^CONNECT\s+(\S+):(\d{1,5})\s+HTTP\/\d\.\d$/i.exec(String(line || '').trim());
  if (!m) return null;
  const port = parseInt(m[2], 10);
  if (!(port >= 1 && port <= 65535)) return null;
  let host = m[1];
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (!host) return null;
  return { host, port };
}

function isLoopback(ip) {
  const ip4 = String(ip || '').replace(/^::ffff:/, '');
  return ip4 === '127.0.0.1' || ip4 === '::1';
}

function respond(socket, status) {
  const head = status === 200
    ? 'HTTP/1.1 200 Connection established\r\nProxy-Agent: auren\r\n\r\n'
    : 'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
  socket.write(head);
}

// Byte-for-byte tunnel. `pre` (ClientHello bytes already read for an IP-CONNECT
// SNI decision) is written upstream first, then both sides are piped. Either
// side dying destroys the other.
function tunnel(socket, host, port, pre) {
  const upstream = net.connect({ host, port });
  let connected = false;
  upstream.on('connect', () => {
    connected = true;
    if (pre && pre.length) upstream.write(pre);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => { if (connected) upstream.destroy(); });
  socket.on('close', () => { if (connected) upstream.destroy(); });
}

// CONNECT to an IP literal: the authority tells us nothing, so decide from the
// ClientHello SNI after the 200. Unreadable / missing SNI is fail-closed.
function handleIpConnect(socket, req, pre) {
  let buffer = pre || Buffer.alloc(0);
  let done = false;
  const timer = setTimeout(() => { if (!done) socket.destroy(); }, HEADER_TIMEOUT_MS);

  const decide = () => {
    const host = sni.parseSni(buffer);
    if (host) {
      done = true;
      clearTimeout(timer);
      socket.removeAllListeners('data');
      if (ctx.blockFn(host)) {
        if (ctx.onBlocked) ctx.onBlocked(host);
        socket.destroy();
        return;
      }
      tunnel(socket, req.host, req.port, buffer);
      return;
    }
    if (buffer.length >= MAX_HEAD_BYTES) {
      done = true;
      clearTimeout(timer);
      if (ctx.onUnreadable) ctx.onUnreadable();
      socket.destroy();
    }
  };

  socket.on('data', (chunk) => {
    if (done) return;
    buffer = Buffer.concat([buffer, chunk]);
    decide();
  });
  socket.on('error', () => { clearTimeout(timer); });
  socket.resume();
  if (buffer.length) decide();
}

function handleConnect(socket, line, pre) {
  const req = parseConnectLine(line);
  if (!req) { socket.write('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'); socket.end(); return; }
  if (net.isIP(req.host) > 0) {
    respond(socket, 200);
    handleIpConnect(socket, req, pre);
    return;
  }
  const host = String(req.host).toLowerCase().replace(/\.+$/, '');
  if (ctx.blockFn(host)) {
    if (ctx.onBlocked) ctx.onBlocked(host);
    respond(socket, 403);
    socket.end();
    return;
  }
  respond(socket, 200);
  tunnel(socket, req.host, req.port);
}

function servePac(socket) {
  const body = Buffer.from(buildPac(info.port || DEFAULT_PORT), 'utf8');
  socket.write('HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n'
    + 'Content-Length: ' + body.length + '\r\nConnection: close\r\n\r\n');
  socket.end(body);
}

function handleSocket(socket) {
  if (!isLoopback(socket.remoteAddress)) { socket.destroy(); return; }
  let head = '';
  let timer = setTimeout(() => socket.destroy(), HEADER_TIMEOUT_MS);
  socket.on('error', () => { clearTimeout(timer); });
  socket.on('data', (chunk) => {
    head += chunk.toString('latin1');
    const lineEnd = head.indexOf('\r\n');
    if (lineEnd === -1) {
      if (head.length >= MAX_HEAD_BYTES) socket.destroy();
      return;
    }
    clearTimeout(timer);
    const line = head.slice(0, lineEnd);
    // The tunnel payload is everything after the header block terminator
    // (\r\n\r\n), NOT after the request line — otherwise a bare
    // 'CONNECT ... HTTP/1.1\r\n\r\n' would leak a stray '\r\n' into the stream
    // and corrupt the ClientHello the SNI parser reads for IP CONNECTs.
    const headEnd = head.indexOf('\r\n\r\n');
    const pre = headEnd === -1 ? Buffer.alloc(0) : Buffer.from(head.slice(headEnd + 4), 'latin1');
    // Stop the socket from flowing before we detach the head collector: with
    // no 'data' listener attached, bytes arriving before the tunnel pipe (or
    // SNI listener) attaches would be emitted to nobody and silently dropped.
    socket.removeAllListeners('data');
    socket.pause();
    if (/^CONNECT\s+/i.test(line)) {
      handleConnect(socket, line, pre);
    } else if (/^GET\s+\/proxy\.pac\s+HTTP/i.test(line)) {
      servePac(socket);
    } else {
      socket.write('HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
      socket.end();
    }
  });
}

// opts: { port, blockFn(name)->bool, onBlocked(name), onUnreadable() }
// Resolves { port } with the actual bound port.
function start(opts = {}) {
  return new Promise((resolve, reject) => {
    if (server) { resolve({ port: info.port }); return; }
    ctx = {
      blockFn: typeof opts.blockFn === 'function' ? opts.blockFn : () => false,
      onBlocked: typeof opts.onBlocked === 'function' ? opts.onBlocked : null,
      onUnreadable: typeof opts.onUnreadable === 'function' ? opts.onUnreadable : null
    };
    server = net.createServer(handleSocket);
    server.on('error', (err) => { server = null; info = { running: false, port: null }; reject(err); });
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
    server = null;
    info = { running: false, port: null };
    let finished = false;
    const finish = () => { if (!finished) { finished = true; resolve(); } };
    const forceClose = () => {
      try { if (typeof s.closeAllConnections === 'function') s.closeAllConnections(); } catch { /* ignore */ }
    };
    forceClose();
    s.close(finish);
    // A tunneled connection stuck in a weird state (half-open TCP, a client
    // mid-handshake, an aborted pipe) can keep net.Server.close()'s callback
    // pending forever. The daemon's reconcile loop awaits this — an unwedged
    // stop is the whole point, so force-destroy stragglers after a short grace
    // period and resolve regardless. The old sockets are orphaned, never the
    // reconcile loop.
    setTimeout(() => { forceClose(); finish(); }, 1000);
  });
}

function status() {
  return { running: info.running, port: info.port };
}

module.exports = { DEFAULT_PORT, buildPac, parseConnectLine, start, stop, status };
