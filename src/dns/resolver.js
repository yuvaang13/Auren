/* Auren — resolver.js
 *
 * Local DNS server: answers NXDOMAIN for blocked domains and forwards
 * everything else verbatim to an upstream resolver. Runs on 127.0.0.1 so it
 * only ever answers the machine itself, never the wider network.
 *
 * Pure UDP/TCP forwarding: allowed queries are passed through byte-for-byte,
 * so this server does no caching, no record inspection, and no content
 * handling of any kind.
 */

'use strict';
const dgram = require('dgram');
const net = require('net');
const { extractQuestion, buildNxdomain, buildRefused, encodeFrame } = require('./dns-message');

const DEFAULT_UPSTREAM = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];
const PENDING_TTL_MS = 10000;
const MAX_PENDING = 5000;
const MAX_TCP_BUFFER = 65535;

class DnsResolver {
  constructor(opts) {
    this.port = opts.port != null ? opts.port : 53;
    this.host = opts.host || '127.0.0.1';
    this.upstreamPort = opts.upstreamPort || 53;
    this.blockFn = opts.blockFn || (() => false);
    this.upstreamServers = (opts.upstreamServers && opts.upstreamServers.length ? opts.upstreamServers : DEFAULT_UPSTREAM).slice();
    this.onBlocked = opts.onBlocked || (() => {});
    this.onError = opts.onError || (() => {});
    this.udp = null;
    this.tcp = null;
    this.upstreamSocket = null;
    this.upstreamRoundRobin = 0;
    this.pending = new Map(); // id -> [{ qname, client, time }]
    this.running = false;
  }

  async start() {
    if (this.running) return;
    this.udp = dgram.createSocket('udp4');
    this.udp.on('message', (msg, rinfo) => this.handleUdp(msg, rinfo));
    await new Promise((resolve, reject) => {
      this.udp.once('error', reject);
      this.udp.bind(this.port, this.host, () => { this.udp.removeListener('error', reject); resolve(); });
    });

    this.tcp = net.createServer((sock) => this.handleTcp(sock));
    try {
      await new Promise((resolve, reject) => {
        this.tcp.once('error', reject);
        this.tcp.listen(this.port, this.host, () => { this.tcp.removeListener('error', reject); resolve(); });
      });
    } catch (err) {
      // TCP bind failed (e.g. another service on this port) — release the UDP
      // socket we already bound and report failure so DNS is never overridden.
      try { this.udp.close(); } catch {}
      throw err;
    }

    this.upstreamSocket = dgram.createSocket('udp4');
    this.upstreamSocket.on('message', (msg) => this.handleUpstreamReply(msg));
    this.upstreamSocket.on('error', (err) => this.onError(new Error('upstream socket: ' + err.message)));
    this.cleanupTimer = setInterval(() => this.sweepPending(), 5000);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
    this.running = true;
  }

  async stop() {
    if (!this.running) return;
    this.running = false;
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    for (const q of this.pending.values()) {
      for (const p of q) p.client.done = true;
    }
    this.pending.clear();
    const close = (s) => new Promise((res) => { if (!s) return res(); try { s.close(res); } catch { res(); } });
    await close(this.udp);
    await close(this.tcp);
    if (this.upstreamSocket) { try { this.upstreamSocket.close(); } catch {} }
  }

  setBlockFn(fn) { this.blockFn = fn; }
  setUpstream(servers) {
    if (servers && servers.length) {
      this.upstreamServers = servers.slice();
      this.upstreamRoundRobin = 0;
    }
  }

  /* ------------------------------- UDP ------------------------------- */

  // Extract all questions (qdcount may be >1). Returns array of {qname,qtype,qclass}
  extractAllQuestions(msg) {
    if (msg.length < 12) return null;
    const qdcount = (msg[4] << 8) | msg[5];
    if (qdcount < 1 || qdcount > 10) return null; // bound
    let offset = 12;
    const out = [];
    const { parseName } = require('./dns-message');
    for (let i = 0; i < qdcount; i++) {
      const parsed = parseName(msg, offset);
      if (!parsed || parsed.endOffset + 4 > msg.length) return null;
      const qtype = (msg[parsed.endOffset] << 8) | msg[parsed.endOffset + 1];
      const qclass = (msg[parsed.endOffset + 2] << 8) | msg[parsed.endOffset + 3];
      out.push({ qname: parsed.name, qtype, qclass });
      offset = parsed.endOffset + 4;
    }
    return out;
  }

  handleUdp(msg, rinfo) {
    if (msg.length < 12) return;
    const q = extractQuestion(msg);
    if (!q) return;
    const all = this.extractAllQuestions(msg);
    if (all) {
      for (const qq of all) {
        if (this.blockFn(qq.qname)) {
          const reply = buildNxdomain(q.id, qq.qname, qq.qtype, qq.qclass, q.flags) || buildRefused(q.id, qq.qname, qq.qtype, qq.qclass, q.flags);
          if (!reply) {
            const srv = buildRefused(q.id, 'invalid', 1, 1, q.flags);
            if (srv) this.udp.send(srv, rinfo.port, rinfo.address, () => {});
            return;
          }
          this.udp.send(reply, rinfo.port, rinfo.address, () => {});
          this.onBlocked(qq.qname);
          return;
        }
      }
    } else if (this.blockFn(q.qname)) {
      const reply = buildNxdomain(q.id, q.qname, q.qtype, q.qclass, q.flags) || buildRefused(q.id, q.qname, q.qtype, q.qclass, q.flags);
      if (!reply) {
        const srv = buildRefused(q.id, 'invalid', 1, 1, q.flags);
        if (srv) this.udp.send(srv, rinfo.port, rinfo.address, () => {});
        return;
      }
      this.udp.send(reply, rinfo.port, rinfo.address, () => {});
      this.onBlocked(q.qname);
      return;
    }
    this.forwardUdp(msg, q, rinfo);
  }

  forwardUdp(msg, q, rinfo) {
    if (this.pending.size >= MAX_PENDING) {
      const srv = buildRefused(q.id, q.qname, q.qtype, q.qclass, q.flags);
      if (srv) this.udp.send(srv, rinfo.port, rinfo.address, () => {});
      this.onError(new Error('pending overflow'));
      return;
    }
    const server = this.upstreamServers[this.upstreamRoundRobin % this.upstreamServers.length];
    this.upstreamRoundRobin += 1;
    const id = q.id;
    if (!this.pending.has(id)) this.pending.set(id, []);
    this.pending.get(id).push({ qname: q.qname, qtype: q.qtype, qclass: q.qclass, client: { address: rinfo.address, port: rinfo.port }, time: Date.now() });
    this.upstreamSocket.send(msg, this.upstreamPort, server, (err) => {
      if (err) {
        const list = this.pending.get(id);
        let pend = null;
        if (list) {
          // find and remove the matching entry by qname
          const idx = list.findIndex((p) => p.qname === q.qname);
          if (idx !== -1) pend = list.splice(idx, 1)[0];
          else pend = list.shift();
          if (list.length === 0) this.pending.delete(id);
        }
        this.onError(new Error('forward to ' + server + ': ' + err.message));
        const srv = buildRefused(q.id, q.qname, q.qtype, q.qclass, q.flags) || buildRefused(q.id, 'invalid', 1, 1, q.flags);
        if (srv && pend && pend.client && !pend.client.done) {
          this.udp.send(srv, pend.client.port, pend.client.address, () => {});
        }
      }
    });
  }

  handleUpstreamReply(msg) {
    if (msg.length < 12) return;
    const id = (msg[0] << 8) | msg[1];
    const list = this.pending.get(id);
    if (!list || list.length === 0) return;
    // Verify qname matches to avoid ID collision mis-delivery
    const replyQ = extractQuestion(msg);
    let idx = 0;
    if (replyQ) {
      const found = list.findIndex((p) => p.qname === replyQ.qname);
      if (found !== -1) idx = found;
    }
    const pending = list.splice(idx, 1)[0];
    if (list.length === 0) this.pending.delete(id);
    if (pending && pending.client && !pending.client.done) {
      this.udp.send(msg, pending.client.port, pending.client.address, () => {});
    }
  }

  sweepPending() {
    const now = Date.now();
    for (const [id, list] of this.pending.entries()) {
      const fresh = list.filter((p) => now - p.time < PENDING_TTL_MS);
      if (fresh.length) this.pending.set(id, fresh);
      else this.pending.delete(id);
    }
  }

  /* ------------------------------- TCP ------------------------------- */

  handleTcp(sock) {
    let buf = Buffer.alloc(0);
    sock.on('data', (chunk) => {
      if (buf.length + chunk.length > MAX_TCP_BUFFER) { sock.destroy(); return; }
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 2) {
        const len = buf.readUInt16BE(0);
        if (len > 4096) { sock.destroy(); return; }
        if (buf.length < 2 + len) break;
        const frame = buf.slice(2, 2 + len);
        buf = buf.slice(2 + len);
        this.handleTcpFrame(sock, frame);
      }
    });
    sock.on('error', () => {});
  }

  handleTcpFrame(sock, msg) {
    if (msg.length < 12) return;
    const q = extractQuestion(msg);
    if (!q) { sock.end(); return; }
    const all = this.extractAllQuestions(msg);
    if (all) {
      for (const qq of all) {
        if (this.blockFn(qq.qname)) {
          const reply = buildNxdomain(q.id, qq.qname, qq.qtype, qq.qclass, q.flags) || buildRefused(q.id, qq.qname, qq.qtype, qq.qclass, q.flags);
          if (reply) sock.write(encodeFrame(reply));
          else {
            const srv = buildRefused(q.id, 'invalid', 1, 1, q.flags);
            if (srv) sock.write(encodeFrame(srv));
          }
          this.onBlocked(qq.qname);
          return;
        }
      }
    } else if (this.blockFn(q.qname)) {
      const reply = buildNxdomain(q.id, q.qname, q.qtype, q.qclass, q.flags) || buildRefused(q.id, q.qname, q.qtype, q.qclass, q.flags);
      if (reply) sock.write(encodeFrame(reply));
      else {
        const srv = buildRefused(q.id, 'invalid', 1, 1, q.flags);
        if (srv) sock.write(encodeFrame(srv));
      }
      this.onBlocked(q.qname);
      return;
    }
    const server = this.upstreamServers[this.upstreamRoundRobin % this.upstreamServers.length];
    this.upstreamRoundRobin += 1;
    const up = net.createConnection({ host: server, port: this.upstreamPort });
    let relayed = false;
    const done = () => { if (!relayed) { relayed = true; try { up.destroy(); } catch {} } };
    up.on('connect', () => { up.write(encodeFrame(msg)); });
    let uBuf = Buffer.alloc(0);
    up.on('data', (chunk) => {
      uBuf = Buffer.concat([uBuf, chunk]);
      while (uBuf.length >= 2) {
        const len = uBuf.readUInt16BE(0);
        if (uBuf.length < 2 + len) break;
        const frame = uBuf.slice(2, 2 + len);
        uBuf = uBuf.slice(2 + len);
        sock.write(encodeFrame(frame));
        if (!relayed && frame.length >= 2 && frame[0] === msg[0] && frame[1] === msg[1]) {
          relayed = true;
          up.destroy();
        }
      }
    });
    up.on('error', (err) => this.onError(new Error('tcp forward to ' + server + ': ' + err.message)));
    const timer = setTimeout(done, 5000);
    up.on('close', () => { clearTimeout(timer); done(); });
    sock.on('close', done);
  }
}

module.exports = { DnsResolver, DEFAULT_UPSTREAM };
