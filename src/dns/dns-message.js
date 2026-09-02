/* Auren — dns-message.js
 *
 * Minimal DNS wire-format helpers. This is a small, deliberately narrow
 * implementation: we only need to (a) read the query name out of a request,
 * (b) build an NXDOMAIN response for blocked names, and (c) forward
 * everything else verbatim to an upstream resolver. We do not implement DNS
 * zone serving, caching, or any security-sensitive parsing beyond what these
 * three jobs require.
 */

'use strict';

function readU16(buf, offset) {
  return (buf[offset] << 8) | buf[offset + 1];
}

function readU32(buf, offset) {
  return ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
}

// Parses a domain name starting at `offset`. Returns { name, endOffset }
// where endOffset points just past the QNAME field (i.e. at QTYPE/QCLASS).
// Compression pointers are followed for the name value but do not advance
// endOffset past the pointer itself.
function parseName(buf, offset, depth) {
  let pos = offset;
  let endOffset = -1;
  const labels = [];
  const seen = new Set();
  depth = depth || 0;
  while (true) {
    if (pos + 1 > buf.length) return null;
    const len = buf[pos];
    if ((len & 0xc0) === 0xc0) {
      if (pos + 2 > buf.length) return null;
      if (endOffset === -1) endOffset = pos + 2;
      if (depth > 64) return null;
      const target = ((len & 0x3f) << 8) | buf[pos + 1];
      if (seen.has(target)) return null;
      seen.add(target);
      pos = target;
      depth += 1;
      continue;
    }
    if (len === 0) {
      if (endOffset === -1) endOffset = pos + 1;
      break;
    }
    if ((len & 0xc0) !== 0 || pos + 1 + len > buf.length) return null;
    labels.push(buf.toString('ascii', pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  return { name: labels.join('.').toLowerCase(), endOffset };
}

function encodeName(name) {
  const labels = String(name).replace(/\.$/, '').split('.');
  const parts = [];
  for (const label of labels) {
    const b = Buffer.from(label, 'ascii');
    if (b.length > 63) return null;
    parts.push(Buffer.from([b.length]), b);
  }
  return Buffer.concat([...parts, Buffer.from([0])]);
}

// Extracts the first question (if any) from a DNS message.
function extractQuestion(buf) {
  if (buf.length < 12) return null;
  const id = readU16(buf, 0);
  const flags = readU16(buf, 2);
  const qdcount = readU16(buf, 4);
  if (qdcount < 1) return null;
  const parsed = parseName(buf, 12);
  if (!parsed || parsed.endOffset + 4 > buf.length) return null;
  return {
    id,
    flags,
    qname: parsed.name,
    qtype: readU16(buf, parsed.endOffset),
    qclass: readU16(buf, parsed.endOffset + 2)
  };
}

// Header block for a reply that echoes the client's RD flag.
const REPLY_FLAGS = 0x8000 | 0x0080; // QR=1, RA=1

function buildReply(id, rcode, qname, qtype, qclass, origFlags) {
  const question = encodeName(qname || '.');
  if (!question) return null;
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  const rd = origFlags != null ? (origFlags & 0x0100) : 0;
  header.writeUInt16BE(REPLY_FLAGS | rd | (rcode & 0xf), 2);
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(0, 6); // ANCOUNT
  header.writeUInt16BE(0, 8); // NSCOUNT
  header.writeUInt16BE(0, 10); // ARCOUNT
  const t = Buffer.alloc(4);
  t.writeUInt16BE(qtype || 1, 0);
  t.writeUInt16BE(qclass || 1, 2);
  return Buffer.concat([header, question, t]);
}

// Builds an NXDOMAIN (refused-to-resolve) response. rcode 3 = NXDOMAIN.
function buildNxdomain(id, qname, qtype, qclass, origFlags) {
  return buildReply(id, 3, qname, qtype, qclass, origFlags);
}

function buildRefused(id, qname, qtype, qclass, origFlags) {
  return buildReply(id, 5, qname, qtype, qclass, origFlags);
}

// TCP framing: 2-byte big-endian length prefix.
function encodeFrame(buf) {
  const head = Buffer.alloc(2);
  head.writeUInt16BE(buf.length, 0);
  return Buffer.concat([head, buf]);
}

module.exports = { readU16, readU32, parseName, encodeName, extractQuestion, buildNxdomain, buildRefused, encodeFrame };
