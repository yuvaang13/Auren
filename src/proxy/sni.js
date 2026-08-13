/* Auren — sni.js
 *
 * Minimal, pure TLS SNI extraction. The HTTPS-blocking proxy (src/proxy/
 * server.js) uses it to learn the destination hostname of a CONNECT tunnel
 * that targets a raw IP — where the CONNECT authority tells us nothing — by
 * reading the client's ClientHello without terminating TLS and without
 * decrypting anything.
 *
 * It understands exactly one message: the ClientHello record. Everything else
 * returns null. Truncated / non-TLS / SNI-less input is indistinguishable from
 * "cannot see a hostname here" and callers treat that as fail-closed.
 */

'use strict';

const TLS_HANDSHAKE_RECORD = 0x16;
const CH_TYPE = 0x01;
const SNI_EXTENSION = 0x0000;
const HOST_NAME_TYPE = 0x00;

function u16(buf, off) {
  return buf.readUInt16BE(off);
}

// Normalize a hostname for blocking: lowercase, single trailing dot stripped,
// empty -> null. Punycode/IDN is left untouched — block lists are ASCII.
function normalize(name) {
  const s = String(name || '').toLowerCase().replace(/\.+$/, '').trim();
  return s || null;
}

// Extract the first SNI host_name from a TLS ClientHello record buffer.
// Returns the hostname (lowercased) or null when no parseable host_name is
// present (non-TLS bytes, truncated record, no SNI extension).
function parseSni(buf) {
  if (!buf || buf.length < 5 || buf[0] !== TLS_HANDSHAKE_RECORD) return null;

  const recordLen = u16(buf, 3);
  if (buf.length < 5 + recordLen) return null;

  let off = 5;
  if (buf[off] !== CH_TYPE) return null;
  const hsLen = (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];
  off += 4;
  const end = Math.min(buf.length, off + hsLen);

  // Skip fixed ClientHello body up to the extensions block.
  off += 2;               // client_version
  off += 32;              // random
  if (off + 1 > end) return null;
  off += 1 + buf[off];    // session_id
  if (off + 2 > end) return null;
  const csLen = u16(buf, off);
  off += 2 + csLen;       // cipher_suites
  if (off + 1 > end) return null;
  off += 1 + buf[off];    // compression_methods
  if (off + 2 > end) return null;
  const extTotal = u16(buf, off);
  off += 2;
  const extEnd = Math.min(end, off + extTotal);

  while (off + 4 <= extEnd) {
    const type = u16(buf, off);
    const len = u16(buf, off + 2);
    off += 4;
    if (off + len > extEnd) return null;
    if (type === SNI_EXTENSION) {
      const name = parseServerNameList(buf, off, len);
      if (name) return name;
    }
    off += len;
  }
  return null;
}

// Inside a server_name extension: 2-byte list length, then entries of
// (1-byte type, 2-byte length, name bytes). Returns the first host_name.
function parseServerNameList(buf, base, len) {
  if (len < 2) return null;
  const listLen = u16(buf, base);
  const listEnd = Math.min(base + 2 + listLen, base + 2 + len);
  let p = base + 2;
  while (p + 3 <= listEnd) {
    const nameType = buf[p];
    const nameLen = u16(buf, p + 1);
    p += 3;
    if (nameType === HOST_NAME_TYPE && p + nameLen <= listEnd) {
      return normalize(buf.toString('ascii', p, p + nameLen));
    }
    p += nameLen;
  }
  return null;
}

module.exports = { parseSni, normalize };
