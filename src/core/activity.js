/* Auren — activity.js
 *
 * Plain-language local activity log (JSONL). Only ever records a domain name,
 * a timestamp, and an outcome — never any content, credentials, or biometric
 * data. Appended to by both the desktop app (Protection Mode changes) and the
 * root DNS daemon (block events).
 *
 * The log is intentionally local and best-effort: it is an audit trail for
 * "what did the guardrail do and when", not a tamper-proof store.
 */

'use strict';
const fs = require('fs');
const path = require('path');

// kinds: 'block' (a lookup was refused), 'toggle' (protection mode change),
//        'daemon' (resolver lifecycle / errors)
// outcome: for block -> 'blocked' | 'allowed'; for toggle -> 'on' | 'off' |
//          'off_pending' (verified, waiting out the cooldown) | 'off_failed' |
//          'off_cancelled'; for daemon -> 'started' | 'stopped'
//          | 'error' | 'dns_applied' | 'dns_restored'
function makeEntry(kind, outcome, domain, note) {
  return { ts: new Date().toISOString(), kind, outcome, domain: domain || null, note: note || null };
}

function appendActivity(file, entry) {
  if (!file) return;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const line = JSON.stringify({ ts: entry.ts || new Date().toISOString(), kind: entry.kind, outcome: entry.outcome, domain: entry.domain || null, note: entry.note || null }) + '\n';
  fs.appendFileSync(file, line, 'utf8');
}

function readActivity(file, limit) {
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch (err) { if (err.code !== 'ENOENT') throw err; return []; }
  const lines = text.split('\n').filter((l) => l.trim().length > 0);
  const out = [];
  for (const line of lines.slice(-(limit || 200))) {
    try { out.push(JSON.parse(line)); } catch { /* skip malformed line */ }
  }
  return out;
}

// Plain-language line for the UI, e.g. "Blocked: attempt to reach bank.com".
function toPlainText(entry) {
  const t = entry.ts ? new Date(entry.ts).toLocaleString() : '';
  const time = t || '';
  switch (entry.kind) {
    case 'block':
      return `Blocked: attempt to reach ${entry.domain} \u00b7 ${time}`;
    case 'toggle':
      if (entry.outcome === 'on') return `Protection turned on \u00b7 ${time}`;
      if (entry.outcome === 'off') return `Protection turned off (verified by fingerprint or passcode) \u00b7 ${time}`;
      if (entry.outcome === 'off_pending') return `Protection-off verified \u2014 sites stay blocked for 10 seconds \u00b7 ${time}`;
      if (entry.outcome === 'off_failed') return `Protection-off request did not pass verification \u00b7 ${time}`;
      if (entry.outcome === 'off_cancelled') return `Protection-off request cancelled \u00b7 ${time}`;
      if (entry.outcome === 'on_failed') return `Protection-on request did not finish (background service setup declined) \u00b7 ${time}`;
      return `Protection change \u00b7 ${time}`;
    case 'daemon':
      if (entry.outcome === 'dns_applied') return `DNS pointing at Auren (system-wide) \u00b7 ${time}`;
      if (entry.outcome === 'dns_restored') return `DNS restored to normal \u00b7 ${time}`;
      if (entry.outcome === 'error') return `Auren background service error${entry.note ? ': ' + entry.note : ''} \u00b7 ${time}`;
      return `Auren background service ${entry.outcome} \u00b7 ${time}`;
    default:
      return (entry.note || entry.outcome || 'event') + (time ? ' \u00b7 ' + time : '');
  }
}

module.exports = { makeEntry, appendActivity, readActivity, toPlainText };
