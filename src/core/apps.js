/* Auren — apps.js
 *
 * App-blocking logic shared between the desktop app (writer) and the root
 * DNS daemon (enforcer). Everything here is pure and unit-testable: entry
 * validation, `ps` line parsing, and process matching. The actual `kill`
 * lives in the daemon (src/dns/daemon.js).
 *
 * Data model — one block entry:
 *   { id:   <bundle ID, e.g. "com.apple.Safari">,
 *     name: <display name>,
 *     path: <absolute executable path, or null> }
 *
 * Matching (the daemon scans `ps -axo pid=,command=`):
 *   - exact executable path,
 *   - executable basename (a macOS binary is usually named after the app),
 *   - any argv token equal to the executable path (node/py launcher scripts).
 * There is NO substring matching: "Discord" never matches "Discord Web".
 *
 * Honest limits (see README "App blocking"): a blocked app that renames or
 * relocates its binary stops matching. Blocking is cooperative — an agent
 * with root / deep OS access can bypass it, and an entry with no executable
 * path (bare bundle ID) can't match any process at all.
 */

'use strict';
const path = require('path');

// Validate one block entry. Accepts an entry object { id, name, path } or a
// bare string (a bundle ID, or an absolute executable path). Returns
// { ok: true, entry } or { ok: false, error }.
function validateBlockApp(input) {
  if (!input) return { ok: false, error: 'Pick an app to block.' };
  let entry;
  if (typeof input === 'string') {
    const s = String(input).trim();
    if (!s) return { ok: false, error: 'Pick an app to block.' };
    if (/\s/.test(s)) return { ok: false, error: 'Enter a bundle ID or app path with no spaces.' };
    // A path becomes its own entry; a bare token is treated as a bundle ID.
    // For a path the ID is derived from the executable name, so it can never
    // contain the slash that would fail ID validation below.
    entry = s.includes('/')
      ? { id: path.basename(s), name: path.basename(s), path: s }
      : { id: s, name: s, path: null };
  } else if (input && typeof input === 'object') {
    const id = String(input.id || '').trim();
    const name = String(input.name || '').trim();
    const p = input.path != null ? String(input.path).trim() : '';
    if (!id) return { ok: false, error: 'That app is missing a bundle ID.' };
    if (!name) return { ok: false, error: 'That app is missing a name.' };
    entry = { id, name, path: p || null };
  } else {
    return { ok: false, error: 'Pick an app to block.' };
  }
  if (!/^[A-Za-z0-9._-]+$/.test(entry.id)) {
    return { ok: false, error: 'That bundle ID looks malformed.' };
  }
  return { ok: true, entry };
}

// Keep only well-formed, deduplicated entries. Run on every read so a
// tampered file can never smuggle a malformed entry into the kill loop.
function normalizeAppBlocklist(list) {
  const seen = new Set();
  const out = [];
  for (const item of (Array.isArray(list) ? list : [])) {
    const r = validateBlockApp(item);
    if (!r.ok) continue;
    if (seen.has(r.entry.id)) continue;
    seen.add(r.entry.id);
    out.push(r.entry);
  }
  return out;
}

// One line of `ps -axo pid=,command=`. Returns { pid, exe, tokens } or null
// when the line isn't a process (or is a system placeholder we never touch).
function parsePsLine(line) {
  const s = String(line || '');
  const m = /^\s*(\d+)\s+(.+)$/.exec(s);
  if (!m) return null;
  const pid = Number(m[1]);
  if (!Number.isFinite(pid) || pid <= 0) return null;
  const tokens = m[2].trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) return null;
  return { pid, exe: tokens[0], tokens };
}

// Does a running process match a blocked entry? Exact executable path,
// basename, or an argv token equal to the executable path. No substrings.
function exeMatches(exe, tokens, entry) {
  if (!entry || !entry.path || !exe) return false;
  const ePath = entry.path;
  if (exe === ePath) return true;
  if (path.basename(exe) === path.basename(ePath)) return true;
  return (tokens || []).some((t) => t === ePath);
}

// Which running PIDs (from ps lines) belong to a blocked app? Never the
// caller's own pid and never a protected executable (the daemon interpreter).
function findBlockedPids(psLines, appBlocklist, opts) {
  const procs = (Array.isArray(psLines) ? psLines : []).map(parsePsLine).filter(Boolean);
  return findBlockedProcesses(procs, appBlocklist, opts);
}

// Which running processes (descriptors from src/platform/procs-*) belong to a
// blocked app? Same guarantees as findBlockedPids, but the descriptors — not
// raw ps text — come from the caller, so macOS `ps` and Windows CIM can both
// feed it. A descriptor is { pid, exe, tokens }.
function findBlockedProcesses(procs, appBlocklist, opts) {
  const selfPid = (opts && opts.selfPid) || 0;
  const protectedExes = new Set((opts && opts.protectedExes) || []);
  const blocked = normalizeAppBlocklist(appBlocklist);
  const hits = [];
  for (const p of (Array.isArray(procs) ? procs : [])) {
    if (!p || !p.pid || p.pid <= 1 || p.pid === selfPid) continue;
    if (protectedExes.has(p.exe)) continue;
    for (const entry of blocked) {
      if (exeMatches(p.exe, p.tokens, entry)) {
        hits.push({ pid: p.pid, exe: p.exe, entry });
        break;
      }
    }
  }
  return hits;
}

// Root-enforced floor: never let a blocked entry kill Auren's own daemon
// interpreter (Electron / node), no matter what a forged config claims.
function appSafetyFloor(entries, opts) {
  const selfExes = new Set(
    (opts && Array.isArray(opts.selfExes) ? opts.selfExes : [])
      .map((e) => String(e || '').trim()).filter(Boolean)
  );
  const dropped = [];
  const kept = [];
  for (const entry of normalizeAppBlocklist(entries)) {
    if (entry.path && selfExes.has(entry.path)) { dropped.push(entry); continue; }
    kept.push(entry);
  }
  return { appBlocklist: kept, dropped, changed: dropped.length > 0 };
}

module.exports = { validateBlockApp, normalizeAppBlocklist, parsePsLine, exeMatches, findBlockedPids, findBlockedProcesses, appSafetyFloor };
