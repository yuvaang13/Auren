/* Auren — app-resolver.js
 *
 * Resolves a search query to real installed apps: finds `.app` bundles (via
 * Spotlight's mdfind plus a directory scan of the standard app folders) and
 * reads each bundle's Info.plist for the bundle ID and executable path. Runs
 * in the main process only — it shells out to /usr/bin/mdfind and
 * /usr/bin/plutil, which need a user session.
 *
 * Matching is deliberately plain: name or bundle ID contains the query
 * (case-insensitive). Auren never fuzzy-matches process names at block time —
 * the daemon matches exact executables from the resolved entry (core/apps.js).
 */

'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

// Read one string key from a bundle's Info.plist (plutil is the safe way; a
// plist is untrusted XML/ASN.1, so we never parse it by hand). Returns null on
// any failure — a bundle with a broken plist simply won't be offered.
function plistValue(plistPath, key) {
  try {
    const out = execFileSync('/usr/bin/plutil', ['-extract', key, 'raw', '-o', '-', plistPath], { encoding: 'utf8' });
    return String(out || '').trim();
  } catch {
    return null;
  }
}

// Resolve one `.app` bundle to a block entry: bundle ID, display name, and the
// executable inside Contents/MacOS. Returns null if it has no valid plist or
// no bundle ID (so only real apps are ever offered).
function appBundleInfo(bundlePath) {
  const plist = path.join(bundlePath, 'Contents', 'Info.plist');
  if (!fs.existsSync(plist)) return null;
  const id = plistValue(plist, 'CFBundleIdentifier');
  const exe = plistValue(plist, 'CFBundleExecutable');
  if (!id) return null;
  return {
    id,
    name: path.basename(bundlePath).replace(/\.app$/, ''),
    path: exe ? path.join(bundlePath, 'Contents', 'MacOS', exe) : null
  };
}

// The standard places apps live, including one level of nesting
// (System/Applications nests a Utilities folder, etc.).
function scanAppDirs() {
  const dirs = ['/Applications', '/System/Applications', '/System/Applications/Utilities', path.join(os.homedir(), 'Applications')];
  const out = [];
  for (const dir of dirs) {
    let entries = [];
    try { entries = fs.readdirSync(dir); } catch { continue; }
    for (const name of entries) {
      const full = path.join(dir, name);
      if (name.endsWith('.app')) { out.push(full); continue; }
      let sub = [];
      try { sub = fs.readdirSync(full); } catch { continue; }
      for (const subName of sub) {
        if (subName.endsWith('.app')) out.push(path.join(full, subName));
      }
    }
  }
  return out;
}

// Spotlight's index finds apps outside the scanned folders (installed for a
// single user, e.g. managed apps) and is fast. Unavailable on headless/CI
// without a user session — that's fine, the directory scan still works.
function mdfindAppBundles(query) {
  try {
    const q = 'kMDItemContentType == "com.apple.application-bundle" && kMDItemDisplayName == "*' + String(query).replace(/"/g, '\\"') + '*"cd';
    const out = execFileSync('/usr/bin/mdfind', [q], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 8000 });
    return String(out || '').split('\n').map((l) => l.trim()).filter((l) => l.endsWith('.app'));
  } catch {
    return [];
  }
}

// Search installed apps by display name or bundle ID (case-insensitive).
// `opts.excludePaths` removes bundles whose executable matches one of those
// paths (the app passes its own executable so Auren never offers itself).
// Returns up to 10 entries, sorted by name.
function searchApps(query, opts) {
  const q = String(query || '').trim().toLowerCase();
  const excludePaths = new Set(
    (opts && Array.isArray(opts.excludePaths) ? opts.excludePaths : [])
      .map((p) => String(p || '').trim()).filter(Boolean)
  );
  const found = [];
  const seen = new Set();
  for (const bundle of new Set(mdfindAppBundles(q).concat(scanAppDirs()))) {
    const info = appBundleInfo(bundle);
    if (!info || seen.has(info.id)) continue;
    if (excludePaths.has(info.path)) continue;
    if (q && !info.name.toLowerCase().includes(q) && !info.id.toLowerCase().includes(q)) continue;
    seen.add(info.id);
    found.push(info);
  }
  found.sort((a, b) => a.name.localeCompare(b.name));
  return found.slice(0, 10);
}

module.exports = { searchApps, appBundleInfo, scanAppDirs, mdfindAppBundles };
