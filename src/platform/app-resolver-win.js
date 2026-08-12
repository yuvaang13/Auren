/* Auren — app-resolver-win.js
 *
 * Windows app search. macOS finds `.app` bundles with metadata; Windows has no
 * equivalent, so we enumerate installed executables from the standard install
 * folders (depth <= 2) and read each file's version info for a display name.
 *
 * A Windows exe has no bundle ID, so the block entry id is the executable's
 * basename (e.g. Discord.exe -> "Discord") — the same derivation the shared
 * validator uses for path entries (core/apps.js validateBlockApp).
 *
 * The version-info query is a pure command builder (unit-testable without
 * Windows); the exec wrappers spawn `powershell.exe` (AUREN_PS).
 */

'use strict';
const { execFileSync } = require('child_process');

const US = String.fromCharCode(0x1f);

function psBin() {
  return process.env.AUREN_PS || 'powershell.exe';
}

function runPS(script) {
  return execFileSync(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
}

// Pure builder: emits PATH<US>NAME per candidate exe (ProductName, else
// FileDescription, else the basename).
function listInstalledExesCmd() {
  const dirs = [
    process.env.ProgramFiles || 'C:\\Program Files',
    process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)',
    process.env.LOCALAPPDATA ? process.env.LOCALAPPDATA + '\\Programs' : ''
  ].filter(Boolean).map((d) => "'" + String(d).replace(/'/g, "''") + "'").join(',');
  return 'Get-ChildItem -Path ' + dirs + ' -Filter *.exe -Recurse -Depth 2 -ErrorAction SilentlyContinue | '
    + 'ForEach-Object { '
    + '$vi = $_.VersionInfo; '
    + '$n = if ($vi.ProductName) { $vi.ProductName } elseif ($vi.FileDescription) { $vi.FileDescription } else { $_.BaseName }; '
    + '"' + US + '" -f $_.FullName, $n | Out-Null; '
    + '"{0}' + US + '{1}" -f $_.FullName, $n }';
}

// Pure parser: "C:\...\Discord.exe<US>Discord" -> { id, name, path } or null.
function parseLine(line) {
  const parts = String(line || '').split(US);
  const p = String(parts[0] || '').trim();
  const n = String(parts[1] || '').trim();
  if (!p || !/\.exe$/i.test(p)) return null;
  const base = p.replace(/\\/g, '/').split('/').pop().replace(/\.exe$/i, '');
  return { id: base, name: n || base, path: p };
}

let cache = { at: 0, entries: [] };

function listInstalledExes() {
  const now = Date.now();
  if (now - cache.at < 30000) return cache.entries;
  let entries = [];
  try {
    entries = String(runPS(listInstalledExesCmd()) || '')
      .split(/\r?\n/)
      .map(parseLine)
      .filter(Boolean);
  } catch {}
  cache = { at: now, entries };
  return entries;
}

// Pure: filter candidate entries by query + excludes, sorted, capped at 10.
function filterEntries(entries, query, opts) {
  const q = String(query || '').trim().toLowerCase();
  const excludePaths = new Set(
    (opts && Array.isArray(opts.excludePaths) ? opts.excludePaths : [])
      .map((p) => String(p || '').trim().toLowerCase()).filter(Boolean)
  );
  const found = [];
  const seen = new Set();
  for (const e of (Array.isArray(entries) ? entries : [])) {
    if (!e || seen.has(e.id)) continue;
    if (excludePaths.has(String(e.path || '').toLowerCase())) continue;
    if (q && !e.name.toLowerCase().includes(q) && !e.id.toLowerCase().includes(q)) continue;
    seen.add(e.id);
    found.push(e);
  }
  found.sort((a, b) => a.name.localeCompare(b.name));
  return found.slice(0, 10);
}

// Search installed apps by display name or executable name (case-insensitive).
function searchApps(query, opts) {
  return filterEntries(listInstalledExes(), query, opts);
}

module.exports = { searchApps, listInstalledExesCmd, parseLine, filterEntries };
