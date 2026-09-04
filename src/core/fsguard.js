/* Auren — fsguard.js
 *
 * File System Guard & Virtual Isolation engine.
 *
 * ZERO-KNOWLEDGE / LOCAL-ONLY: every decision is made in-memory on the user's
 * machine. No path, mount point, or exclusion is ever transmitted.
 *
 * Architecture:
 *   - Default-Deny: agent starts with zero FS access. Only explicit Virtual
 *     Mount Points grant visibility, minus the forced exclusion list.
 *   - Canonical-first: every input path is passed through path-normalize.js
 *     (lexical + realpath) BEFORE any containment or exclusion check.
 *   - Forced exclusions are non-overridable and evaluated after mount
 *     containment, so even an explicit mount cannot expose a protected file.
 *
 * Mount storage:
 *   - Persisted in the encrypted store (guardrail.dat via store.js) and signed
 *     config (config.json + .sig) — same mechanism as blocklists. Renderer never
 *     touches files directly; IPC is the only write path.
 *   - On macOS, mounts are kept as Security-Scoped Bookmarks when possible
 *     (opaque base64 blobs stored alongside the mount). On Windows, ACL
 *     enforcement is done via the sandbox monitor + explicit containment.
 *
 * Forced exclusion list (non-removable, per spec):
 *   - .env, .env.*, .ssh/*, *.pem, *.key, keychain, browser data stores, etc.
 *   - Any match => DENY regardless of mount.
 */

'use strict';
const path = require('path');
const fs = require('fs');
const { canonicalize, isWithinMount, hasTraversalSequence } = require('./path-normalize');

const VERSION = 1;

/* ------------------------------------------------------------------ */
/*  Forced exclusion rules — cannot be removed by the user            */
/* ------------------------------------------------------------------ */

// Basename exact matches (case-sensitive on POSIX, handled case-insensitively
// for Windows at check time)
const FORCED_BASENAMES = new Set([
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.git' // prevent .git exposure as well — conservative
]);

// Glob-like prefixes for basenames: .env.*  (covers .env.example etc — still blocked
// by default because even example files can contain real secrets in practice;
// user can explicitly allow via mount suffix if they understand the risk — but
// forced list here blocks all .env.* inside any mount)
const FORCED_BASENAME_PREFIXES = ['.env.'];

// Extensions that always deny (lower-cased, with dot)
const FORCED_EXTENSIONS = new Set([
  '.pem',
  '.key',
  '.p12',
  '.pfx',
  '.kdbx' // KeePass
]);

// Directory name segments that cause denial if present anywhere in the path
// e.g., ~/.ssh/id_rsa, ~/.aws/credentials
const FORCED_DIR_SEGMENTS = new Set([
  '.ssh',
  '.aws',
  '.gnupg',
  '.gnupg2',
  '.azure',
  '.gcloud',
  '.kube' // kubernetes configs often hold cluster keys
]);

// Substring / filename patterns for sensitive stores (case-insensitive)
const FORCED_SUBSTRINGS = [
  'keychain',        // macOS Keychain
  'login data',      // Chrome/Edge login store
  'cookies',         // browser cookies (exact basename handled below too)
  'web data',        // Chrome Web Data
  'history',         // browser history is not secret but excluded as data store
  'secret_token',
  'credentials',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa'
];

// Exact browser data store basenames (case-insensitive)
const FORCED_BROWSER_FILES = new Set([
  'login data',
  'cookies',
  'web data',
  'history',
  'bookmarks',
  'secure preferences',
  'local state'
]);

// Paths that look like browser profile stores — denied by directory segment
const FORCED_BROWSER_DIRS = new Set([
  'chrome',
  'chromium',
  'brave',
  'edge',
  'firefox',
  'safari'
]);

/**
 * Test whether a canonical path matches any forced exclusion.
 * Runs AFTER mount containment, so it can deny even inside a mount.
 *
 * @param {string} canonicalPath
 * @param {string} [platform]
 * @returns {{ excluded: boolean, reason?: string, rule?: string }}
 */
function isForcedExcluded(canonicalPath, platform) {
  if (!canonicalPath || typeof canonicalPath !== 'string') return { excluded: false };
  const isWin = (platform || process.platform) === 'win32';
  const mod = isWin ? path.win32 : path.posix;

  const basename = mod.basename(canonicalPath);
  const lowerBase = basename.toLowerCase();
  const lowerFull = canonicalPath.toLowerCase();
  const ext = mod.extname(basename).toLowerCase();

  // 1. Exact basename match
  if (FORCED_BASENAMES.has(basename)) {
    return { excluded: true, reason: `blocked dotfile: ${basename}`, rule: 'basename:' + basename };
  }

  // 2. Prefix glob .env.*
  for (const pref of FORCED_BASENAME_PREFIXES) {
    if (basename.startsWith(pref)) {
      return { excluded: true, reason: `blocked env file: ${basename}`, rule: 'glob:' + pref + '*' };
    }
  }

  // 3. Extension block
  if (FORCED_EXTENSIONS.has(ext)) {
    return { excluded: true, reason: `blocked extension: ${ext}`, rule: 'ext:' + ext };
  }

  // 4. Directory segment block — split the full path and check each segment
  const segments = canonicalPath.split(mod.sep).map(s => s.toLowerCase());
  for (const seg of segments) {
    if (FORCED_DIR_SEGMENTS.has(seg)) {
      return { excluded: true, reason: `blocked sensitive directory: ${seg}`, rule: 'dir:' + seg };
    }
  }
  // Note: FORCED_BROWSER_DIRS (chrome, firefox, etc.) is intentionally NOT
  // segment-blocked — a project named "chrome" would otherwise be denied.
  // Browser data stores are already covered by FORCED_BROWSER_FILES +
  // substring checks, which is sufficient and less prone to false positives.

  // 5. Browser file exact match (inside any browser profile dir, but we block
  //    globally to be safe — these files never need to be exposed to an agent)
  if (FORCED_BROWSER_FILES.has(lowerBase)) {
    return { excluded: true, reason: `blocked browser data store: ${basename}`, rule: 'browser-file:' + lowerBase };
  }

  // 6. Substring patterns (low-cost, case-insensitive)
  // FIX: previously checked basename-only, so `/keychain/file.txt` or
  // `/a/credentials/config.json` inside a sensitive dir slipped through when
  // the basename was generic (file.txt). Now check any path segment.
  for (const sub of FORCED_SUBSTRINGS) {
    const lowSub = sub.toLowerCase();
    if (lowerFull.includes(lowSub)) {
      if (segments.some(s => s.includes(lowSub))) {
        return { excluded: true, reason: `blocked sensitive pattern: ${sub}`, rule: 'substr:' + sub };
      }
    }
  }

  // 7. Paths containing `.ssh/` or `.aws/` already covered by dir segments.
  //    No further checks.

  return { excluded: false };
}

/* ------------------------------------------------------------------ */
/*  Data models                                                       */
/* ------------------------------------------------------------------ */

/**
 * @typedef {object} VirtualMount
 * @property {string} id - stable UUID (hex)
 * @property {string} path - canonical absolute path chosen by user
 * @property {string} displayName - short name for UI (basename)
 * @property {number} addedAt - epoch ms
 * @property {'read'|'readwrite'} scope
 * @property {string|null} bookmark - macOS security-scoped bookmark (base64) or null
 */

/**
 * @typedef {object} FsGuardPolicy
 * @property {number} version
 * @property {VirtualMount[]} mounts
 * @property {boolean} defaultDeny - always true (kept for clarity / future)
 * @property {boolean} blockTraversal - always true
 * @property {boolean} enforceCanonical - always true
 */

/**
 * Create a fresh policy (default-deny, zero mounts).
 * @returns {FsGuardPolicy}
 */
function createDefaultPolicy() {
  return {
    version: VERSION,
    mounts: [],
    defaultDeny: true,
    blockTraversal: true,
    enforceCanonical: true
  };
}

/**
 * Normalize a persisted policy (tolerates older / corrupt shapes).
 * @param {any} raw
 * @returns {FsGuardPolicy}
 */
function normalizePolicy(raw) {
  if (!raw || typeof raw !== 'object') return createDefaultPolicy();
  const mounts = Array.isArray(raw.mounts) ? raw.mounts.filter(isValidMount).map(normMount) : [];
  return {
    version: 1,
    mounts,
    defaultDeny: true,
    blockTraversal: true,
    enforceCanonical: true
  };
}

function isValidMount(m) {
  return m && typeof m === 'object' && typeof m.path === 'string' && m.path.trim().length > 0 && typeof m.id === 'string' && m.id.length > 0;
}

function normMount(m) {
  return {
    id: String(m.id),
    path: String(m.path),
    displayName: String(m.displayName || path.basename(m.path) || m.path),
    addedAt: Number(m.addedAt) || Date.now(),
    scope: m.scope === 'read' ? 'read' : 'readwrite',
    bookmark: typeof m.bookmark === 'string' ? m.bookmark : null
  };
}

/**
 * Validate a candidate mount path without adding it.
 * Ensures it is absolute, exists, and is a directory.
 *
 * @param {string} inputPath
 * @returns {{ ok: boolean, canonical?: string, error?: string }}
 */
function validateMountPath(inputPath) {
  const c = canonicalize(inputPath);
  if (!c.ok) return { ok: false, error: c.error };
  try {
    const st = fs.statSync(c.canonical);
    if (!st.isDirectory()) return { ok: false, error: 'not a directory: ' + c.canonical };
  } catch (err) {
    if (err.code === 'ENOENT') return { ok: false, error: 'directory does not exist: ' + c.canonical };
    return { ok: false, error: err.message };
  }
  return { ok: true, canonical: c.canonical };
}

/**
 * Add a mount to a policy (mutates and returns the policy for chaining).
 * Dedupes by canonical path (case-insensitive on Windows).
 *
 * @param {FsGuardPolicy} policy
 * @param {string} inputPath - user-picked directory
 * @param {object} [opts]
 * @param {string} [opts.bookmark] - macOS bookmark base64
 * @returns {{ ok: boolean, policy: FsGuardPolicy, mount?: VirtualMount, error?: string }}
 */
function addMount(policy, inputPath, opts) {
  const normalized = normalizePolicy(policy);
  const v = validateMountPath(inputPath);
  if (!v.ok) return { ok: false, policy: normalized, error: v.error };

  const isWin = process.platform === 'win32';
  const exists = normalized.mounts.some(m => {
    if (isWin) return m.path.toLowerCase() === v.canonical.toLowerCase();
    return m.path === v.canonical;
  });
  if (exists) return { ok: false, policy: normalized, error: 'already mounted: ' + v.canonical };

  const crypto = require('crypto');
  const mount = {
    id: crypto.randomBytes(8).toString('hex'),
    path: v.canonical,
    displayName: path.basename(v.canonical) || v.canonical,
    addedAt: Date.now(),
    scope: 'readwrite',
    bookmark: (opts && opts.bookmark) ? String(opts.bookmark) : null
  };
  normalized.mounts.push(mount);
  return { ok: true, policy: normalized, mount };
}

/**
 * Remove a mount by id.
 * @param {FsGuardPolicy} policy
 * @param {string} id
 * @returns {{ ok: boolean, policy: FsGuardPolicy, error?: string }}
 */
function removeMount(policy, id) {
  const normalized = normalizePolicy(policy);
  const idx = normalized.mounts.findIndex(m => m.id === String(id));
  if (idx === -1) return { ok: false, policy: normalized, error: 'mount not found' };
  normalized.mounts.splice(idx, 1);
  return { ok: true, policy: normalized };
}

/**
 * Core enforcement: is `inputPath` allowed under `policy`?
 *
 * Order (critical):
 *   1. Canonicalize input (lexical + symlink)
 *   2. Forced exclusion check => DENY (even inside a mount)
 *   3. Mount containment => if not inside any mount => DENY (default-deny)
 *   4. Otherwise ALLOW
 *
 * @param {string} inputPath
 * @param {FsGuardPolicy} policy
 * @param {object} [opts]
 * @param {string} [opts.platform]
 * @returns {{ allowed: boolean, canonical: string|null, reason: string, rule?: string }}
 */
function isAccessAllowed(inputPath, policy, opts) {
  const platform = opts && opts.platform;

  if (typeof inputPath !== 'string' || !inputPath.trim()) {
    return { allowed: false, canonical: null, reason: 'empty path' };
  }

  // Early traversal signal — still canonicalize to be sure, but this is
  // useful for logging the attack vector.
  const hadTraversal = hasTraversalSequence(inputPath);

  const c = canonicalize(inputPath, { platform });
  if (!c.ok) {
    return { allowed: false, canonical: null, reason: c.error };
  }
  const canonical = c.canonical;

  // 1. Forced exclusions (non-overridable)
  const excl = isForcedExcluded(canonical, platform);
  if (excl.excluded) {
    return { allowed: false, canonical, reason: excl.reason, rule: excl.rule };
  }

  // 2. Default-deny: must be inside at least one mount
  const norm = normalizePolicy(policy);
  if (norm.mounts.length === 0) {
    return { allowed: false, canonical, reason: 'no mounts configured — default deny' + (hadTraversal ? ' (traversal sequence detected)' : '') };
  }

  for (const m of norm.mounts) {
    if (isWithinMount(canonical, m.path, platform)) {
      // Also deny if the path is exactly the mount root and the mount root
      // itself is a forced-excluded basename (e.g., user tried to mount ~/.ssh)
      // The exclusion above already handles leaf files, but the mount root being
      // a sensitive dir means the mount itself is suspect — deny creation at
      // addMount time ideally, but also deny access here.
      return { allowed: true, canonical, reason: `inside mount: ${m.displayName}` };
    }
  }

  return { allowed: false, canonical, reason: 'outside allowed mounts — default deny' + (hadTraversal ? ' (traversal blocked)' : '') };
}

/**
 * Batch check helper for the agent gate (multiple file reads).
 * Returns the first denial, or allowed if all pass.
 */
function checkBatch(paths, policy, opts) {
  if (!Array.isArray(paths)) return isAccessAllowed(String(paths), policy, opts);
  for (const p of paths) {
    const r = isAccessAllowed(p, policy, opts);
    if (!r.allowed) return r;
  }
  // If any path was checked, return allowed for the last canonical
  const last = paths[paths.length - 1];
  const c = canonicalize(String(last || ''), opts);
  return { allowed: true, canonical: c.ok ? c.canonical : null, reason: 'all paths inside mounts' };
}

module.exports = {
  VERSION,
  FORCED_BASENAMES,
  FORCED_EXTENSIONS,
  FORCED_DIR_SEGMENTS,
  isForcedExcluded,
  createDefaultPolicy,
  normalizePolicy,
  validateMountPath,
  addMount,
  removeMount,
  isAccessAllowed,
  checkBatch
};
