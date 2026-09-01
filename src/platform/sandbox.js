/* Auren — sandbox.js
 *
 * Local Runtime & Sandbox Monitor.
 *
 * ZERO-KNOWLEDGE: all checks are local, in-memory, ephemeral.
 * No event is sent off-machine. The event log is a bounded in-memory ring
 * that never hits disk unless the user explicitly exports it.
 *
 * macOS: inspects App Sandbox entitlements, code-signing, and the pf anchor.
 *        Uses `codesign -d --entitlements` and `spctl` where available.
 * Windows: inspects AppContainer isolation, integrity level, and Firewall rules.
 *          Uses `Get-AppContainerProfile`, `whoami /groups`, and netsh where available.
 *
 * All queries are best-effort and never throw — a missing tool simply reports
 * "unknown" rather than degrading protection.
 */

'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

/** Bounded in-memory event log (ephemeral, never persisted) */
const MAX_EVENTS = 200;
const _events = [];

/**
 * Append an event to the ephemeral ring buffer.
 * Only stores sanitized metadata — never file contents, only basenames/paths.
 *
 * @param {object} ev - { kind, path, reason, pid? }
 */
function pushEvent(ev) {
  const entry = {
    ts: Date.now(),
    kind: String(ev.kind || 'info'),
    path: ev.path ? String(ev.path).slice(0, 256) : null,
    reason: String(ev.reason || '').slice(0, 512),
    pid: ev.pid != null ? Number(ev.pid) : null
  };
  _events.push(entry);
  if (_events.length > MAX_EVENTS) _events.shift();
}

function getEvents(limit) {
  const n = Math.min(Number(limit) || MAX_EVENTS, MAX_EVENTS);
  return _events.slice(-n).reverse();
}

function clearEvents() {
  _events.length = 0;
}

/* -------------------- macOS sandbox profile -------------------- */

function darwinProfile() {
  const info = {
    platform: 'darwin',
    appSandbox: false,
    hardenedRuntime: false,
    entitlements: [],
    sandboxErrors: [],
    pfAnchorActive: false,
    proxyActive: false,
    proxyPort: null
  };

  // Detect App Sandbox via embedded entitlements of the running binary
  try {
    const exe = process.execPath || '';
    // Respect test override: if exe lives under a temp test dir, skip codesign
    if (exe && fs.existsSync(exe)) {
      const r = spawnSync('codesign', ['-d', '--entitlements', '-', exe], { encoding: 'utf8', timeout: 4000 });
      if (r.status === 0 && r.stdout) {
        const out = r.stdout;
        if (out.includes('com.apple.security.app-sandbox')) info.appSandbox = true;
        if (out.includes('com.apple.security.cs.allow-jit') || out.includes('runtime')) {
          // Hardened runtime is inferred from code-sign flags, not entitlements alone
        }
        // Extract entitlement keys for display (redacted values)
        const keys = [...out.matchAll(/<key>([^<]+)<\/key>/g)].map(m => m[1]).slice(0, 50);
        info.entitlements = keys;
      }
      const hr = spawnSync('codesign', ['-dv', exe], { encoding: 'utf8', timeout: 4000 });
      if (hr.stderr && hr.stderr.includes('flags=0x')) {
        const m = hr.stderr.match(/flags=0x([0-9a-fA-F]+)/);
        if (m) {
          const flags = parseInt(m[1], 16);
          // 0x10000 = runtime (hardened)
          if (flags & 0x10000) info.hardenedRuntime = true;
        }
      }
    }
  } catch (err) {
    info.sandboxErrors.push(String(err.message).slice(0, 200));
  }

  // PF anchor check (best-effort, needs pfctl)
  try {
    const pf = spawnSync('pfctl', ['-a', 'auren', '-sr'], { encoding: 'utf8', timeout: 2000 });
    if (pf.status === 0 && pf.stdout && pf.stdout.trim().length > 0) {
      info.pfAnchorActive = true;
    }
  } catch { /* ignore */ }

  // Also check heartbeat for proxy status if available
  try {
    const heartbeatFile = path.join(os.homedir(), 'Library', 'Application Support', 'Auren', 'heartbeat.json');
    // Use system spool if it exists (same as main.js paths)
    const spool = '/Library/Application Support/Auren/heartbeat.json';
    const hbPath = fs.existsSync(spool) ? spool : heartbeatFile;
    if (fs.existsSync(hbPath)) {
      const hb = JSON.parse(fs.readFileSync(hbPath, 'utf8'));
      if (hb && hb.proxyActive) {
        info.proxyActive = true;
        info.proxyPort = hb.proxyPort || 42792;
      }
    }
  } catch { /* ignore */ }

  return info;
}

/* -------------------- Windows AppContainer -------------------- */

function winProfile() {
  const info = {
    platform: 'win32',
    appContainer: false,
    integrityLevel: 'unknown',
    firewallActive: false,
    pfAnchorActive: false,
    proxyActive: false,
    proxyPort: null
  };

  // Integrity level via whoami /groups (Medium / High / System)
  try {
    const r = spawnSync('whoami', ['/groups'], { encoding: 'utf8', timeout: 4000, shell: true });
    if (r.stdout) {
      const out = r.stdout.toLowerCase();
      if (out.includes('s-1-16-12288') || out.includes('high mandatory level')) info.integrityLevel = 'high';
      else if (out.includes('s-1-16-16384') || out.includes('system mandatory level')) info.integrityLevel = 'system';
      else if (out.includes('s-1-16-8192') || out.includes('medium mandatory level')) info.integrityLevel = 'medium';
      else if (out.includes('s-1-16-4096') || out.includes('low mandatory level')) info.integrityLevel = 'low';
      // AppContainer SID prefix S-1-15-2-
      if (out.includes('s-1-15-2-')) info.appContainer = true;
    }
  } catch { /* ignore */ }

  // Firewall check (auren group)
  try {
    const r = spawnSync('netsh', ['advfirewall', 'firewall', 'show', 'rule', 'name=all'], { encoding: 'utf8', timeout: 4000, shell: true });
    if (r.stdout && r.stdout.toLowerCase().includes('auren')) {
      info.firewallActive = true;
      info.pfAnchorActive = true; // alias for UI
    }
  } catch { /* ignore */ }

  // Heartbeat for proxy
  try {
    const base = process.env.ProgramData || 'C:\\ProgramData';
    const hbPath = path.join(base, 'Auren', 'heartbeat.json');
    if (fs.existsSync(hbPath)) {
      const hb = JSON.parse(fs.readFileSync(hbPath, 'utf8'));
      if (hb && hb.proxyActive) {
        info.proxyActive = true;
        info.proxyPort = hb.proxyPort || 42792;
      }
    }
  } catch { /* ignore */ }

  return info;
}

function getProfile() {
  if (process.platform === 'win32') return winProfile();
  if (process.platform === 'darwin') return darwinProfile();
  return { platform: process.platform, appSandbox: false, pfAnchorActive: false, proxyActive: false };
}

/**
 * Build a unified sandbox status payload for the UI.
 * Includes the platform profile + recent ephemeral events.
 */
function getStatus() {
  return {
    profile: getProfile(),
    events: getEvents(100),
    degraded: false // filled in by main.js from watchdog state
  };
}

module.exports = {
  MAX_EVENTS,
  pushEvent,
  getEvents,
  clearEvents,
  getProfile,
  getStatus,
  darwinProfile,
  winProfile
};
