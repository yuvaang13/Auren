/* Auren — AgentDetection AutomationMonitor (macOS).
 *
 * Phase 4 of the plan. Detects applications interacting with OTHER
 * applications through macOS accessibility / automation mechanisms, using
 * observable OS evidence — never screenshots or screen recording.
 *
 * Observable automation relationships surfaced:
 *   Process A → (accessibility / automation API) → Safari / Finder / …
 *
 * macOS-native sources used (best-effort, local-only, no content captured):
 *   1. Process-table heuristics: known automation executables (osascript,
 *      automator, cliclick, etc.) and agent processes co-occurring with
 *      GUI targets (Safari, Finder) imply an automation relationship.
 *   2. TCC accessibility consent list (~/Library/Application Support/
 *      com.apple.TCC/TCC.db, service kTCCServiceAccessibility): which apps
 *      the user consented to let control the computer. Read-only; failure
 *      (SIP / permission) degrades to heuristic mode, never fatal.
 *   3. Optional injected AX-client enumerator hook (opts.axClients): callers
 *      with a native AX API binding can pass `() => [{ pid, target }]` and
 *      those observations are emitted as AutomationAccessObserved events.
 *
 * Emits: AutomationAccessStarted / AutomationAccessObserved / AutomationAccessStopped
 * Each carries { source { pid, exe, name }, targetApplication, automationType,
 * timestamp }. Never captures user content.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const events = require('./events');

function lastSegment(s) {
  return String(s || '').split(/[\\/]/).pop();
}

// Executables whose very presence means "automation API in use".
const AUTOMATION_BINARIES = Object.freeze([
  'osascript', 'automator', 'cliclick', 'cliclicker',
  'chromedriver', 'geckodriver', 'msedgedriver', 'safaridriver',
  'playwright', 'puppeteer', 'selenium',
]);

// GUI apps that are typical automation TARGETS.
const AUTOMATION_TARGETS = Object.freeze([
  'Safari', 'Finder', 'Google Chrome', 'Firefox', 'Mail', 'Calendar', 'System Events',
]);

const AUTOMATION_RE = new RegExp('\\b(?:' + AUTOMATION_BINARIES.join('|') + ')\\b', 'i');

function isAutomationBinary(proc) {
  if (!proc) return false;
  const exe = String(proc.exe || '');
  const toks = Array.isArray(proc.tokens) ? proc.tokens.join(' ') : '';
  return AUTOMATION_RE.test(lastSegment(exe)) || AUTOMATION_RE.test(toks);
}

function isAutomationTarget(proc) {
  if (!proc) return false;
  const base = lastSegment(proc.exe || '').replace(/\.app$/i, '');
  return AUTOMATION_TARGETS.some((t) => t.toLowerCase() === String(base).toLowerCase());
}

// Best-effort read of the user TCC db accessibility list. Returns bundle ids /
// executable names granted kTCCServiceAccessibility, or [] when unreadable.
// Read-only; never writes. Purely local.
function readAccessibilityClients() {
  try {
    const db = path.join(os.homedir(), 'Library', 'Application Support', 'com.apple.TCC', 'TCC.db');
    if (!fs.existsSync(db)) return [];
    const out = execFileSync('/usr/bin/sqlite3', [
      db,
      "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND auth_value=2;",
    ], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
    return String(out || '').split('\n').map((s) => s.trim()).filter(Boolean);
  } catch { return []; }
}

function createAutomationMonitor(opts) {
  const cfg = (opts && typeof opts === 'object') ? opts : {};
  const nowFn = typeof cfg.now === 'function' ? cfg.now : () => Date.now();
  const axClientsFn = typeof cfg.axClients === 'function' ? cfg.axClients : null;
  const tccReader = typeof cfg.tccReader === 'function' ? cfg.tccReader : readAccessibilityClients;
  // key "pid->target" -> { source, target, automationType, lastSeen }
  const active = new Map();

  function keyFor(pid, target) { return pid + '->' + target; }

  // Scan a process list; returns typed automation events. `knownAgentPids` is
  // an optional Set of pids already identified as agent processes — when such
  // a process co-occurs with an automation binary or a GUI target, the
  // relationship is reported as evidence (never as proof by name alone).
  function update(processList, knownAgentPids) {
    const list = Array.isArray(processList) ? processList : [];
    const agents = knownAgentPids instanceof Set ? knownAgentPids : new Set();
    const out = [];
    const seen = new Set();

    const automationProcs = list.filter(isAutomationBinary);
    const targetProcs = list.filter(isAutomationTarget);

    const consider = (source, targetName, automationType) => {
      if (!source || !source.pid || !targetName) return;
      const key = keyFor(source.pid, targetName);
      seen.add(key);
      if (!active.has(key)) {
        active.set(key, { source, target: targetName, automationType, lastSeen: nowFn() });
        out.push(events.automationEvent('AutomationAccessStarted', source, targetName, automationType, nowFn));
      } else {
        active.get(key).lastSeen = nowFn();
        out.push(events.automationEvent('AutomationAccessObserved', source, targetName, automationType, nowFn));
      }
    };

    // 1. Automation binary + GUI target co-occurring: attribute to the
    //    automation binary's parent chain head when identifiable, else the
    //    binary itself.
    if (automationProcs.length > 0 && targetProcs.length > 0) {
      for (const auto of automationProcs) {
        for (const target of targetProcs) {
          if (auto.pid === target.pid) continue;
          consider(
            { pid: auto.pid, exe: auto.exe || '', name: lastSegment(auto.exe || '') },
            lastSegment(target.exe || '').replace(/\.app$/i, ''),
            'automation-api'
          );
        }
      }
    }

    // 2. Known agent process co-occurring with a GUI target while ANY
    //    automation binary is also alive (agent → automation → app chain).
    if (automationProcs.length > 0) {
      for (const p of list) {
        if (!p || !p.pid || !agents.has(p.pid)) continue;
        for (const target of targetProcs) {
          if (p.pid === target.pid) continue;
          consider(
            { pid: p.pid, exe: p.exe || '', name: lastSegment(p.exe || '') },
            lastSegment(target.exe || '').replace(/\.app$/i, ''),
            'accessibility'
          );
        }
      }
    }

    // 3. Native AX-client hook (when the host provides one).
    if (axClientsFn) {
      let clients = [];
      try { clients = axClientsFn() || []; } catch { clients = []; }
      for (const c of clients) {
        if (!c) continue;
        consider(
          { pid: c.pid || null, exe: c.exe || '', name: c.name || lastSegment(c.exe || '') },
          c.target || null,
          c.automationType || 'accessibility'
        );
      }
    }

    // 4. TCC consent cross-check is exposed via getAccessibilityClients();
    //    it does not itself emit start/stop, only enriches evidence.

    // Expire relationships no longer observed.
    for (const [key, rel] of active) {
      if (!seen.has(key)) {
        active.delete(key);
        out.push(events.automationEvent('AutomationAccessStopped', rel.source, rel.target, rel.automationType, nowFn));
      }
    }
    return out;
  }

  function getAccessibilityClients() {
    try { return tccReader() || []; } catch { return []; }
  }

  function activeRelationships() {
    return Array.from(active.values()).map((r) => Object.assign({}, r));
  }

  function reset() { active.clear(); }

  return { update, getAccessibilityClients, activeRelationships, reset };
}

module.exports = {
  createAutomationMonitor,
  isAutomationBinary,
  isAutomationTarget,
  readAccessibilityClients,
  AUTOMATION_BINARIES,
  AUTOMATION_TARGETS,
};
