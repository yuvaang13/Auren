/* Auren — agenttrack.js
 *
 * Dwell-time / confidence tracker for auto-protect. Pure and clock-injectable,
 * so it is trivially unit-testable without real processes or timers.
 *
 * Auto-protect should not flip the firewall on because one `ps` snapshot
 * happened to show a stray word (`rg codex`). This tracker requires a match to
 * PERSIST: an evidence entry only becomes "confirmed" once it has been seen
 * continuously for minDwellMs (default 2s, i.e. survives a couple of scans).
 *
 * Strong signals get a fast path: `forceStrong` confirms any score >= 3 match
 * that was also present on the immediately previous scan, so a real agent
 * binary or driver engages within ~1–2 scans without waiting out the dwell.
 *
 * Entries keyed by tool+pid (one agent instance), pruned when a process stops
 * matching for staleMs, and reset when it comes back after a gap.
 */

'use strict';

function createTracker(opts) {
  const cfg = (opts && typeof opts === 'object') ? opts : {};
  const defaultDwell = Number.isFinite(cfg.minDwellMs) ? cfg.minDwellMs : 2000;
  const staleMs = Number.isFinite(cfg.staleMs) ? cfg.staleMs : 5000;
  const nowFn = typeof cfg.now === 'function' ? cfg.now : () => Date.now();

  const entries = new Map(); // tool:pid -> { firstSeen, lastSeen, score }
  let prevStrongKeys = new Set(); // strong keys present on the last scan

  return {
    // Fold the current scan's evidence in. Returns the confirmed sessions as
    // [{ pid, exe, tool, score }, ...] — only matches that persisted long
    // enough (or strong + forceStrong on a follow-up scan) are returned.
    //   evidence:   [{ pid, exe, tool, score }, ...] from agentdetect
    //   dwellMs:    per-call dwell override (defaults to the tracker default)
    //   forceStrong: confirm previously-seen score >= 3 matches immediately
    update(evidence, dwellMs, forceStrong) {
      const t = nowFn();
      const dwell = Number.isFinite(dwellMs) ? dwellMs : defaultDwell;
      const seen = new Set();
      const outMap = new Map(); // tool:pid -> best confirmed entry this scan
      for (const e of (Array.isArray(evidence) ? evidence : [])) {
        if (!e || !e.pid || !e.tool) continue;
        const key = e.tool + ':' + e.pid;
        seen.add(key);
        const score = Number.isFinite(e.score) ? e.score : 3;
        let ent = entries.get(key);
        // Absent for longer than the dwell => treat as a fresh match.
        if (!ent || (t - ent.lastSeen) > dwell) {
          ent = { firstSeen: t, lastSeen: t, score: 0 };
          entries.set(key, ent);
        } else {
          ent.lastSeen = t;
        }
        if (score > ent.score) ent.score = score; // reflect the strongest current evidence
        const dwelled = (t - ent.firstSeen) >= dwell;
        const strongRecheck = !!(forceStrong && score >= 3 && prevStrongKeys.has(key));
        if (dwelled || strongRecheck) {
          const prev = outMap.get(key);
          if (!prev || ent.score > prev.score) {
            outMap.set(key, { pid: e.pid, exe: e.exe || '', tool: e.tool, score: ent.score });
          }
        }
      }
      // Prune processes that stopped matching long enough ago.
      for (const [key, ent] of entries) {
        if (!seen.has(key) && (t - ent.lastSeen) >= staleMs) entries.delete(key);
      }
      prevStrongKeys = new Set(
        Array.from(seen).filter((k) => { const e = entries.get(k); return e && e.score >= 3; })
      );
      return Array.from(outMap.values());
    },

    // Forget everything (settings disabled, protection manually engaged, etc.).
    reset() { entries.clear(); prevStrongKeys = new Set(); },

    size() { return entries.size; },

    // For tests: access the raw entry map.
    _entries: entries
  };
}

module.exports = { createTracker };
