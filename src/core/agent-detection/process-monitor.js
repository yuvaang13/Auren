/* Auren — AgentDetection ProcessMonitor (macOS).
 *
 * Phase 2 of the plan. Tracks running processes, creation/termination,
 * parent/child relationships, executable paths and bundle identifiers.
 * Maintains a local process tree; emits typed events:
 *   ProcessStarted / ProcessStopped / ProcessRelationshipChanged
 *
 * Implementation: event-driven where possible, lightweight `ps` snapshot diff
 * otherwise (the existing src/platform/procs layer). Never assumes a process
 * name proves agent activity — that judgment belongs to the scoring engine.
 */

'use strict';

const events = require('./events');

function lastSegment(s) {
  return String(s || '').split(/[\\/]/).pop();
}

function createProcessMonitor(opts) {
  const cfg = (opts && typeof opts === 'object') ? opts : {};
  const nowFn = typeof cfg.now === 'function' ? cfg.now : () => Date.now();
  // pid -> { pid, ppid, exe, bundleId }
  const tree = new Map();

  function snapshotToMap(list) {
    const m = new Map();
    for (const p of (Array.isArray(list) ? list : [])) {
      if (!p || !p.pid) continue;
      m.set(p.pid, {
        pid: p.pid,
        ppid: p.ppid || null,
        exe: p.exe || '',
        bundleId: p.bundleId || null,
        name: lastSegment(p.exe || ''),
      });
    }
    return m;
  }

  // Diff a fresh process list against the tracked tree. Returns typed events.
  function update(processList) {
    const next = snapshotToMap(processList);
    const out = [];
    for (const [pid, proc] of next) {
      if (!tree.has(pid)) {
        out.push(events.processStarted(proc, nowFn));
      } else {
        const prev = tree.get(pid);
        if (prev.ppid !== proc.ppid) {
          out.push(events.processRelationshipChanged(pid, prev.ppid, proc.ppid, nowFn));
        }
      }
    }
    for (const [pid, proc] of tree) {
      if (!next.has(pid)) out.push(events.processStopped(proc, nowFn));
    }
    tree.clear();
    for (const [pid, proc] of next) tree.set(pid, proc);
    return out;
  }

  // Ancestor chain for a pid (up to 10 hops). Used for
  // "agent child/subprocess relationship" evidence.
  function ancestorsOf(pid) {
    const chain = [];
    let node = tree.get(pid);
    let hops = 0;
    while (node && node.ppid && hops < 10) {
      const parent = tree.get(node.ppid);
      if (!parent || parent.pid === node.pid) break;
      chain.push(parent);
      node = parent;
      hops += 1;
    }
    return chain;
  }

  function childrenOf(pid) {
    const out = [];
    for (const proc of tree.values()) {
      if (proc.ppid === pid) out.push(proc);
    }
    return out;
  }

  function get(pid) { return tree.get(pid) || null; }
  function size() { return tree.size; }
  function reset() { tree.clear(); }

  return { update, ancestorsOf, childrenOf, get, size, reset, _tree: tree };
}

module.exports = { createProcessMonitor };
