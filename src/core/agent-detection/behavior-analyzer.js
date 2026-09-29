/* Auren — AgentDetection BehaviorAnalyzer.
 *
 * Phase 6 of the plan. Deterministic rules for repeated automation patterns
 * over a rolling time window. No ML, no intent inference — just counting
 * observable sequences of typed local events.
 *
 * Patterns detected:
 *   - app_switch_programmatic_input: application/process change followed by
 *     programmatic input, then more programmatic input within the window.
 *   - rapid_programmatic_burst: N programmatic inputs within a short window.
 *   - automation_plus_input_plus_agent: automation API access + programmatic
 *     input + known agent process all observed within the window.
 *
 * All thresholds centralized in DEFAULT_BEHAVIOR_CONFIG so they can be tuned
 * without touching logic. Pure + clock-injectable for tests.
 */

'use strict';

const events = require('./events');

const DEFAULT_BEHAVIOR_CONFIG = Object.freeze({
  windowMs: 30 * 1000,
  rapidBurstCount: 5,
  rapidBurstWindowMs: 10 * 1000,
  maxBuffer: 1000,
});

function createBehaviorAnalyzer(opts) {
  const cfg = Object.assign({}, DEFAULT_BEHAVIOR_CONFIG, (opts && typeof opts === 'object') ? opts : {});
  const nowFn = typeof cfg.now === 'function' ? cfg.now : () => Date.now();
  const buffer = []; // { t, kind } ephemeral in-memory only

  function push(kind) {
    const t = nowFn();
    buffer.push({ t, kind });
    while (buffer.length > cfg.maxBuffer) buffer.shift();
    // Prune outside the rolling window.
    const cutoff = t - cfg.windowMs;
    while (buffer.length > 0 && buffer[0].t < cutoff) buffer.shift();
    return t;
  }

  // Feed one typed event (or a shorthand kind string) into the rolling
  // window. Returns any AutomationPatternObserved events triggered.
  function observe(ev) {
    const kind = typeof ev === 'string' ? ev : (ev && ev.type);
    if (!kind) return [];
    push(kind);
    return analyze();
  }

  function countInWindow(kind, windowMs) {
    const t = nowFn();
    const cutoff = t - (windowMs || cfg.windowMs);
    let n = 0;
    for (let i = buffer.length - 1; i >= 0; i -= 1) {
      if (buffer[i].t < cutoff) break;
      if (buffer[i].kind === kind) n += 1;
    }
    return n;
  }

  function hasInWindow(kind) {
    return countInWindow(kind, cfg.windowMs) > 0;
  }

  function analyze() {
    const out = [];
    // Rapid burst: N programmatic inputs in the short window.
    if (countInWindow('ProgrammaticInputObserved', cfg.rapidBurstWindowMs) >= cfg.rapidBurstCount) {
      out.push(events.automationPatternObserved('rapid_programmatic_burst', {
        count: countInWindow('ProgrammaticInputObserved', cfg.rapidBurstWindowMs),
        windowMs: cfg.rapidBurstWindowMs,
      }, nowFn));
    }
    // App/process change → programmatic input → programmatic input.
    const kinds = buffer.map((b) => b.kind);
    const hasSwitch = kinds.includes('ProcessStarted') || kinds.includes('ProcessRelationshipChanged');
    if (hasSwitch && countInWindow('ProgrammaticInputObserved', cfg.windowMs) >= 2) {
      out.push(events.automationPatternObserved('app_switch_programmatic_input', null, nowFn));
    }
    // Automation API + programmatic input + known agent process marker.
    if (
      (hasInWindow('AutomationAccessObserved') || hasInWindow('AutomationAccessStarted')) &&
      hasInWindow('ProgrammaticInputObserved') &&
      hasInWindow('KnownAgentProcessObserved')
    ) {
      out.push(events.automationPatternObserved('automation_plus_input_plus_agent', null, nowFn));
    }
    return out;
  }

  function reset() { buffer.length = 0; }
  function size() { return buffer.length; }

  return { observe, analyze, countInWindow, hasInWindow, reset, size, _buffer: buffer };
}

module.exports = { createBehaviorAnalyzer, DEFAULT_BEHAVIOR_CONFIG };
