/* Auren — AgentDetection DetectionEngine.
 *
 * Phases 1–8 of the plan orchestrated: owns the ProcessMonitor,
 * AutomationMonitor, InputMonitor, BehaviorAnalyzer, SignatureDatabase and
 * scoring engine, and emits structured evidence-based DetectionEvents:
 *
 *   { timestamp, level, score, evidence: [ "...", ... ] }
 *
 * The UI can explain WHY a detection occurred (evidence list) for debugging
 * and user trust. Detection provides evidence/context only — the POLICY
 * engine (src/core/policy.js decideAutomationPolicy) decides ALLOW / WARN /
 * REQUIRE_APPROVAL / BLOCK.
 *
 * Fully local: no network, no ML, no LLM. Fail-safe: on internal error the
 * engine reports { level: 'DETECTION_UNAVAILABLE' } rather than silently
 * claiming no automation exists.
 *
 * Privacy: only minimum metadata is retained (pids, exes, counts,
 * timestamps) in ephemeral in-memory buffers. No content, keystrokes,
 * clipboard, screenshots, or document data anywhere.
 */

'use strict';

const { createProcessMonitor } = require('./process-monitor');
const { normalizeSignatures, matchProcess } = require('./signatures');
const { createAutomationMonitor } = require('./automation-monitor');
const { createInputMonitor } = require('./input-monitor');
const { createBehaviorAnalyzer } = require('./behavior-analyzer');
const { createScoringEngine } = require('./scoring');

function lastSegment(s) {
  return String(s || '').split(/[\\/]/).pop();
}

function createDetectionEngine(opts) {
  const cfg = (opts && typeof opts === 'object') ? opts : {};
  const nowFn = typeof cfg.now === 'function' ? cfg.now : () => Date.now();
  const debug = cfg.debug === true;
  const signatures = normalizeSignatures(cfg.signatures);

  const processes = createProcessMonitor({ now: nowFn });
  const automation = createAutomationMonitor({ now: nowFn, axClients: cfg.axClients, tccReader: cfg.tccReader });
  const input = createInputMonitor({ now: nowFn });
  const behavior = createBehaviorAnalyzer({ now: nowFn });
  const scoring = createScoringEngine({ now: nowFn, weights: cfg.weights, thresholds: cfg.thresholds, decayMs: cfg.decayMs });

  const evidenceLog = []; // recent human-readable evidence strings (capped)
  const eventLog = []; // recent typed events (capped, metadata only)
  const MAX_LOG = 200;
  let crashed = false;

  function log(fmt) {
    if (debug) {
      try {
        const d = new Date(nowFn());
        const pad = (n) => String(n).padStart(2, '0');
        // eslint-disable-next-line no-console
        console.log(`[${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}] ${fmt}`);
      } catch { /* ignore */ }
    }
  }

  function pushEvidence(label) {
    evidenceLog.push(label);
    while (evidenceLog.length > MAX_LOG) evidenceLog.shift();
  }

  function pushEvent(e) {
    eventLog.push(e);
    while (eventLog.length > MAX_LOG) eventLog.shift();
    return e;
  }

  // Feed one live process snapshot through every monitor. Returns
  // { events, detection } where detection is the current DetectionEvent.
  function update(processList) {
    if (crashed) return { events: [], detection: unavailableEvent('engine previously crashed') };
    try {
      const out = [];

      // 1. Process tree diff.
      const procEvents = processes.update(processList || []);
      procEvents.forEach(pushEvent);
      out.push(...procEvents);

      // 2. Signature match → known-agent evidence (+40). Track agent pids.
      const agentPids = new Set();
      for (const p of (Array.isArray(processList) ? processList : [])) {
        if (!p || !p.pid) continue;
        const matches = matchProcess(p, signatures);
        for (const m of matches) {
          agentPids.add(p.pid);
          const label = `Known agent process detected: ${m.agentName}`;
          pushEvidence(label);
          scoring.addEvidence('knownAgentProcess', label);
          behavior.observe('KnownAgentProcessObserved');
          log(`ProcessStarted: ${lastSegment(p.exe || '')} → ${label}`);
        }
        // Child/subprocess of a known agent (+15).
        const ancestors = processes.ancestorsOf(p.pid);
        for (const anc of ancestors) {
          if (matchProcess(anc, signatures).length > 0) {
            const label = `Agent child/subprocess relationship: ${lastSegment(p.exe || '')} spawned by ${lastSegment(anc.exe || '')}`;
            pushEvidence(label);
            scoring.addEvidence('agentChildRelationship', label);
            break;
          }
        }
      }

      // 3. Automation / accessibility monitoring (+25 each).
      const autoEvents = automation.update(processList || [], agentPids);
      autoEvents.forEach(pushEvent);
      out.push(...autoEvents);
      for (const e of autoEvents) {
        if (e.type === 'AutomationAccessStarted' || e.type === 'AutomationAccessObserved') {
          const who = e.source ? (e.source.name || e.source.exe) : 'unknown';
          const label = `Accessibility automation observed: ${who} → ${e.targetApplication || 'app'}`;
          pushEvidence(label);
          scoring.addEvidence('accessibilityAutomation', label);
          behavior.observe(e);
          log(`AutomationAccessObserved: ${who} → ${e.targetApplication || 'app'}`);
        }
      }

      // 4. Programmatic input heuristic (+25 each).
      const inputEvents = input.scanProcesses(processList || []);
      inputEvents.forEach(pushEvent);
      out.push(...inputEvents);
      for (const e of inputEvents) {
        const label = 'Programmatic input detected';
        pushEvidence(label);
        scoring.addEvidence('programmaticInput', label);
        behavior.observe(e);
        log('ProgrammaticInputDetected');
      }

      // 5. Behavioral patterns (+20 each).
      const patterns = behavior.analyze();
      patterns.forEach(pushEvent);
      out.push(...patterns);
      for (const e of patterns) {
        const label = `Repeated automation pattern: ${e.pattern}`;
        pushEvidence(label);
        scoring.addEvidence('repeatedPattern', label);
        log(`AutomationPattern: ${e.pattern}`);
      }

      const snap = scoring.snapshot();
      log(`DetectionScore: ${snap.score}`);
      log(`DetectionLevel: ${snap.level}`);
      return { events: out, detection: currentDetection() };
    } catch (err) {
      crashed = true;
      return { events: [], detection: unavailableEvent(err && err.message) };
    }
  }

  // Direct ingestion for hosts with native event taps (metadata only).
  function observeInput({ eventType, source, targetApplication }) {
    const e = input.observe({ eventType, source, targetApplication });
    if (!e) return currentDetection();
    pushEvent(e);
    if (e.source === 'programmatic') {
      pushEvidence('Programmatic input detected');
      scoring.addEvidence('programmaticInput', 'Programmatic input detected');
    }
    behavior.observe(e);
    for (const p of behavior.analyze()) {
      pushEvent(p);
      pushEvidence(`Repeated automation pattern: ${p.pattern}`);
      scoring.addEvidence('repeatedPattern', `Repeated automation pattern: ${p.pattern}`);
    }
    return currentDetection();
  }

  function currentDetection() {
    if (crashed) return unavailableEvent('engine crashed');
    const snap = scoring.snapshot();
    return {
      timestamp: new Date(nowFn()).toISOString(),
      level: snap.level,
      score: snap.score,
      evidence: evidenceLog.slice(-20),
    };
  }

  function unavailableEvent(reason) {
    return {
      timestamp: new Date(nowFn()).toISOString(),
      level: 'DETECTION_UNAVAILABLE',
      score: 0,
      evidence: ['Detection unavailable' + (reason ? ': ' + reason : '')],
    };
  }

  function status() {
    const d = currentDetection();
    return {
      level: d.level,
      score: d.score,
      evidence: d.evidence.slice(),
      recentActivity: eventLog.slice(-20).map((e) => ({ type: e.type, timestamp: e.timestamp })),
      crashed,
    };
  }

  function reset() {
    processes.reset();
    automation.reset();
    input.reset();
    behavior.reset();
    scoring.reset();
    evidenceLog.length = 0;
    eventLog.length = 0;
    crashed = false;
  }

  return {
    update, observeInput, currentDetection, status, reset,
    _processes: processes, _automation: automation, _input: input,
    _behavior: behavior, _scoring: scoring, _signatures: signatures,
  };
}

module.exports = { createDetectionEngine };
