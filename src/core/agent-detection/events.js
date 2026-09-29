/* Auren — AgentDetection typed local events.
 *
 * Phase 1 of the Local Agent Detection plan. All AgentDetection components
 * communicate through these typed, purely-local event objects. No network,
 * no ML, no LLM — just plain data + timestamps.
 *
 * Event kinds:
 *   ProcessStarted / ProcessStopped / ProcessRelationshipChanged
 *   AutomationAccessStarted / AutomationAccessObserved / AutomationAccessStopped
 *   ProgrammaticInputObserved (MouseClick | KeyboardEvent | ScrollEvent metadata)
 *   AutomationPatternObserved (from BehaviorAnalyzer)
 *   DetectionEvent (final scored output — see detection-engine.js)
 *
 * Privacy: input events carry metadata ONLY (timestamp, eventType, source,
 * targetApplication). Never typed text, passwords, clipboard, screenshots,
 * or document contents.
 */

'use strict';

const EVENT_TYPES = Object.freeze([
  'ProcessStarted',
  'ProcessStopped',
  'ProcessRelationshipChanged',
  'AutomationAccessStarted',
  'AutomationAccessObserved',
  'AutomationAccessStopped',
  'ProgrammaticInputObserved',
  'AutomationPatternObserved',
  'DetectionEvent',
]);

function nowIso(nowFn) {
  try {
    const t = typeof nowFn === 'function' ? nowFn() : Date.now();
    return new Date(t).toISOString();
  } catch { return new Date().toISOString(); }
}

function baseEvent(type, fields, nowFn) {
  return Object.assign({ type, timestamp: nowIso(nowFn) }, fields || {});
}

function processStarted(proc, nowFn) {
  return baseEvent('ProcessStarted', {
    pid: proc.pid, ppid: proc.ppid || null,
    exe: proc.exe || '', bundleId: proc.bundleId || null,
  }, nowFn);
}

function processStopped(proc, nowFn) {
  return baseEvent('ProcessStopped', {
    pid: proc.pid, exe: proc.exe || '',
  }, nowFn);
}

function processRelationshipChanged(pid, oldPpid, newPpid, nowFn) {
  return baseEvent('ProcessRelationshipChanged', { pid, oldPpid, newPpid }, nowFn);
}

function automationEvent(type, source, target, automationType, nowFn) {
  return baseEvent(type, {
    source: source ? { pid: source.pid || null, exe: source.exe || '', name: source.name || '' } : null,
    targetApplication: target || null,
    automationType: automationType || 'accessibility',
  }, nowFn);
}

// Metadata-only input observation. `source` is 'human' | 'programmatic' |
// 'unknown'; never includes content.
function programmaticInputObserved({ eventType, source, targetApplication, nowFn }) {
  const allowed = ['MouseClick', 'KeyboardEvent', 'ScrollEvent'];
  return baseEvent('ProgrammaticInputObserved', {
    eventType: allowed.includes(eventType) ? eventType : 'KeyboardEvent',
    source: source || 'unknown',
    targetApplication: targetApplication || null,
  }, nowFn);
}

function automationPatternObserved(pattern, detail, nowFn) {
  return baseEvent('AutomationPatternObserved', {
    pattern,
    detail: detail || null,
  }, nowFn);
}

function isValidEvent(e) {
  return !!(e && typeof e === 'object' && EVENT_TYPES.includes(e.type) && typeof e.timestamp === 'string');
}

module.exports = {
  EVENT_TYPES,
  processStarted,
  processStopped,
  processRelationshipChanged,
  automationEvent,
  programmaticInputObserved,
  automationPatternObserved,
  isValidEvent,
};
