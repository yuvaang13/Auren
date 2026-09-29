/* Auren — AgentDetection InputMonitor.
 *
 * Phase 5 of the plan. Local input monitor identifying suspicious
 * PROGRAMMATIC input from metadata only.
 *
 * Observed metadata per event: { timestamp, eventType, source,
 * targetApplication }. eventType is one of MouseClick | KeyboardEvent |
 * ScrollEvent. source is 'human' | 'programmatic' | 'unknown'.
 *
 * Explicitly NEVER recorded: typed text, passwords, clipboard contents,
 * screenshots, private document contents. There is no field for content and
 * no code path that captures it.
 *
 * Two ingestion paths:
 *   1. observe({ eventType, source, targetApplication }) — for hosts with a
 *      native event-tap / CGEvent-source binding that reports whether an
 *      event was synthesized (kCGEventSourceStateID / kCGEventSourceGroupID).
 *      Returns the typed ProgrammaticInputObserved event (or null when the
 *      observation is human-sourced and opts.emitHuman is false).
 *   2. scanProcesses(processList) — heuristic fallback with zero permissions:
 *      processes whose command lines indicate input synthesis (cliclick,
 *      xdotool-equivalents, AppleScript `keystroke`/`click`, Python
 *      Quartz/pynput controllers) emit programmatic input evidence.
 *      Coarse and clearly labeled as heuristic evidence.
 */

'use strict';

const events = require('./events');

function lastSegment(s) {
  return String(s || '').split(/[\\/]/).pop();
}

// Command-line shapes that synthesize input or drive another app's UI.
// Includes direct input synthesizers (cliclick, CGEventPost, pynput…) and
// macOS automation scripting verbs (AppleScript `tell application`, keystroke,
// `do shell script`) — running those IS programmatic control of another app.
const SYNTH_RE = /(?:cliclick|xdotool|ydotool|keystroke|key\s+code|CGEventCreate|CGEventPost|pynput|pyautogui|robotjs|nut\.js|keytap|tell\s+application|do\s+shell\s+script)/i;

function looksSynthesized(proc) {
  if (!proc) return false;
  const toks = Array.isArray(proc.tokens) ? proc.tokens.join(' ') : '';
  const exe = String(proc.exe || '');
  return SYNTH_RE.test(lastSegment(exe) + ' ' + toks);
}

function createInputMonitor(opts) {
  const cfg = (opts && typeof opts === 'object') ? opts : {};
  const nowFn = typeof cfg.now === 'function' ? cfg.now : () => Date.now();
  const emitHuman = cfg.emitHuman === true;
  // Ephemeral in-memory ring buffer (metadata only), capped.
  const buffer = [];
  const MAX_BUFFER = Number.isFinite(cfg.maxBuffer) ? cfg.maxBuffer : 500;

  function push(e) {
    buffer.push(e);
    while (buffer.length > MAX_BUFFER) buffer.shift();
    return e;
  }

  function observe({ eventType, source, targetApplication }) {
    if (source === 'human' && !emitHuman) return null;
    return push(events.programmaticInputObserved({ eventType, source, targetApplication, nowFn }));
  }

  // Heuristic process scan → programmatic-input evidence events.
  function scanProcesses(processList) {
    const out = [];
    for (const p of (Array.isArray(processList) ? processList : [])) {
      if (!p || !p.pid || p.pid <= 1) continue;
      if (looksSynthesized(p)) {
        out.push(push(events.programmaticInputObserved({
          eventType: 'KeyboardEvent',
          source: 'programmatic',
          targetApplication: null,
          nowFn,
        })));
        // Attach non-sensitive attribution for the engine (pid/exe only).
        out[out.length - 1].pid = p.pid;
        out[out.length - 1].exe = p.exe || '';
      }
    }
    return out;
  }

  function recent(limit) {
    return buffer.slice(-(limit || 100));
  }

  function reset() { buffer.length = 0; }

  return { observe, scanProcesses, recent, reset };
}

module.exports = { createInputMonitor, looksSynthesized };
