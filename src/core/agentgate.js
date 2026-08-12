/* Auren - agentgate.js
 *
 * Shared decision functions for Auren's agent gates. There is exactly ONE
 * implementation of each decision, and every integration surface calls it:
 * the Electron IPC handlers (src/main.js) and the loopback HTTP bridge
 * (src/bridge/http.js). Keeping the logic here means a decision made over the
 * bridge is identical to one made over IPC, and both are unit-testable without
 * Electron.
 *
 * This module is pure: it only needs the pieces passed in via ctx.
 *
 * ctx contract:
 *   {
 *     mode: 'on' | 'off',
 *     degraded: boolean,        // enforcement can't be trusted -> fail closed
 *     failClosed: boolean,      // encrypted store unverified -> fail closed
 *     sensitiveRules: object,   // settings.sensitivePolicy (may be undefined)
 *     commandRules: object,     // settings.commandPolicy (may be undefined)
 *     blocklist: string[],      // site block list (for isBlocked)
 *     authFn: (reason) => Promise<boolean>,  // OS-native auth checkpoint
 *     logFn: (entry) => void,   // writes an activity entry
 *     notifyFn: (void) => void  // optional UI push after a decision
 *   }
 */

'use strict';

const sensitive = require('./sensitive');
const commands = require('./commands');
const policy = require('./policy');
const activity = require('./activity');
const { normalizeDomain, domainMatches } = require('./domains');

// The allow/log/block/require_auth tail shared by both gates. Returns the same
// shape as the old IPC handlers: { allowed, action, types, reason } where
// `action` is the policy action, not the actual outcome (so a require_auth
// decision that the user cancels returns action 'require_auth' but allowed
// false, exactly as before).
async function runDecision(signal, decision, opts) {
  const { kind, reason, ctx } = opts;
  let allowed = false;
  let outcome;
  if (decision.action === 'allow') {
    allowed = true;
    outcome = 'allowed';
  } else if (decision.action === 'log') {
    allowed = true;
    outcome = 'logged';
  } else if (decision.action === 'block') {
    outcome = 'blocked';
  } else {
    // require_auth — the user's OS-native checkpoint decides.
    const ok = await ctx.authFn(reason);
    if (ok) { allowed = true; outcome = 'allowed'; }
    else outcome = 'blocked';
  }

  const note = 'types=' + (signal.types.join(',') || 'none');
  if (ctx.logFn) ctx.logFn(activity.makeEntry(kind, outcome, null, note));
  if (ctx.notifyFn) ctx.notifyFn();
  return { allowed, action: decision.action, types: signal.types, reason: decision.reason };
}

// Gate an outgoing agent action (form submission, JSON body, raw payload).
// Unlike the command gate there is NO mode guard: a sensitive payload asks for
// native auth even while protection is off. While degraded it fails closed.
async function inspectAction(payload, ctx = {}) {
  const signal = sensitive.classifySensitivePayload(payload);
  const decision = policy.decidePolicy(signal, {
    degraded: ctx.degraded || ctx.failClosed,
    rules: ctx.sensitiveRules
  });
  const typesLabel = signal.types.join(', ') || 'sensitive data';
  const reason = 'Approve sending ' + typesLabel + (payload && payload.url ? ' to ' + payload.url : '');
  return runDecision(signal, decision, { kind: 'agent', reason, ctx });
}

// Gate an OS/terminal-level agent command. Tied to Protection Mode: while
// protection is OFF the gate does not stand in the way; while degraded it
// refuses (fail-closed). Only a bridge/native host that routes commands
// through Auren hits this gate — the pf firewall covers everything else.
async function inspectCommand(cmd, ctx = {}) {
  if (ctx.degraded || ctx.failClosed) {
    if (ctx.logFn) ctx.logFn(activity.makeEntry('command', 'blocked', null, 'enforcement degraded'));
    if (ctx.notifyFn) ctx.notifyFn();
    return { allowed: false, action: 'block', types: [], reason: 'enforcement degraded' };
  }
  if (ctx.mode !== 'on') {
    return { allowed: true, action: 'allow', types: [], reason: 'protection off' };
  }
  const signal = commands.classifyCommand(cmd);
  const decision = policy.decidePolicy(signal, { degraded: false, rules: ctx.commandRules });
  const typesLabel = signal.types.join(', ') || 'network access';
  const reason = 'Approve running a network-capable command (' + typesLabel + ')';
  return runDecision(signal, decision, { kind: 'command', reason, ctx });
}

// Read-only "is this site blocked?" used by the UI and any bridge component.
// While degraded everything is reported as blocked (fail-closed).
function isBlocked(domain, ctx = {}) {
  if (ctx.degraded || ctx.failClosed) return true;
  if (ctx.mode !== 'on') return false;
  const d = normalizeDomain(domain);
  return (ctx.blocklist || []).some((x) => domainMatches(d, x));
}

module.exports = { inspectAction, inspectCommand, isBlocked };
