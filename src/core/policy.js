/* Auren - policy.js
 *
 * Policy layer over classifier signals. The classifiers (src/core/sensitive.js
 * for outgoing form data, src/core/commands.js for OS/terminal-level commands)
 * only answer "is this sensitive/network-capable, and which types?"; this
 * module decides what to DO about it. Keep detection and policy decoupled so
 * rules can change without touching detection, and vice versa.
 *
 * Decision model (most severe wins):
 *   action: 'allow' | 'log' | 'require_auth' | 'block'
 *
 * Default rules:
 *   - outgoing sensitive data (autofill gate) -> require native OS auth
 *   - network-capable OS/terminal commands (command gate) -> BLOCK
 *
 * Tuning is a config change, not a code change (see README "Sensitive-action
 * policy" and "Terminal & OS-level network access").
 *
 * Automation policy (Phase 9 of the Local Agent Detection plan): the
 * AgentDetection engine provides evidence/context only
 * ({ level, score, evidence }); THIS module decides the action:
 *   ALLOW | WARN | REQUIRE_APPROVAL | BLOCK
 * Never auto-blocks solely because an app is an AI app — a sensitive
 * operation plus a detection is what escalates.
 */

'use strict';

// Conservative defaults:
//  - Anything sensitive asks for native OS auth.
//  - OS/terminal-level network commands are blocked by default.
const DEFAULT_RULES = Object.freeze({
  ssn: 'require_auth',
  credit_card: 'require_auth',
  password: 'require_auth',
  email_password: 'require_auth',
  secret: 'require_auth',
  cmd_ssh: 'block',
  cmd_ping: 'block',
  cmd_probe: 'block',
  cmd_tunnel: 'block',
  cmd_suspicious_443: 'block',
  cmd_transfer: 'block',
  cmd_reverse_shell: 'block',
  cmd_remote_admin: 'block',
  cmd_exfil: 'block'
});

const SEVERITY = { allow: 1, log: 2, require_auth: 3, block: 4 };

function makePolicy(rules) {
  return Object.assign({}, DEFAULT_RULES, rules);
}

// signal: { sensitive, types[] } from the classifier.
// opts: { degraded: boolean, rules: custom policy map }
// Returns { action, reason, types }.
function decidePolicy(signal, opts) {
  const rules = (opts && opts.rules) ? makePolicy(opts.rules) : DEFAULT_RULES;
  if (opts && opts.degraded) {
    return { action: 'block', reason: 'enforcement degraded', types: (signal && signal.types) || [] };
  }
  if (!signal || !signal.sensitive) {
    return { action: 'allow', reason: 'not sensitive', types: [] };
  }

  let action = 'allow';
  let reason = 'not sensitive';
  for (const t of signal.types) {
    const rule = rules[t] || 'require_auth';
    if (SEVERITY[rule] >= SEVERITY[action]) {
      action = rule;
      reason = 'contains ' + t;
    }
  }
  return { action, reason, types: signal.types };
}

// ---------------------------------------------------------------------------
// Automation policy: maps an AgentDetection DetectionEvent + operation context
// to ALLOW | WARN | REQUIRE_APPROVAL | BLOCK. Detection never blocks on its
// own; the policy engine decides.
//
//   detection: { level, score, evidence[] } from the detection engine.
//   ctx: { sensitiveOperation: boolean, degraded: boolean,
//          rules: optional overrides { NORMAL, SUSPICIOUS, LIKELY_AUTOMATION,
//          HIGH_CONFIDENCE_AGENT, SENSITIVE_ESCALATION } }
//
// Default matrix (tunable via settings.json automationPolicy):
//   NORMAL                                  -> ALLOW
//   SUSPICIOUS                              -> ALLOW (unknown/low-confidence)
//   LIKELY_AUTOMATION                       -> WARN
//   HIGH_CONFIDENCE_AGENT                   -> REQUIRE_APPROVAL
//   any level + sensitiveOperation          -> escalate one step
//     (e.g. agent detected + sensitive op  -> REQUIRE_APPROVAL;
//      HIGH_CONFIDENCE + sensitive op      -> BLOCK)
//   degraded enforcement                    -> BLOCK (fail safely)
// ---------------------------------------------------------------------------
const AUTOMATION_ACTIONS = Object.freeze(['ALLOW', 'WARN', 'REQUIRE_APPROVAL', 'BLOCK']);

const DEFAULT_AUTOMATION_RULES = Object.freeze({
  NORMAL: 'ALLOW',
  SUSPICIOUS: 'ALLOW',
  LIKELY_AUTOMATION: 'WARN',
  HIGH_CONFIDENCE_AGENT: 'REQUIRE_APPROVAL',
  DETECTION_UNAVAILABLE: 'WARN',
  SENSITIVE_ESCALATION: true,
});

const AUTOMATION_SEVERITY = { ALLOW: 1, WARN: 2, REQUIRE_APPROVAL: 3, BLOCK: 4 };

function escalate(action) {
  const order = ['ALLOW', 'WARN', 'REQUIRE_APPROVAL', 'BLOCK'];
  const i = order.indexOf(action);
  return i === -1 || i >= order.length - 1 ? 'BLOCK' : order[i + 1];
}

function decideAutomationPolicy(detection, ctx) {
  const c = (ctx && typeof ctx === 'object') ? ctx : {};
  if (c.degraded) {
    return { action: 'BLOCK', reason: 'enforcement degraded — fail safely', level: (detection && detection.level) || 'UNKNOWN' };
  }
  const rules = Object.assign({}, DEFAULT_AUTOMATION_RULES, c.rules);
  const level = (detection && detection.level) || 'NORMAL';
  let action = rules[level] || 'ALLOW';
  if (!AUTOMATION_ACTIONS.includes(action)) action = 'ALLOW';
  const sensitive = c.sensitiveOperation === true;
  if (sensitive && rules.SENSITIVE_ESCALATION !== false && action !== 'BLOCK') {
    action = escalate(action);
  }
  const evidence = (detection && Array.isArray(detection.evidence)) ? detection.evidence.slice(0, 20) : [];
  return {
    action,
    reason: sensitive ? `automation level ${level} with sensitive operation` : `automation level ${level}`,
    level,
    score: (detection && detection.score) || 0,
    evidence,
  };
}

module.exports = { DEFAULT_RULES, decidePolicy, makePolicy, AUTOMATION_ACTIONS, DEFAULT_AUTOMATION_RULES, decideAutomationPolicy };
