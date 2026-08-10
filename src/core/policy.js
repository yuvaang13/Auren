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

module.exports = { DEFAULT_RULES, decidePolicy, makePolicy };
