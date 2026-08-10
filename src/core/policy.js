/* Auren - policy.js
 *
 * Policy layer over the classifier signal. The classifier (src/core/sensitive.js)
 * only answers "is this sensitive, and which types?"; this module decides what
 * to DO about it. Keep these two decoupled so detection rules can change without
 * touching policy, and vice versa.
 *
 * Decision model (most severe wins):
 *   action: 'allow' | 'log' | 'require_auth' | 'block'
 *
 * Default rules map a classifier type to an action. Tuning is a config change,
 * not a code change (see README "Sensitive-action policy").
 */

'use strict';

// Conservative defaults: anything sensitive asks for native OS auth.
const DEFAULT_RULES = Object.freeze({
  ssn: 'require_auth',
  credit_card: 'require_auth',
  password: 'require_auth',
  email_password: 'require_auth',
  secret: 'require_auth'
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
