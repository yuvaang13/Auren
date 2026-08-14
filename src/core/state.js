/* Auren — state.js
 *
 * Merge semantics for the daemon's state.json. The daemon snapshots the
 * machine's original DNS (state.services) and system-proxy (state.proxy)
 * configuration when it takes them over, so it can hand them back on
 * protection-off. applyProxy records each service's prior proxy config
 * in-memory and the reconcile loop re-reads state.json (loadState) before the
 * proxy work runs — a plain replace would throw those fresh in-memory records
 * away, and clearProxy would then have nothing to restore, leaving the system
 * PAC pointed at a stopped proxy (ALL HTTPS breaks). mergeState is the rule
 * for that read: disk wins for keys it actually holds; keys it lacks (fresh
 * takeovers not yet persisted) survive from the in-memory copy.
 */

'use strict';

const DEFAULTS = { services: {}, applied: false };

function mergeState(prev, disk) {
  const base = Object.assign({}, DEFAULTS);
  const inMemory = (prev && typeof prev === 'object') ? prev : {};
  if (disk && typeof disk === 'object') return Object.assign(base, inMemory, disk);
  return Object.assign(base, inMemory);
}

module.exports = { mergeState };
