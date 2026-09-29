/* Auren — AgentDetection SignatureDatabase.
 *
 * Phase 3 of the plan. Local signature configuration, kept SEPARATE from the
 * detection engine so new applications can be added without rewriting logic.
 *
 * Signatures are evidence, not proof: a name match alone never confirms an
 * agent (see scoring.js). Detection answers "is there sufficient local
 * evidence of automated control?", never "which model is this?".
 *
 * No network, no ML. Pure data + match helpers. User-extendable via
 * settings.json { agentDetection: { knownAgents: [...] } }.
 */

'use strict';

const DEFAULT_SIGNATURES = Object.freeze({
  knownAgents: [
    { name: 'Claude', processNames: ['Claude'], bundleIdentifiers: [] },
    { name: 'Codex', processNames: ['codex'], bundleIdentifiers: [] },
    { name: 'OpenCode', processNames: ['opencode'], bundleIdentifiers: [] },
    { name: 'Cursor', processNames: ['Cursor'], bundleIdentifiers: ['com.todesktop.230313mzl4w4u92'] },
    { name: 'Windsurf', processNames: ['Windsurf'], bundleIdentifiers: [] },
    { name: 'Aider', processNames: ['aider'], bundleIdentifiers: [] },
    { name: 'Goose', processNames: ['goose'], bundleIdentifiers: [] },
    { name: 'GeminiCLI', processNames: ['gemini'], bundleIdentifiers: [] },
  ],
});

function lastSegment(s) {
  return String(s || '').split(/[\\/]/).pop();
}

// Normalize raw config (built-ins + user overrides appended). Invalid entries
// are dropped, never fatal.
function normalizeSignatures(raw) {
  const base = DEFAULT_SIGNATURES.knownAgents.map((a) => ({
    name: String(a.name),
    processNames: (a.processNames || []).map((n) => String(n)),
    bundleIdentifiers: (a.bundleIdentifiers || []).map((b) => String(b)),
  }));
  const extra = raw && Array.isArray(raw.knownAgents) ? raw.knownAgents : [];
  for (const a of extra) {
    if (!a || typeof a !== 'object' || !String(a.name || '').trim()) continue;
    base.push({
      name: String(a.name).trim(),
      processNames: Array.isArray(a.processNames) ? a.processNames.map((n) => String(n)) : [],
      bundleIdentifiers: Array.isArray(a.bundleIdentifiers) ? a.bundleIdentifiers.map((b) => String(b)) : [],
    });
  }
  return { knownAgents: base };
}

// Match a single process descriptor { exe, bundleId } against signatures.
// Case-insensitive basename comparison. Returns [{ agentName }] (evidence).
function matchProcess(proc, signatures) {
  const list = (signatures && signatures.knownAgents) || DEFAULT_SIGNATURES.knownAgents;
  if (!proc) return [];
  const base = lastSegment(proc.exe || '').toLowerCase();
  const bundle = String(proc.bundleId || '');
  const out = [];
  for (const sig of list) {
    const names = (sig.processNames || []).map((n) => String(n).toLowerCase());
    const bundles = sig.bundleIdentifiers || [];
    if ((base && names.includes(base)) || (bundle && bundles.includes(bundle))) {
      out.push({ agentName: sig.name });
    }
  }
  return out;
}

module.exports = { DEFAULT_SIGNATURES, normalizeSignatures, matchProcess };
