/* Auren — agentdetect.js
 *
 * Heuristic detection of "an AI-agent session is running on this machine",
 * used by auto-protect (src/core/autoprotect.js + agenttrack.js). This is
 * intentionally NOT an AI classifier: it matches process descriptors
 * ({ pid, ppid, exe, tokens }, the same shape src/platform/procs-* produces)
 * against a curated, user-extendable signature list. It is honest about what
 * it is, and it can only ever RAISE protection; it never turns it off.
 *
 * Every match is evidence with a score, not a binary flag:
 *   - a match on the executable BASENAME is always score 3 (the real agent
 *     binary is running — unambiguous, e.g. `codex`, `cursor`, `chromedriver`);
 *   - a match on an argv token is scored by the signature's tier:
 *       flag    -> 3   dedicated automation flags/driver processes
 *                    (`--headless`, `--remote-debugging-port=`, playwright…)
 *       wrapper -> 2   wrapper/package invocations
 *                    (`claude-code`, `@anthropic-ai/claude-code`, `@openai/codex`)
 *       word    -> 1   a bare tool name used as an argument
 *                    (`rg codex`, `vim goose`) — weak, needs to persist
 *
 * So a real agent flips the tracker instantly at score 3, while a stray word
 * in an unrelated command line contributes almost nothing and must accumulate.
 *
 * Ancestry: processes spawned BY a strong match (ancestor chain via ppid) also
 * count as evidence at score 2, which catches headed Playwright/Puppeteer
 * browsers and agent-spawned terminals that carry no agent-looking flags.
 *
 * Users can extend/ignore via settings.json:
 *   { "autoProtect": { "tools": [{ "name": "my-agent", "re": "\\bmyagent\\b" }],
 *                      "ignore": [{ "tool": "claude-code", "exe": "claude" }] } }
 * Signatures match a full token (never a partial path), so a project directory
 * named "cursor" can't trip the cursor detector by accident.
 */

'use strict';

// Known agent tooling. `tier` only matters when the match is on an argv token:
//   flag    = dedicated automation flag / driver process      (score 3)
//   wrapper = package / wrapper invocation                    (score 2)
//   word    = bare tool name used as an argument              (score 1)
// A basename match of ANY of these is always score 3.
const DEFAULT_TOOLS = [
  // Browser automation — the classic "an agent is driving a browser" signal.
  { name: 'headless-browser', re: /--headless/, tier: 'flag' },
  { name: 'remote-debugging', re: /--remote-debugging-port=/, tier: 'flag' },
  { name: 'browser-driver', re: /\b(?:chromedriver|geckodriver|msedgedriver|operadriver|phantomjs)\b/i, tier: 'flag' },
  { name: 'playwright', re: /\bplaywright\b/i, tier: 'flag' },
  { name: 'puppeteer', re: /\bpuppeteer\b/i, tier: 'flag' },
  { name: 'selenium', re: /\bselenium\b/i, tier: 'flag' },
  // Coding / terminal CLI agents. Their binary basename is the strong signal;
  // the bare word (e.g. `rg codex`) is deliberately weak.
  { name: 'claude-code', re: /\bclaude(?:[\s-]?code)?\b/i, tier: 'word' },
  { name: 'codex-cli', re: /\bcodex\b/i, tier: 'word' },
  { name: 'goose', re: /\bgoose\b/i, tier: 'word' },
  { name: 'opencode', re: /\bopencode\b/i, tier: 'word' },
  { name: 'gemini-cli', re: /\bgemini(?:-cli)?\b/i, tier: 'word' },
  { name: 'aider', re: /\baider\b/i, tier: 'word' },
  { name: 'openhands', re: /\bopenhands\b/i, tier: 'word' },
  // Agent-hosted IDEs / agent desktops.
  { name: 'cursor', re: /\bcursor\b/i, tier: 'word' },
  { name: 'windsurf', re: /\bwindsurf\b/i, tier: 'word' },
  // Wrapper / package invocations (npx claude-code, bunx @openai/codex).
  { name: 'claude-code-wrapper', re: /\b(?:@anthropic-ai\/)?claude[-_]code\b/i, tier: 'wrapper' },
  { name: 'codex-wrapper', re: /\b@openai\/codex\b/i, tier: 'wrapper' },
  { name: 'gemini-cli-wrapper', re: /\bgemini-cli\b/i, tier: 'wrapper' }
];

// Last path segment regardless of the running platform's separator, so a
// Windows-style path seen on macOS (or vice versa) still resolves correctly.
function lastSegment(s) {
  return String(s || '').split(/[\\/]/).pop();
}

// Candidate strings to match a signature against, tagged with where they came
// from: the executable basename ('exe') or an argv token ('argv'). Path-like
// candidates (containing a / or \ separator) are reduced to their last segment
// first, so a *path* like /Users/me/projects/cursor/app.js never matches
// "cursor" — only the basename app.js does. Bare words and flags (--headless,
// playwright, aider) are matched in full.
function candidatesFor(p) {
  const out = [];
  const push = (s, via) => {
    const t = String(s || '').trim();
    if (!t) return;
    out.push({ s: t, via });
    out.push({ s: t.toLowerCase(), via });
  };
  const reduce = (s) => (/[\\/]/.test(s) ? lastSegment(s) : s);
  if (p.exe) push(reduce(p.exe), 'exe');
  for (const t of (Array.isArray(p.tokens) ? p.tokens : [])) { push(reduce(t), 'argv'); }
  return out;
}

// Merge the built-in signatures with any user overrides. A user entry must
// carry { name, re } (a RegExp) or { name, pattern } (a RegExp source string);
// invalid entries are dropped, never fatal. User entries default to the
// 'wrapper' tier (explicit opt-in = real evidence, score 2) unless they say
// otherwise. Defaults keep their built-in tiers.
function normalizeTools(raw) {
  const out = DEFAULT_TOOLS.map((t) => ({ name: t.name, re: t.re, tier: t.tier }));
  if (Array.isArray(raw)) {
    for (const t of raw) {
      if (!t || typeof t !== 'object') continue;
      const name = String(t.name || '').trim();
      const source = t.re != null ? String(t.re) : (t.pattern != null ? String(t.pattern) : '');
      if (!name || !source) continue;
      const tier = t.tier === 'flag' || t.tier === 'word' ? t.tier : 'wrapper';
      try { out.push({ name, re: new RegExp(source), tier }); } catch { /* skip invalid regex */ }
    }
  }
  return out;
}

// Normalize an autoProtect.ignore list: [{ tool, exe? }, ...]. `tool` names
// which signature to silence; optional `exe` narrows it to that executable
// (exact path, basename, or case-insensitive basename).
function normalizeIgnore(raw) {
  const out = [];
  if (Array.isArray(raw)) {
    for (const i of raw) {
      if (!i || typeof i !== 'object') continue;
      const tool = String(i.tool || '').trim();
      if (!tool) continue;
      const exe = i.exe != null ? String(i.exe).trim() : '';
      out.push(exe ? { tool, exe } : { tool });
    }
  }
  return out;
}

// Does an ignore entry silence this match? Tool name must match; if the entry
// has an exe it must match the process executable (path, basename, or
// case-insensitive basename).
function isIgnored(match, ignore) {
  for (const i of ignore) {
    if (i.tool !== match.tool) continue;
    if (!i.exe) return true;
    const base = lastSegment(match.exe);
    if (match.exe === i.exe || base === i.exe || base.toLowerCase() === i.exe.toLowerCase()) return true;
  }
  return false;
}

// Score for a match, given whether it hit the executable basename or an argv
// token, and the signature tier.
function scoreFor(via, tier) {
  if (via === 'exe') return 3;
  if (tier === 'flag') return 3;
  if (tier === 'wrapper') return 2;
  return 1;
}

// Which running processes match a known agent-tool signature?
//   processList: [{ pid, ppid, exe, tokens }, ...] (from src/platform/procs-*)
//   tools:       output of normalizeTools()
//   opts:        { ignore: raw autoProtect.ignore list }
// Returns [{ pid, exe, tool, via, tier, score }, ...] — at most one entry per
// (tool, pid), with the best (exe-over-argv) scoring match for that pair.
function detectSessions(processList, tools, opts) {
  const list = Array.isArray(processList) ? processList : [];
  const ignore = normalizeIgnore(opts && opts.ignore);
  const out = [];
  const seen = new Set();
  for (const p of list) {
    if (!p || !p.pid || p.pid <= 1) continue;
    const cands = candidatesFor(p);
    if (cands.length === 0) continue;
    // Best via per tool for this pid: exe outranks argv.
    const best = new Map();
    for (const c of cands) {
      for (const tool of tools) {
        if (tool.re.test(c.s)) {
          const rank = c.via === 'exe' ? 1 : 0;
          const prev = best.get(tool.name);
          if (!prev || rank > prev.rank) best.set(tool.name, { rank, via: c.via, tier: tool.tier });
        }
      }
    }
    for (const [tool, m] of best) {
      const key = tool + ':' + p.pid;
      if (seen.has(key)) continue;
      seen.add(key);
      const match = { pid: p.pid, exe: p.exe || '', tool, via: m.via, tier: m.tier, score: scoreFor(m.via, m.tier) };
      if (isIgnored(match, ignore)) continue;
      out.push(match);
    }
  }
  return out;
}

// Processes spawned by a strong agent match also count as agent activity (score
// 2, via 'spawned'), so a headed Playwright browser or an agent-spawned shell
// that carries no agent-looking flags still contributes evidence. Walk the
// ancestor chain via ppid; never the same pid twice, capped at 10 hops.
function ancestorEvidence(processList, baseSessions) {
  const list = Array.isArray(processList) ? processList : [];
  if (list.length === 0) return [];
  const strong = new Map();
  for (const s of (Array.isArray(baseSessions) ? baseSessions : [])) {
    if (s.score >= 3) strong.set(s.pid, s.tool);
  }
  if (strong.size === 0) return [];
  const byPid = new Map();
  for (const p of list) if (p.pid) byPid.set(p.pid, p);
  const out = [];
  const seen = new Set();
  for (const p of list) {
    if (!p || !p.pid || p.pid <= 1) continue;
    if (strong.has(p.pid)) continue; // already direct evidence
    let node = p;
    let hops = 0;
    while (node && hops < 10) {
      const tool = strong.get(node.pid);
      if (tool) {
        const key = tool + ':spawn:' + p.pid;
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ pid: p.pid, exe: p.exe || '', tool, via: 'spawned', tier: 'spawned', score: 2 });
        }
        break;
      }
      const parent = byPid.get(node.ppid);
      if (!parent || parent.pid === node.pid) break;
      node = parent;
      hops += 1;
    }
  }
  return out;
}

module.exports = { DEFAULT_TOOLS, normalizeTools, normalizeIgnore, detectSessions, ancestorEvidence, scoreFor };
