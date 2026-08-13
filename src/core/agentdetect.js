/* Auren — agentdetect.js
 *
 * Heuristic detection of "an AI-agent session is running on this machine",
 * used by auto-protect (src/core/autoprotect.js). This is intentionally NOT
 * an AI classifier: it matches process descriptors ({ pid, exe, tokens }, the
 * same shape src/platform/procs-* produces for app blocking) against a list of
 * known agent-tool signatures. It is honest about what it is — a curated,
 * user-extendable signature list — and it can only ever RAISE protection; it
 * never turns it off.
 *
 * Signatures match against the executable basename and every argv token of a
 * process (both raw and lowercased), so `node run-claude.js`, `/usr/local/bin/
 * codex`, or `chromium --headless` are all recognizable without substring
 * false positives (matching a full token, never a partial path).
 *
 * Users can extend the default list via settings.json:
 *   { "autoProtect": { "enabled": true, "mode": "on",
 *                      "tools": [{ "name": "my-agent", "re": "\\bmyagent\\b" }] } }
 */

'use strict';

// Known agent tooling. Each entry matches the executable basename or any argv
// token (raw or lowercased) of a running process. Defaults are deliberately
// conservative — genuine agent software only — so normal apps don't trip it;
// extend via autoProtect.tools in settings.json.
const DEFAULT_TOOLS = [
  // Browser automation — the classic "an agent is driving a browser" signal.
  { name: 'headless-browser', re: /--headless/ },
  { name: 'remote-debugging', re: /--remote-debugging-port=/ },
  { name: 'browser-driver', re: /\b(?:chromedriver|geckodriver|msedgedriver|operadriver|phantomjs)\b/i },
  { name: 'playwright', re: /\bplaywright\b/i },
  { name: 'puppeteer', re: /\bpuppeteer\b/i },
  { name: 'selenium', re: /\bselenium\b/i },
  // Coding / terminal CLI agents.
  { name: 'claude-code', re: /\bclaude(?:[\s-]?code)?\b/i },
  { name: 'codex-cli', re: /\bcodex\b/i },
  { name: 'goose', re: /\bgoose\b/i },
  { name: 'opencode', re: /\bopencode\b/i },
  { name: 'gemini-cli', re: /\bgemini(?:-cli)?\b/i },
  { name: 'aider', re: /\baider\b/i },
  { name: 'openhands', re: /\bopenhands\b/i },
  // Agent-hosted IDEs / agent desktops.
  { name: 'cursor', re: /\bcursor\b/i },
  { name: 'windsurf', re: /\bwindsurf\b/i }
];

// Last path segment regardless of the running platform's separator, so a
// Windows-style path seen on macOS (or vice versa) still resolves correctly.
function lastSegment(s) {
  return String(s || '').split(/[\\/]/).pop();
}

// Candidate strings to match a tool signature against: the executable and every
// argv token. Path-like candidates (containing a / or \ separator) are reduced
// to their last segment first, so a *path* like /Users/me/projects/cursor/app.js
// never matches "cursor" — only the basename app.js does. Bare words and flags
// (--headless, playwright, aider) are matched in full.
function candidatesFor(p) {
  const out = [];
  const push = (s) => {
    const t = String(s || '').trim();
    if (!t) return;
    out.push(t);
    out.push(t.toLowerCase());
  };
  const reduce = (s) => (/[\\/]/.test(s) ? lastSegment(s) : s);
  if (p.exe) push(reduce(p.exe));
  for (const t of (Array.isArray(p.tokens) ? p.tokens : [])) { push(reduce(t)); }
  return out;
}

// Merge the built-in signatures with any user overrides. A user entry must
// carry { name, re } (a RegExp) or { name, pattern } (a RegExp source string);
// invalid entries are dropped, never fatal.
function normalizeTools(raw) {
  const out = DEFAULT_TOOLS.map((t) => ({ name: t.name, re: t.re }));
  if (Array.isArray(raw)) {
    for (const t of raw) {
      if (!t || typeof t !== 'object') continue;
      const name = String(t.name || '').trim();
      const source = t.re != null ? String(t.re) : (t.pattern != null ? String(t.pattern) : '');
      if (!name || !source) continue;
      try { out.push({ name, re: new RegExp(source) }); } catch { /* skip invalid regex */ }
    }
  }
  return out;
}

// Which running processes match a known agent-tool signature?
//   processList: [{ pid, exe, tokens }, ...] (from src/platform/procs-*)
//   tools:       output of normalizeTools()
// Returns [{ pid, exe, tool }, ...] — at most one entry per (tool, pid).
function detectSessions(processList, tools) {
  const list = Array.isArray(processList) ? processList : [];
  const out = [];
  const seen = new Set();
  for (const p of list) {
    if (!p || !p.pid || p.pid <= 1) continue;
    const candidates = candidatesFor(p);
    for (const tool of tools) {
      if (candidates.some((c) => tool.re.test(c))) {
        const key = tool.name + ':' + p.pid;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ pid: p.pid, exe: p.exe || '', tool: tool.name });
      }
    }
  }
  return out;
}

module.exports = { DEFAULT_TOOLS, normalizeTools, detectSessions };
