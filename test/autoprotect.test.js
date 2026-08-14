/* Auren — auto-protect tests.
 *
 * Pure tests for agent detection (src/core/agentdetect.js) and the auto-
 * protect decision layer (src/core/autoprotect.js). No privileges, no real
 * processes — detection runs against fabricated { pid, exe, tokens } lists.
 *
 * Run: npm run test:autoprotect (also part of npm run test:all)
 */
'use strict';
const assert = require('assert');
const agentdetect = require('../src/core/agentdetect');
const autoprotect = require('../src/core/autoprotect');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try { fn(); passed += 1; console.log('  ok   ' + name); }
  catch (err) { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (err && err.stack || err)); }
}

const P = (pid, exe, tokens) => ({ pid, exe, tokens });

/* -------------------------- agent detection -------------------------- */

test('detectSessions flags a headless browser by argv flag', () => {
  const sessions = agentdetect.detectSessions(
    [P(101, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', ['--headless', '--disable-gpu'])],
    agentdetect.normalizeTools(undefined)
  );
  assert.ok(sessions.some((s) => s.tool === 'headless-browser'));
});

test('detectSessions flags remote-debugging (CDP) browsers', () => {
  const sessions = agentdetect.detectSessions(
    [P(102, '/usr/bin/chromium', ['--remote-debugging-port=9222'])],
    agentdetect.normalizeTools(undefined)
  );
  assert.ok(sessions.some((s) => s.tool === 'remote-debugging'));
});

test('detectSessions flags playwright/puppeteer/selenium driver processes', () => {
  const tools = agentdetect.normalizeTools(undefined);
  for (const [exe, tokens, tool] of [
    ['/usr/local/bin/node', ['/path/playwright', 'test'], 'playwright'],
    ['/usr/local/bin/node', ['puppeteer'], 'puppeteer'],
    ['/usr/local/bin/chromedriver', [], 'browser-driver'],
    ['node', ['selenium-webdriver'], 'selenium']
  ]) {
    const sessions = agentdetect.detectSessions([P(200, exe, tokens)], tools);
    assert.ok(sessions.some((s) => s.tool === tool), tool + ' must be detected from ' + exe + ' ' + tokens.join(' '));
  }
});

test('detectSessions flags coding/terminal CLI agents by executable basename', () => {
  const tools = agentdetect.normalizeTools(undefined);
  for (const [exe, tokens, tool] of [
    ['/usr/local/bin/claude', [], 'claude-code'],
    ['/usr/local/bin/codex', [], 'codex-cli'],
    ['/usr/local/bin/goose', [], 'goose'],
    ['/opt/homebrew/bin/opencode', [], 'opencode'],
    ['/Applications/Cursor.app/Contents/MacOS/Cursor', [], 'cursor'],
    ['/usr/bin/node', ['aider'], 'aider'] // invoked via a script launcher
  ]) {
    const sessions = agentdetect.detectSessions([P(300, exe, tokens)], tools);
    assert.ok(sessions.some((s) => s.tool === tool), tool + ' must be detected from ' + exe);
  }
});

test('detectSessions does NOT flag a plain browser or unrelated processes', () => {
  const tools = agentdetect.normalizeTools(undefined);
  const sessions = agentdetect.detectSessions([
    P(1, 'Google Chrome', ['--no-sandbox']),
    P(2, '/usr/bin/grep', ['-r', 'TODO', 'src']),
    P(3, '/usr/bin/ps', []),
    P(4, '/bin/ls', ['-la'])
  ], tools);
  assert.strictEqual(sessions.length, 0);
});

test('detectSessions does not match a path that merely contains a tool name', () => {
  // /Users/me/projects/cursor/app.js is ONE argv token — its basename is
  // app.js, so "cursor" inside the path must never match.
  const sessions = agentdetect.detectSessions(
    [P(500, '/usr/bin/node', ['/Users/me/projects/cursor/app.js'])],
    agentdetect.normalizeTools(undefined)
  );
  assert.strictEqual(sessions.length, 0);
});

test('detectSessions returns one entry per (tool, pid) with exe + tool', () => {
  const sessions = agentdetect.detectSessions(
    [P(600, '/usr/local/bin/claude', ['--headless'])],
    agentdetect.normalizeTools(undefined)
  );
  assert.ok(sessions.every((s) => s.pid === 600 && s.exe && s.tool));
});

test('normalizeTools merges user tools and drops invalid entries', () => {
  const tools = agentdetect.normalizeTools([
    { name: 'my-agent', pattern: '\\bmyagent\\b' },
    { name: 'bad-regex', re: '(' },
    { name: '' },
    'not-an-object'
  ]);
  assert.ok(tools.some((t) => t.name === 'my-agent'));
  assert.ok(!tools.some((t) => t.name === 'bad-regex'));
  assert.ok(tools.some((t) => t.name === 'playwright'), 'defaults always present');
});

test('normalizeTools: a user tool actually matches', () => {
  const tools = agentdetect.normalizeTools([{ name: 'my-agent', re: '\\bmyagent\\b' }]);
  const sessions = agentdetect.detectSessions([P(700, '/usr/bin/node', ['myagent'])], tools);
  assert.ok(sessions.some((s) => s.tool === 'my-agent'));
});

/* --------------------------- auto-protect ---------------------------- */

test('normalizeAutoProtect defaults to enabled + auto-engage', () => {
  const d = autoprotect.normalizeAutoProtect(undefined);
  assert.strictEqual(d.enabled, true);
  assert.strictEqual(d.mode, 'on');
});

test('normalizeAutoProtect honors explicit settings', () => {
  const p = autoprotect.normalizeAutoProtect({ enabled: false });
  assert.strictEqual(p.enabled, false);
  const q = autoprotect.normalizeAutoProtect({ mode: 'prompt' });
  assert.strictEqual(q.mode, 'prompt');
});

test('shouldEngage: engages only when off, enabled, and a session is live', () => {
  const sessions = [{ pid: 1, exe: '/bin/claude', tool: 'claude-code' }];
  const base = { mode: 'off', failClosed: false, sessions, autoProtect: undefined };
  assert.strictEqual(autoprotect.shouldEngage(base), true);
});

test('shouldEngage: never engages while protection is on or failed closed', () => {
  const sessions = [{ pid: 1, exe: '/bin/claude', tool: 'claude-code' }];
  assert.strictEqual(autoprotect.shouldEngage({ mode: 'on', failClosed: false, sessions, autoProtect: undefined }), false);
  assert.strictEqual(autoprotect.shouldEngage({ mode: 'off', failClosed: true, sessions, autoProtect: undefined }), false);
});

test('shouldEngage: disabled or no sessions means no engage', () => {
  assert.strictEqual(autoprotect.shouldEngage({ mode: 'off', failClosed: false, sessions: [], autoProtect: undefined }), false);
  assert.strictEqual(autoprotect.shouldEngage({ mode: 'off', failClosed: false, sessions: [{ pid: 1, tool: 'x' }], autoProtect: { enabled: false } }), false);
});

test('shouldEngage: prompt mode is deferred to the caller (no auto engage)', () => {
  const sessions = [{ pid: 1, exe: '/bin/claude', tool: 'claude-code' }];
  assert.strictEqual(autoprotect.shouldEngage({ mode: 'off', failClosed: false, sessions, autoProtect: { mode: 'prompt' } }), false);
});

test('uniqueToolNames deduplicates across sessions', () => {
  const names = autoprotect.uniqueToolNames([
    { tool: 'claude-code' }, { tool: 'headless-browser' }, { tool: 'claude-code' }
  ]);
  assert.deepStrictEqual(names, ['claude-code', 'headless-browser']);
});

/* ------------------ scoring, tiers, ancestry, ignore ------------------ */

test('detectSessions scores basename matches 3 and argv words 1', () => {
  const tools = agentdetect.normalizeTools(undefined);
  const exe = agentdetect.detectSessions([P(101, '/usr/local/bin/codex', ['--json'])], tools);
  assert.strictEqual(exe[0].score, 3);
  assert.strictEqual(exe[0].via, 'exe');
  const word = agentdetect.detectSessions([P(102, '/usr/bin/grep', ['-r', 'codex', 'src'])], tools);
  assert.strictEqual(word[0].tool, 'codex-cli');
  assert.strictEqual(word[0].score, 1);
  assert.strictEqual(word[0].via, 'argv');
});

test('detectSessions scores wrapper invocations 2', () => {
  const tools = agentdetect.normalizeTools(undefined);
  const sessions = agentdetect.detectSessions(
    [P(3, '/usr/local/bin/npx', ['@anthropic-ai/claude-code', '--version'])],
    tools
  );
  const w = sessions.find((s) => s.tool === 'claude-code-wrapper');
  assert.ok(w, 'wrapper token detected');
  assert.strictEqual(w.score, 2);
});

test('detectSessions applies the ignore list before scoring', () => {
  const tools = agentdetect.normalizeTools(undefined);
  const ignore = [{ tool: 'codex-cli' }];
  const all = agentdetect.detectSessions([P(4, '/usr/local/bin/codex', [])], tools, { ignore });
  assert.strictEqual(all.length, 0, 'tool-level ignore silences the match');
  const exeScoped = agentdetect.detectSessions([P(5, '/usr/local/bin/codex', [])], tools, {
    ignore: [{ tool: 'codex-cli', exe: '/other/path/codex' }]
  });
  assert.strictEqual(exeScoped.length, 1, 'exe-scoped ignore only silences that executable');
});

test('ancestorEvidence flags processes spawned by a strong agent', () => {
  const tools = agentdetect.normalizeTools(undefined);
  const list = [
    { pid: 10, ppid: 1, exe: '/usr/local/bin/claude', tokens: [] },
    { pid: 11, ppid: 10, exe: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', tokens: ['--no-sandbox'] },
    { pid: 12, ppid: 11, exe: '/usr/bin/python3', tokens: ['/tmp/child.py'] }
  ];
  const base = agentdetect.detectSessions(list, tools);
  const extra = agentdetect.ancestorEvidence(list, base);
  const spawned = extra.filter((s) => s.via === 'spawned');
  assert.strictEqual(spawned.length, 2, 'chrome and its python child count as agent-spawned');
  assert.ok(spawned.every((s) => s.score === 2 && s.tool === 'claude-code'));
});

test('ancestorEvidence returns nothing without a strong ancestor', () => {
  const list = [
    { pid: 20, ppid: 1, exe: '/usr/bin/node', tokens: ['aider'] },
    { pid: 21, ppid: 20, exe: '/usr/bin/ssh', tokens: ['-o', 'x'] }
  ];
  const base = agentdetect.detectSessions(list, agentdetect.normalizeTools(undefined));
  assert.strictEqual(agentdetect.ancestorEvidence(list, base).length, 0, 'weak word ancestor spawns nothing');
});

/* ------------------- confidence + snooze decisions -------------------- */

test('shouldEngage needs confidence >= minConfidence', () => {
  const base = { mode: 'off', failClosed: false, autoProtect: undefined, snoozedUntil: {}, now: 1000 };
  assert.strictEqual(autoprotect.shouldEngage(Object.assign({}, base, { sessions: [{ tool: 'aider', score: 1 }] })), false, 'one weak word (1) < 3');
  assert.strictEqual(autoprotect.shouldEngage(Object.assign({}, base, { sessions: [{ tool: 'aider', score: 1 }, { tool: 'goose', score: 1 }] })), false, 'two weak words (2) < 3');
  assert.strictEqual(autoprotect.shouldEngage(Object.assign({}, base, { sessions: [{ tool: 'codex-cli', score: 3 }] })), true, 'one real agent (3) engages');
  assert.strictEqual(autoprotect.shouldEngage(Object.assign({}, base, { sessions: [{ tool: 'claude-code-wrapper', score: 2 }, { tool: 'aider', score: 1 }] })), true, 'wrapper + word (3) engages');
});

test('shouldEngage honors a higher minConfidence', () => {
  const r = autoprotect.shouldEngage({
    mode: 'off', failClosed: false,
    autoProtect: { minConfidence: 5 },
    sessions: [{ tool: 'codex-cli', score: 3 }], snoozedUntil: {}, now: 1000
  });
  assert.strictEqual(r, false, 'score 3 < minConfidence 5');
});

test('shouldEngage: a snoozed tool alone does not engage', () => {
  const now = 1000;
  const r = autoprotect.shouldEngage({
    mode: 'off', failClosed: false, autoProtect: undefined,
    sessions: [{ tool: 'claude-code', score: 3 }],
    snoozedUntil: { 'claude-code': now + 60000 }, now
  });
  assert.strictEqual(r, false);
});

test('shouldEngage: a different non-snoozed tool still engages', () => {
  const now = 1000;
  const r = autoprotect.shouldEngage({
    mode: 'off', failClosed: false, autoProtect: undefined,
    sessions: [{ tool: 'claude-code', score: 3 }, { tool: 'opencode', score: 3 }],
    snoozedUntil: { 'claude-code': now + 60000 }, now
  });
  assert.strictEqual(r, true, 'opencode is not snoozed');
});

test('shouldEngage: an expired snooze re-allows the tool', () => {
  const now = 1000;
  const r = autoprotect.shouldEngage({
    mode: 'off', failClosed: false, autoProtect: undefined,
    sessions: [{ tool: 'claude-code', score: 3 }],
    snoozedUntil: { 'claude-code': now - 1 }, now
  });
  assert.strictEqual(r, true);
});

test('normalizeAutoProtect validates the new settings keys', () => {
  const d = autoprotect.normalizeAutoProtect(undefined);
  assert.strictEqual(d.minDwellMs, 2000);
  assert.strictEqual(d.minConfidence, 3);
  assert.strictEqual(d.snoozeMs, 30 * 60 * 1000);
  const clamped = autoprotect.normalizeAutoProtect({ minDwellMs: 1, minConfidence: 0, snoozeMs: -5 });
  assert.strictEqual(clamped.minDwellMs, 500, 'dwell clamped low');
  assert.strictEqual(clamped.minConfidence, 1, 'confidence clamped low');
  assert.strictEqual(clamped.snoozeMs, 0, 'snooze clamped low');
  const set = autoprotect.normalizeAutoProtect({ tools: [{ name: 'x' }], ignore: [{ tool: 'y' }] });
  assert.deepStrictEqual(set.tools, [{ name: 'x' }]);
  assert.deepStrictEqual(set.ignore, [{ tool: 'y' }]);
});

test('snoozeTools snoozes only the engaged tools from a fixed now', () => {
  const now = 5000;
  const next = autoprotect.snoozeTools(['codex-cli', 'cursor'], { snoozeMs: 60000 }, { 'opencode': 9999 }, now);
  assert.strictEqual(next['codex-cli'], now + 60000);
  assert.strictEqual(next['cursor'], now + 60000);
  assert.strictEqual(next['opencode'], 9999, 'existing snoozes are preserved');
});

test('snoozeTools returns the same map (identity) when there is nothing to snooze', () => {
  const existing = { 'claude-code': 123 };
  const out = autoprotect.snoozeTools([], { snoozeMs: 60000 }, existing, 5000);
  assert.strictEqual(out, existing, 'no-op returns the caller\'s map unchanged');
  const out2 = autoprotect.snoozeTools(null, { snoozeMs: 60000 }, existing, 5000);
  assert.strictEqual(out2, existing);
});

test('snoozeTools honors the default snoozeMs when autoProtect is empty', () => {
  const now = 1000;
  const next = autoprotect.snoozeTools(['codex-cli'], undefined, {}, now);
  assert.strictEqual(next['codex-cli'], now + 30 * 60 * 1000);
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
