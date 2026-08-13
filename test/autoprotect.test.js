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

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
