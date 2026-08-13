/* Auren — agent-track tests.
 *
 * Pure tests for the dwell/confidence tracker (src/core/agenttrack.js) with an
 * injected clock — no timers, no real processes.
 *
 * Run: npm run test:autoprotect (also part of npm run test:all)
 */
'use strict';
const assert = require('assert');
const { createTracker } = require('../src/core/agenttrack');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try { fn(); passed += 1; console.log('  ok   ' + name); }
  catch (err) { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (err && err.stack || err)); }
}

// A fake clock the tracker can advance.
function fakeClock() {
  let t = 0;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

const E = (pid, tool, score) => ({ pid, exe: '/bin/' + tool, tool, score });

console.log('agent track tests');

test('a fresh strong match is not confirmed until it dwells', () => {
  const clock = fakeClock();
  const tr = createTracker({ minDwellMs: 2000, now: clock.now });
  assert.strictEqual(tr.update([E(1, 'claude-code', 3)]).length, 0, 'first sighting not confirmed');
  clock.advance(1000);
  assert.strictEqual(tr.update([E(1, 'claude-code', 3)]).length, 0, 'still under dwell');
  clock.advance(1000);
  const out = tr.update([E(1, 'claude-code', 3)]);
  assert.strictEqual(out.length, 1, 'confirmed after >= 2s');
  assert.strictEqual(out[0].tool, 'claude-code');
  assert.strictEqual(out[0].score, 3);
});

test('a transient weak match never confirms', () => {
  const clock = fakeClock();
  const tr = createTracker({ minDwellMs: 2000, staleMs: 1000, now: clock.now });
  assert.strictEqual(tr.update([E(2, 'codex-cli', 1)]).length, 0, 'first sighting not confirmed');
  clock.advance(3000);                    // process gone before dwell
  tr.update([]);                          // absent — pruned after staleMs
  assert.strictEqual(tr.size(), 0);
});

test('forceStrong confirms a previously-seen strong signal immediately', () => {
  const clock = fakeClock();
  const tr = createTracker({ minDwellMs: 2000, now: clock.now });
  tr.update([E(3, 'cursor', 3)]);         // first sighting (no force)
  clock.advance(400);
  const out = tr.update([E(3, 'cursor', 3)], 2000, true); // fast re-scan
  assert.strictEqual(out.length, 1, 'strong signal confirmed on the follow-up scan');
});

test('forceStrong does not fast-confirm a weak word match', () => {
  const clock = fakeClock();
  const tr = createTracker({ minDwellMs: 2000, now: clock.now });
  tr.update([E(4, 'aider', 1)]);
  clock.advance(400);
  const out = tr.update([E(4, 'aider', 1)], 2000, true);
  assert.strictEqual(out.length, 0, 'weak matches still need the full dwell');
});

test('a gap longer than the dwell restarts the dwell', () => {
  const clock = fakeClock();
  const tr = createTracker({ minDwellMs: 2000, now: clock.now });
  tr.update([E(5, 'goose', 3)]);
  clock.advance(3000);                    // absent > dwell
  tr.update([]);                          // gone
  assert.strictEqual(tr.update([E(5, 'goose', 3)]).length, 0, 'reappearance starts a fresh dwell');
});

test('staleness: a process that stops matching is pruned', () => {
  const clock = fakeClock();
  const tr = createTracker({ minDwellMs: 100, staleMs: 1000, now: clock.now });
  tr.update([E(6, 'opencode', 3)]);
  clock.advance(5000);
  tr.update([]);
  assert.strictEqual(tr.size(), 0, 'pruned after staleMs');
});

test('score tracks the strongest current evidence for a tool+pid', () => {
  const clock = fakeClock();
  const tr = createTracker({ minDwellMs: 0, now: clock.now });
  // Same pid/tool seen via two sources in one scan: weak argv + strong ancestor.
  const out = tr.update([
    E(7, 'claude-code', 1),
    { pid: 7, exe: '/bin/x', tool: 'claude-code', score: 2 }
  ]);
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].score, 2, 'best score wins per (tool, pid)');
});

test('confirmed sessions carry pid/exe/tool for the decision layer', () => {
  const clock = fakeClock();
  const tr = createTracker({ minDwellMs: 0, now: clock.now });
  const out = tr.update([E(8, 'playwright', 3)]);
  assert.deepStrictEqual(out, [{ pid: 8, exe: '/bin/playwright', tool: 'playwright', score: 3 }]);
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
