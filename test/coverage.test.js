/* Auren — coverage smoke test.
 *
 * Closes the P1 gap: every agent-detection submodule must be importable
 * through the index entry point (not just engine/scoring/process-monitor),
 * and the renderer/main/preload wiring must expose the IPC surface the UI
 * actually calls. Static checks only — no Electron runtime needed.
 *
 * Run: node test/coverage.test.js
 */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

let passed = 0;
let failed = 0;
function test(name, fn) {
  try { fn(); passed += 1; console.log('  ok   ' + name); }
  catch (err) { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (err && err.stack || err)); }
}

console.log('coverage: agent-detection index re-exports every submodule');
test('index exposes all submodule factories', () => {
  const idx = require('../src/core/agent-detection/index');
  for (const key of [
    'events', 'createProcessMonitor', 'signatures',
    'createAutomationMonitor', 'createInputMonitor',
    'createBehaviorAnalyzer', 'createScoringEngine',
    'createDetectionEngine', 'levelForScore',
  ]) {
    assert.ok(idx[key], 'index missing export: ' + key);
  }
});

test('automation-monitor factory builds', () => {
  const { createAutomationMonitor } = require('../src/core/agent-detection/index');
  const m = createAutomationMonitor({ now: () => 0 });
  assert.ok(m && typeof m === 'object');
});

test('input-monitor factory builds', () => {
  const { createInputMonitor } = require('../src/core/agent-detection/index');
  const m = createInputMonitor({ now: () => 0 });
  assert.ok(m && typeof m === 'object');
});

test('behavior-analyzer observe/analyze round-trip', () => {
  const { createBehaviorAnalyzer } = require('../src/core/agent-detection/index');
  const ba = createBehaviorAnalyzer({ now: () => 1000 });
  assert.strictEqual(typeof ba.observe, 'function');
  assert.strictEqual(typeof ba.analyze, 'function');
  ba.observe({ type: 'automation' });
  const res = ba.analyze();
  assert.ok(res && typeof res === 'object');
});

test('events module exposes validators', () => {
  const { events } = require('../src/core/agent-detection/index');
  assert.ok(events.EVENT_TYPES);
  assert.strictEqual(typeof events.isValidEvent, 'function');
});

console.log('coverage: main/preload/renderer wiring');
test('preload exposes the full IPC surface', () => {
  const src = read('src/preload.js');
  for (const ch of [
    'state:get', 'mode:set', 'blocklist:add', 'blocklist:remove',
    'guardrail:is-blocked', 'agent:inspect-action', 'agent:inspect-command',
    'fsguard:check', 'detection:get', 'agent:inspect-automation',
  ]) {
    assert.ok(src.includes(ch), 'preload missing channel: ' + ch);
  }
});

test('renderer consumes window.auren and required entry files exist', () => {
  const app = read('src/renderer/app.js');
  assert.ok(app.includes('window.auren'));
  for (const f of ['src/main.js', 'src/preload.js', 'src/renderer/app.js', 'src/renderer/index.html']) {
    assert.ok(fs.existsSync(path.join(ROOT, f)), 'missing: ' + f);
  }
});

test('main process wires gates + bridge (single decision implementation)', () => {
  const main = read('src/main.js');
  assert.ok(main.includes('agent:inspect-action'));
  assert.ok(main.includes('agent:inspect-command'));
  assert.ok(main.includes('guardrail:is-blocked'));
});

console.log(`\ncoverage: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
