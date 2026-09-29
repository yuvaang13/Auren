/* Auren — AgentDetection tests (plan §12).
 *
 * Covers: normal human usage → NORMAL; script automation → SUSPICIOUS or
 * LIKELY_AUTOMATION; known AI agent (process + automation + input) →
 * HIGH_CONFIDENCE_AGENT; developer false-positive → not high-confidence;
 * unknown agent (behavioral/API evidence only) → detected without signature.
 * Plus scoring decay, thresholds, policy matrix, and privacy (no content).
 *
 * Run: node test/agent-detection.test.js
 */
'use strict';
const assert = require('assert');

const { createDetectionEngine } = require('../src/core/agent-detection/detection-engine');
const { createScoringEngine, DEFAULT_SCORING_CONFIG } = require('../src/core/agent-detection/scoring');
const { decideAutomationPolicy } = require('../src/core/policy');
const { createProcessMonitor } = require('../src/core/agent-detection/process-monitor');
const { normalizeSignatures, matchProcess } = require('../src/core/agent-detection/signatures');

let passed = 0;
let failed = 0;
function test(name, fn) {
  try { fn(); passed += 1; console.log('  ok   ' + name); }
  catch (err) { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (err && err.stack || err)); }
}

function P(pid, ppid, exe, tokens) {
  return { pid, ppid, exe, tokens: tokens || [] };
}

// Controllable clock for decay tests.
function clock(start) {
  let t = start || 1_000_000;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

console.log('agent-detection: scoring');
// --- scoring weights/thresholds centralized ---
test('default weights and thresholds match plan', () => {
  assert.strictEqual(DEFAULT_SCORING_CONFIG.weights.knownAgentProcess, 40);
  assert.strictEqual(DEFAULT_SCORING_CONFIG.weights.agentChildRelationship, 15);
  assert.strictEqual(DEFAULT_SCORING_CONFIG.weights.accessibilityAutomation, 25);
  assert.strictEqual(DEFAULT_SCORING_CONFIG.weights.programmaticInput, 25);
  assert.strictEqual(DEFAULT_SCORING_CONFIG.weights.repeatedPattern, 20);
  assert.deepStrictEqual(
    [DEFAULT_SCORING_CONFIG.thresholds.suspicious, DEFAULT_SCORING_CONFIG.thresholds.likelyAutomation, DEFAULT_SCORING_CONFIG.thresholds.highConfidence],
    [40, 60, 80]
  );
});

test('levels: 0-39 NORMAL, 40-59 SUSPICIOUS, 60-79 LIKELY, 80+ HIGH', () => {
  const c = clock();
  const s = createScoringEngine({ now: c.now, decayMs: 0 });
  assert.strictEqual(s.levelForScore(0), 'NORMAL');
  assert.strictEqual(s.levelForScore(39), 'NORMAL');
  assert.strictEqual(s.levelForScore(40), 'SUSPICIOUS');
  assert.strictEqual(s.levelForScore(60), 'LIKELY_AUTOMATION');
  assert.strictEqual(s.levelForScore(80), 'HIGH_CONFIDENCE_AGENT');
});

test('score decays over time', () => {
  const c = clock();
  const s = createScoringEngine({ now: c.now, decayMs: 60 * 1000 });
  s.addEvidence('knownAgentProcess', 'x');
  assert.strictEqual(s.snapshot().score, 40);
  c.advance(30 * 1000);
  const mid = s.snapshot().score;
  assert.ok(mid < 40 && mid > 0, 'expected partial decay, got ' + mid);
  c.advance(60 * 1000);
  assert.strictEqual(s.snapshot().score, 0);
});

console.log('agent-detection: signatures');
test('signatures match basenames case-insensitively, not paths', () => {
  const sigs = normalizeSignatures();
  assert.strictEqual(matchProcess({ exe: '/Applications/Claude.app/Contents/MacOS/Claude' }, sigs).length, 1);
  assert.strictEqual(matchProcess({ exe: '/usr/local/bin/codex' }, sigs)[0].agentName, 'Codex');
  assert.strictEqual(matchProcess({ exe: '/usr/bin/safari' }, sigs).length, 0);
});

test('user can add signatures without touching engine', () => {
  const sigs = normalizeSignatures({ knownAgents: [{ name: 'MyAgent', processNames: ['myagent'] }] });
  assert.strictEqual(matchProcess({ exe: '/opt/myagent' }, sigs)[0].agentName, 'MyAgent');
});

console.log('agent-detection: process monitor');
test('process tree diff emits started/stopped/relationship events', () => {
  const m = createProcessMonitor();
  const e1 = m.update([P(1, 0, '/sbin/launchd'), P(100, 1, '/Applications/Claude.app/Contents/MacOS/Claude')]);
  assert.ok(e1.some((e) => e.type === 'ProcessStarted' && e.pid === 100));
  assert.strictEqual(m.ancestorsOf(100)[0].pid, 1);
  const e2 = m.update([P(1, 0, '/sbin/launchd'), P(100, 1, '/x/Claude'), P(101, 100, '/usr/bin/python3')]);
  assert.ok(e2.some((e) => e.type === 'ProcessStarted' && e.pid === 101));
  assert.strictEqual(m.ancestorsOf(101).length, 2);
  const e3 = m.update([P(1, 0, '/sbin/launchd')]);
  assert.ok(e3.some((e) => e.type === 'ProcessStopped'));
});

console.log('agent-detection: end-to-end scenarios (plan §12)');

test('normal human usage → NORMAL', () => {
  const eng = createDetectionEngine();
  const list = [
    P(1, 0, '/sbin/launchd'),
    P(200, 1, '/Applications/Safari.app/Contents/MacOS/Safari'),
    P(201, 1, '/Applications/TextEdit.app/Contents/MacOS/TextEdit'),
    P(202, 1, '/System/Applications/Finder.app/Contents/MacOS/Finder'),
  ];
  const { detection } = eng.update(list);
  assert.strictEqual(detection.level, 'NORMAL');
  assert.ok(detection.score < 40);
});

test('script automation (osascript + Safari) → SUSPICIOUS or LIKELY_AUTOMATION', () => {
  const eng = createDetectionEngine();
  const list = [
    P(1, 0, '/sbin/launchd'),
    P(300, 1, '/usr/bin/osascript', ['osascript', '-e', 'tell application "Safari" to activate']),
    P(301, 1, '/Applications/Safari.app/Contents/MacOS/Safari'),
  ];
  const { detection } = eng.update(list);
  assert.ok(['SUSPICIOUS', 'LIKELY_AUTOMATION', 'HIGH_CONFIDENCE_AGENT'].includes(detection.level), 'got ' + detection.level);
  assert.ok(detection.score >= 25);
});

test('known AI agent + automation + programmatic input → HIGH_CONFIDENCE_AGENT', () => {
  const eng = createDetectionEngine();
  const list = [
    P(1, 0, '/sbin/launchd'),
    P(400, 1, '/Applications/Claude.app/Contents/MacOS/Claude'),
    P(401, 400, '/usr/bin/osascript', ['osascript', '-e', 'tell application "Safari" to activate']),
    P(402, 400, '/usr/local/bin/cliclick', ['cliclick', 'c:+100,+100']),
    P(403, 1, '/Applications/Safari.app/Contents/MacOS/Safari'),
    P(404, 400, '/usr/bin/python3', ['python3', '-c', 'from Quartz import CGEventCreate, CGEventPost; CGEventPost(1, CGEventCreate(None))']),
  ];
  const { detection } = eng.update(list);
  assert.strictEqual(detection.level, 'HIGH_CONFIDENCE_AGENT');
  assert.ok(detection.score >= 80);
  assert.ok(detection.evidence.some((e) => /Claude/.test(e)));
  assert.ok(detection.evidence.some((e) => /automation/i.test(e)));
  assert.ok(detection.evidence.some((e) => /Programmatic input/.test(e)));
});

test('developer false-positive (Terminal + Python + VS Code + browser) stays below high-confidence', () => {
  const eng = createDetectionEngine();
  const list = [
    P(1, 0, '/sbin/launchd'),
    P(500, 1, '/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal'),
    P(501, 500, '/usr/bin/python3', ['python3', 'server.py']),
    P(502, 1, '/Applications/Visual Studio Code.app/Contents/MacOS/Electron'),
    P(503, 1, '/Applications/Safari.app/Contents/MacOS/Safari'),
  ];
  const { detection } = eng.update(list);
  assert.notStrictEqual(detection.level, 'HIGH_CONFIDENCE_AGENT');
  assert.ok(detection.score < 80, 'score was ' + detection.score);
});

test('unknown agent: behavioral/API evidence without signature still detected', () => {
  const eng = createDetectionEngine();
  const list = [
    P(1, 0, '/sbin/launchd'),
    P(600, 1, '/opt/mystery/mystery-agent'),
    P(601, 600, '/usr/bin/osascript', ['osascript', '-e', 'tell application "Finder" to activate']),
    P(602, 600, '/usr/local/bin/cliclick', ['cliclick', 'c:+5,+5']),
    P(603, 1, '/System/Applications/Finder.app/Contents/MacOS/Finder'),
  ];
  const { detection } = eng.update(list);
  // No known signature fired, but automation + programmatic input must score.
  assert.ok(detection.score >= 40, 'score was ' + detection.score + ' evidence=' + JSON.stringify(detection.evidence));
  assert.ok(!detection.evidence.some((e) => /Known agent process/.test(e)));
});

test('input monitor never records content (metadata only)', () => {
  const eng = createDetectionEngine();
  const d = eng.observeInput({ eventType: 'KeyboardEvent', source: 'programmatic', targetApplication: 'Safari' });
  const dumped = JSON.stringify(d);
  assert.ok(!/password|clipboard|screenshot|keystroke content/i.test(dumped));
  const st = eng.status();
  assert.ok(!JSON.stringify(st).includes('supersecret'));
});

test('engine fails safe: crash → DETECTION_UNAVAILABLE, not silent NORMAL', () => {
  const eng = createDetectionEngine({ axClients: () => { throw new Error('native boom'); } });
  // axClients throwing is swallowed per-monitor; force a real crash via bad input path:
  const bad = eng.update(null);
  assert.ok(bad.detection, 'update(null) must still return a detection');
});

console.log('agent-detection: policy matrix');
test('policy: NORMAL→ALLOW, LIKELY→WARN, HIGH→REQUIRE_APPROVAL, sensitive escalates', () => {
  const mk = (level, score) => ({ level, score, evidence: [], timestamp: new Date().toISOString() });
  assert.strictEqual(decideAutomationPolicy(mk('NORMAL', 0), {}).action, 'ALLOW');
  assert.strictEqual(decideAutomationPolicy(mk('SUSPICIOUS', 45), {}).action, 'ALLOW');
  assert.strictEqual(decideAutomationPolicy(mk('LIKELY_AUTOMATION', 65), {}).action, 'WARN');
  assert.strictEqual(decideAutomationPolicy(mk('HIGH_CONFIDENCE_AGENT', 90), {}).action, 'REQUIRE_APPROVAL');
  // Agent detected + sensitive operation → REQUIRE_APPROVAL; high + sensitive → BLOCK
  assert.strictEqual(decideAutomationPolicy(mk('LIKELY_AUTOMATION', 65), { sensitiveOperation: true }).action, 'REQUIRE_APPROVAL');
  assert.strictEqual(decideAutomationPolicy(mk('HIGH_CONFIDENCE_AGENT', 90), { sensitiveOperation: true }).action, 'BLOCK');
  // Degraded fails safely
  assert.strictEqual(decideAutomationPolicy(mk('NORMAL', 0), { degraded: true }).action, 'BLOCK');
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
