/* Auren — AgentDetection deterministic scoring engine.
 *
 * Phase 7 of the plan. Transparent rule-based scoring. Initial defaults:
 *   Known agent process                  +40
 *   Agent child/subprocess relationship  +15
 *   Accessibility automation             +25
 *   Programmatic input                   +25
 *   Repeated automation pattern          +20
 *
 * Levels:
 *   0–39    NORMAL
 *   40–59   SUSPICIOUS
 *   60–79   LIKELY_AUTOMATION
 *   80+     HIGH_CONFIDENCE_AGENT
 *
 * The score DECAYS over time (linear decay to zero across decayMs with no
 * new evidence). The score is NOT a probability: 80 means "enough predefined
 * evidence accumulated to cross the configured threshold", nothing more.
 * All weights/thresholds centralized in DEFAULT_SCORING_CONFIG.
 */

'use strict';

const DEFAULT_SCORING_CONFIG = Object.freeze({
  weights: Object.freeze({
    knownAgentProcess: 40,
    agentChildRelationship: 15,
    accessibilityAutomation: 25,
    programmaticInput: 25,
    repeatedPattern: 20,
  }),
  thresholds: Object.freeze({
    suspicious: 40,
    likelyAutomation: 60,
    highConfidence: 80,
  }),
  decayMs: 5 * 60 * 1000, // full decay to 0 after 5 min without evidence
  maxScore: 100,
});

function levelForScore(score, thresholds) {
  const t = thresholds || DEFAULT_SCORING_CONFIG.thresholds;
  if (score >= t.highConfidence) return 'HIGH_CONFIDENCE_AGENT';
  if (score >= t.likelyAutomation) return 'LIKELY_AUTOMATION';
  if (score >= t.suspicious) return 'SUSPICIOUS';
  return 'NORMAL';
}

function createScoringEngine(opts) {
  const cfg = (opts && typeof opts === 'object') ? opts : {};
  const weights = Object.assign({}, DEFAULT_SCORING_CONFIG.weights, cfg.weights);
  const thresholds = Object.assign({}, DEFAULT_SCORING_CONFIG.thresholds, cfg.thresholds);
  const decayMs = Number.isFinite(cfg.decayMs) ? cfg.decayMs : DEFAULT_SCORING_CONFIG.decayMs;
  const maxScore = Number.isFinite(cfg.maxScore) ? cfg.maxScore : DEFAULT_SCORING_CONFIG.maxScore;
  const nowFn = typeof cfg.now === 'function' ? cfg.now : () => Date.now();

  let score = 0;
  let lastUpdate = nowFn();
  const contributions = []; // { key, points, at, label } ephemeral

  function applyDecay() {
    const t = nowFn();
    const elapsed = t - lastUpdate;
    if (elapsed <= 0) return;
    if (decayMs <= 0) { lastUpdate = t; return; }
    // Proportional linear decay: the score fades toward zero across decayMs
    // without new evidence (40 → 20 after half the window, 0 at the end).
    const factor = Math.max(0, 1 - elapsed / decayMs);
    score = score * factor;
    if (score < 0.5) score = 0;
    lastUpdate = t;
  }

  // Add one evidence item. key must be a weight name; unknown keys score 0.
  // Returns { score, level }.
  function addEvidence(key, label) {
    applyDecay();
    const points = Number(weights[key]) || 0;
    if (points > 0) {
      score = Math.min(maxScore, score + points);
      contributions.push({ key, points, at: nowFn(), label: label || key });
      while (contributions.length > 200) contributions.shift();
    }
    lastUpdate = nowFn();
    return snapshot();
  }

  function snapshot() {
    applyDecay();
    return { score: Math.round(score), level: levelForScore(Math.round(score), thresholds) };
  }

  function evidenceLabels() {
    return contributions.map((c) => c.label);
  }

  function reset() {
    score = 0;
    lastUpdate = nowFn();
    contributions.length = 0;
  }

  return { addEvidence, snapshot, evidenceLabels, levelForScore: (s) => levelForScore(s, thresholds), reset };
}

module.exports = { createScoringEngine, levelForScore, DEFAULT_SCORING_CONFIG };
