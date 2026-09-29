/* Auren — AgentDetection subsystem index.
 *
 * Single entry point re-exporting every AgentDetection component so callers
 * (main process, tests) integrate with current process/policy/event
 * abstractions instead of duplicating infrastructure.
 */

'use strict';

const events = require('./events');
const { createProcessMonitor } = require('./process-monitor');
const signatures = require('./signatures');
const { createAutomationMonitor } = require('./automation-monitor');
const { createInputMonitor } = require('./input-monitor');
const { createBehaviorAnalyzer, DEFAULT_BEHAVIOR_CONFIG } = require('./behavior-analyzer');
const { createScoringEngine, levelForScore, DEFAULT_SCORING_CONFIG } = require('./scoring');
const { createDetectionEngine } = require('./detection-engine');

module.exports = {
  events,
  createProcessMonitor,
  signatures,
  createAutomationMonitor,
  createInputMonitor,
  createBehaviorAnalyzer,
  DEFAULT_BEHAVIOR_CONFIG,
  createScoringEngine,
  levelForScore,
  DEFAULT_SCORING_CONFIG,
  createDetectionEngine,
};
