/* Auren — preload.js
 *
 * Exposes a minimal, read-only-ish API to the renderer. The renderer never
 * touches the filesystem, Node APIs, or the privileged daemon directly.
 */

'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('auren', {
  getState: () => ipcRenderer.invoke('state:get'),
  setMode: (mode) => ipcRenderer.invoke('mode:set', mode),
  addDomain: (domain) => ipcRenderer.invoke('blocklist:add', domain),
  removeDomain: (domain) => ipcRenderer.invoke('blocklist:remove', domain),
  searchApps: (query) => ipcRenderer.invoke('appblock:search', query),
  addApp: (entry) => ipcRenderer.invoke('appblock:add', entry),
  removeApp: (id) => ipcRenderer.invoke('appblock:remove', id),
  isBlocked: (domain) => ipcRenderer.invoke('guardrail:is-blocked', domain),
  inspectAction: (payload) => ipcRenderer.invoke('agent:inspect-action', payload),
  inspectCommand: (payload) => ipcRenderer.invoke('agent:inspect-command', payload),
  finishOnboarding: () => ipcRenderer.invoke('onboarding:done'),
  setAutoProtect: (patch) => ipcRenderer.invoke('settings:set-auto-protect', patch),
  confirmAutoProtect: () => ipcRenderer.invoke('autoprotect:confirm'),
  ignoreAgentTool: (tool) => ipcRenderer.invoke('settings:ignore-agent-tool', tool),
  // — File System Guard & Virtual Isolation —
  pickWorkspace: () => ipcRenderer.invoke('fsguard:pick'),
  addWorkspace: (p) => ipcRenderer.invoke('fsguard:add', p),
  removeWorkspace: (id) => ipcRenderer.invoke('fsguard:remove', id),
  checkFsAccess: (payload) => ipcRenderer.invoke('fsguard:check', payload),
  getExclusions: () => ipcRenderer.invoke('fsguard:exclusions'),
  canonicalize: (p) => ipcRenderer.invoke('path:canonicalize', p),
  // — Sandbox Monitor —
  getSandbox: () => ipcRenderer.invoke('sandbox:get'),
  getSandboxEvents: (limit) => ipcRenderer.invoke('sandbox:events', limit),
  clearSandboxEvents: () => ipcRenderer.invoke('sandbox:clear'),
  // — Diagnostics & Recovery —
  getDiagnostics: () => ipcRenderer.invoke('diagnostics:get'),
  reinstallDaemon: () => ipcRenderer.invoke('daemon:reinstall'),
  clearRecovery: () => ipcRenderer.invoke('daemon:clear-recovery'),
  checkPorts: () => ipcRenderer.invoke('daemon:check-ports'),
  // — AgentDetection (local, deterministic) —
  getDetection: () => ipcRenderer.invoke('detection:get'),
  inspectAutomation: (payload) => ipcRenderer.invoke('agent:inspect-automation', payload),
  decideDetection: (payload) => ipcRenderer.invoke('detection:decide', payload),
  onDetectionApproval: (cb) => ipcRenderer.on('detection:approval', (_event, req) => cb(req)),
  onChange: (cb) => ipcRenderer.on('state', (_event, state) => cb(state)),
  onAutoProtectPrompt: (cb) => ipcRenderer.on('autoprotect:prompt', (_event, tools) => cb(tools))
});
