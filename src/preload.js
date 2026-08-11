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
  onChange: (cb) => ipcRenderer.on('state', (_event, state) => cb(state))
});
