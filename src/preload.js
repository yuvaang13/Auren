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
  finishOnboarding: () => ipcRenderer.invoke('onboarding:done'),
  onChange: (cb) => ipcRenderer.on('state', (_event, state) => cb(state))
});
