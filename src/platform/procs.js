/* Auren — procs.js
 *
 * Platform seam for enumerating running processes and killing a pid. macOS
 * uses `ps -axo pid=,command=` and `/bin/kill`; Windows uses PowerShell's
 * CIM (ExecutablePath + CommandLine, so app-path matching works like macOS)
 * and taskkill. The daemon feeds the descriptors straight into the shared
 * findBlockedProcesses matcher in core/apps.js.
 */

'use strict';
module.exports = process.platform === 'win32'
  ? require('./procs-win')
  : require('./procs-mac');
