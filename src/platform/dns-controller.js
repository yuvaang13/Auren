/* Auren — dns-controller.js
 *
 * Platform seam for orchestrating the privileged DNS daemon from the desktop
 * app. macOS installs a root LaunchDaemon (dns-controller-mac.js); Windows
 * registers a SYSTEM Scheduled Task (dns-controller-win.js). Both expose the
 * same contract to main.js: isDaemonInstalled, installedDaemonInfo,
 * isDaemonCurrent, isEnforcing, findNodeBin, installDaemon, installDaemonCli.
 */

'use strict';
module.exports = process.platform === 'win32'
  ? require('./dns-controller-win')
  : require('./dns-controller-mac');
