/* Auren — proxyops.js
 *
 * Platform seam for pointing the system HTTPS proxy at Auren's loopback
 * blocking proxy (and restoring it) while Protection Mode is ON. macOS uses
 * networksetup auto-proxy per network service; Windows writes the WinINET
 * AutoConfigURL / ProxyEnable keys for every interactive user hive.
 *
 * Contract exposed to the daemon (both platforms):
 *   applyProxy(state, pacUrl)      -> { changed, failed }
 *   clearProxy(state)              -> { changed, failed }
 *   isProxyActive(pacUrl)          -> boolean
 */

'use strict';
module.exports = process.platform === 'win32'
  ? require('./proxyops-win')
  : require('./proxyops-mac');
