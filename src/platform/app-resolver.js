/* Auren — app-resolver.js
 *
 * Platform seam for resolving a search query to real installed apps. macOS
 * finds `.app` bundles (app-resolver-mac.js); Windows enumerates installed
 * executables with their version-info names (app-resolver-win.js). Both expose
 * searchApps(query, opts) -> [{ id, name, path }], capped at 10.
 *
 * Matching is deliberately plain: name or id contains the query
 * (case-insensitive). Auren never fuzzy-matches process names at block time —
 * the daemon matches exact executables from the resolved entry (core/apps.js).
 */

'use strict';
module.exports = process.platform === 'win32'
  ? require('./app-resolver-win')
  : require('./app-resolver-mac');
