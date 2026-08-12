/* Auren — dnsops.js
 *
 * Platform seam for the daemon's DNS primitives: enumerating network services
 * (adapters), reading/setting their DNS servers, discovering the upstream
 * resolver, and asking "is the system resolving through 127.0.0.1?".
 *
 * macOS wraps networksetup/scutil (extracted from daemon.js); Windows wraps
 * PowerShell's DnsClient cmdlets. The daemon keeps the backup/restore state
 * machine and calls these primitives, so there is one code path per platform
 * and the rule engines stay shared.
 */

'use strict';
module.exports = process.platform === 'win32'
  ? require('./dnsops-win')
  : require('./dnsops-mac');
