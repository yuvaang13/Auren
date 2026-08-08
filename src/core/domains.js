/* Auren — domains.js
 *
 * Domain normalization, validation, and matching. This is the only piece of
 * the old (browser-extension) policy engine that carries over: exact
 * hostname matching used by the DNS resolver's block decision. No fuzzy
 * logic anywhere in this file.
 *
 * Rules:
 *   - matching is "equals or subdomain of a listed domain":
 *       list item "example.com" matches "example.com", "www.example.com",
 *       "a.b.example.com" — but NOT "notexample.com".
 *   - IP addresses are intentionally rejected: direct IP connections bypass
 *     DNS, so blocking them here would silently not work.
 */

'use strict';

function normalizeDomain(hostname) {
  if (!hostname) return '';
  let h = String(hostname).trim().toLowerCase();
  h = h.replace(/^[a-z]+:\/\//, '');
  h = h.split('/')[0].split(':')[0];
  h = h.replace(/\.$/, '');
  h = h.replace(/^www\./, '');
  return h;
}

// A listed domain matches the host if the host equals it or is a subdomain.
function domainMatches(hostname, listedDomain) {
  const h = normalizeDomain(hostname);
  const l = normalizeDomain(listedDomain);
  if (!h || !l) return false;
  if (h === l) return true;
  return h.endsWith('.' + l);
}

const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/i;

// Returns { ok: true, domain } or { ok: false, error }.
function validateBlockDomain(input) {
  const d = normalizeDomain(input);
  if (!d) return { ok: false, error: 'Enter a domain, like bank.com.' };
  if (d.length > 253) return { ok: false, error: 'That domain is too long.' };
  if (IP_RE.test(d)) {
    return { ok: false, error: 'That looks like an IP address. Auren blocks domains by name, not IPs.' };
  }
  if (d.startsWith('.') || d.includes('..')) return { ok: false, error: 'That doesn\u2019t look like a valid domain.' };
  const labels = d.split('.');
  if (labels.some((l) => !LABEL_RE.test(l))) {
    return { ok: false, error: 'Domains can only contain letters, numbers, dots, and hyphens.' };
  }
  return { ok: true, domain: d };
}

module.exports = { normalizeDomain, domainMatches, validateBlockDomain };
