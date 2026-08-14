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

// Second-level public suffixes (the "co.uk" pattern). For a hostname ending in
// one of these, the registrable domain is three labels ("example.co.uk"), not
// two. Curated from the IANA Public Suffix List — covers the widely-used
// multi-label suffix ccTLDs; anything not listed is treated as a two-label
// registrable domain ("example.com").
const SECOND_LEVEL_SUFFIXES = new Set((
  'ac.uk,co.uk,gov.uk,judiciary.uk,ltd.uk,me.uk,net.uk,nhs.uk,org.uk,plc.uk,police.uk,sch.uk,' +
  'com.au,edu.au,gov.au,id.au,net.au,org.au,asn.au,' +
  'co.nz,ac.nz,govt.nz,net.nz,org.nz,school.nz,' +
  'co.jp,ac.jp,ad.jp,ed.jp,go.jp,gr.jp,lg.jp,ne.jp,or.jp,' +
  'co.in,firm.in,gen.in,ind.in,net.in,org.in,ac.in,edu.in,gov.in,res.in,' +
  'com.sg,edu.sg,gov.sg,net.sg,org.sg,per.sg,' +
  'com.br,adm.br,adv.br,art.br,blog.br,eco.br,edu.br,eng.br,gov.br,ind.br,inf.br,med.br,net.br,org.br,tur.br,tv.br,' +
  'com.mx,edu.mx,gob.mx,net.mx,org.mx,' +
  'com.ar,edu.ar,gob.ar,net.ar,org.ar,int.ar,tur.ar,' +
  'com.hk,edu.hk,gov.hk,idv.hk,net.hk,org.hk,' +
  'com.cn,ac.cn,edu.cn,gov.cn,net.cn,org.cn,mil.cn,' +
  'com.tw,biz.tw,club.tw,edu.tw,gov.tw,idv.tw,net.tw,org.tw,' +
  'co.za,ac.za,gov.za,net.za,org.za,web.za,' +
  'com.tr,av.tr,bbs.tr,bel.tr,biz.tr,edu.tr,gov.tr,gen.tr,k12.tr,name.tr,net.tr,org.tr,tel.tr,tv.tr,web.tr,' +
  'com.ru,msk.ru,net.ru,org.ru,spb.ru,' +
  'co.kr,ac.kr,go.kr,ne.kr,or.kr,pe.kr,re.kr,' +
  'com.my,edu.my,gov.my,net.my,org.my,' +
  'com.ph,edu.ph,gov.ph,net.ph,org.ph,' +
  'co.id,ac.id,go.id,or.id,sch.id,web.id,' +
  'com.pl,edu.pl,gov.pl,info.pl,net.pl,org.pl,waw.pl,' +
  'com.gr,edu.gr,gov.gr,net.gr,org.gr,' +
  'com.pt,edu.pt,gov.pt,net.pt,org.pt,' +
  'com.vn,edu.vn,gov.vn,net.vn,org.vn,' +
  'com.ua,edu.ua,gov.ua,net.ua,org.ua,' +
  'com.ir,ac.ir,edu.ir,gov.ir,net.ir,org.ir,' +
  'co.il,ac.il,edu.il,gov.il,k12.il,muni.il,net.il,org.il,' +
  'co.th,ac.th,go.th,in.th,net.th,or.th,' +
  'com.eg,edu.eg,gov.eg,net.eg,org.eg,' +
  'com.ng,edu.ng,gov.ng,net.ng,org.ng,' +
  'co.ke,ac.ke,go.ke,ne.ke,or.ke,' +
  'co.ma,ac.ma,gov.ma,net.ma,org.ma,' +
  'com.sa,edu.sa,gov.sa,net.sa,org.sa,' +
  'co.ae,ac.ae,gov.ae,net.ae,org.ae,sch.ae,' +
  'com.qa,edu.qa,gov.qa,net.qa,org.qa,' +
  'com.pk,edu.pk,gov.pk,net.pk,org.pk,' +
  'com.lk,edu.lk,gov.lk,net.lk,org.lk,' +
  'com.pe,edu.pe,gob.pe,mil.pe,net.pe,org.pe,' +
  'com.co,edu.co,gov.co,net.co,org.co,' +
  'com.ec,edu.ec,gob.ec,mil.ec,net.ec,org.ec,' +
  'com.ve,edu.ve,gob.ve,net.ve,org.ve,web.ve,' +
  'co.ao,edu.ao,gov.ao,org.ao,' +
  'com.bo,edu.bo,gob.bo,net.bo,org.bo,' +
  'com.py,edu.py,gov.py,net.py,org.py,' +
  'com.uy,edu.uy,gub.uy,net.uy,org.uy,' +
  'co.cr,ac.cr,ed.cr,go.cr,or.cr,sa.cr,' +
  'com.do,edu.do,gov.do,net.do,org.do,' +
  'com.gt,edu.gt,gob.gt,net.gt,org.gt,' +
  'com.hn,edu.hn,gob.hn,net.hn,org.hn,' +
  'com.sv,edu.sv,gob.sv,net.sv,org.sv,' +
  'com.ni,edu.ni,gob.ni,net.ni,org.ni,' +
  'com.pa,edu.pa,gob.pa,net.pa,org.pa,' +
  'com.kz,edu.kz,gov.kz,net.kz,org.kz,' +
  'com.az,edu.az,gov.az,net.az,org.az,' +
  'com.ge,edu.ge,gov.ge,net.ge,org.ge,' +
  'com.by,edu.by,gov.by,net.by,org.by,' +
  'com.md,edu.md,gov.md,net.md,org.md,' +
  'com.uz,edu.uz,gov.uz,net.uz,org.uz,' +
  'com.tn,edu.tn,gov.tn,net.tn,org.tn,' +
  'com.mu,edu.mu,gov.mu,net.mu,org.mu,' +
  'com.mt,edu.mt,gov.mt,net.mt,org.mt,' +
  'com.sc,edu.sc,gov.sc,net.sc,org.sc,' +
  'co.ug,ac.ug,go.ug,or.ug,sc.ug,' +
  'co.tz,ac.tz,go.tz,or.tz,' +
  'co.zw,ac.zw,gov.zw,org.zw,' +
  'com.et,edu.et,gov.et,net.et,org.et,' +
  'com.sn,edu.sn,gouv.sn,net.sn,org.sn,' +
  'com.ci,edu.ci,gov.ci,net.ci,org.ci,' +
  'com.af,com.bd,com.bh,com.bt,com.dz,com.fj,com.ga,com.gh,com.gm,com.gn,com.iq,com.jo,com.kh,com.kw,com.la,com.lb,com.lr,com.ly,com.ml,com.mm,com.mn,com.mv,com.na,com.np,com.om,com.pg,com.sb,com.sd,com.sl,com.sy,com.tg,com.vu,com.ye,' +
  'co.ck,co.fk,co.pn,co.to,' +
  'com.ai,com.ag,com.bb,com.bs,com.bz,com.dm,com.gd,com.gp,com.gy,com.jm,com.kn,com.ky,com.lc,com.ms,com.sr,com.vc,com.vg,' +
  'com.gi,com.gl,com.gg,com.je,' +
  'co.us,com.us,net.us,org.us'
).split(','));

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

// The registrable (apex) domain of a hostname — the domain a registrant
// actually controls. "mail.google.com" -> "google.com", "example.co.uk" ->
// "example.co.uk". Returns '' for empty/invalid input. Pure.
function registrableDomain(hostname) {
  const h = normalizeDomain(hostname);
  if (!h) return '';
  const labels = h.split('.');
  if (labels.length <= 2) return h;
  const last2 = labels.slice(-2).join('.');
  if (labels.length >= 3 && SECOND_LEVEL_SUFFIXES.has(last2)) return labels.slice(-3).join('.');
  return last2;
}

// The effective blocklist: each entry plus its registrable domain, deduped.
// Blocking a subdomain therefore also blocks its apex. Without this, browsers
// reuse an existing pooled HTTPS connection to the apex's shared front-end
// (HTTP/2 connection coalescing — the TLS cert covers *.apex) and load the
// blocked subdomain without ever issuing a new DNS lookup or proxy CONNECT for
// it. Discord is always re-resolved so it stays blocked; Google subdomains
// (mail.google.com etc.) ride an existing allowed connection to the same
// front-end and slip past both gates. Blocking the apex closes that hole: no
// *.apex front-end can be resolved or connected to at all.
function expandBlocklist(entries) {
  const out = new Set();
  for (const e of (Array.isArray(entries) ? entries : [])) {
    const d = normalizeDomain(e);
    if (!d) continue;
    out.add(d);
    const apex = registrableDomain(d);
    if (apex) out.add(apex);
  }
  return Array.from(out);
}

module.exports = { normalizeDomain, domainMatches, validateBlockDomain, registrableDomain, expandBlocklist };
