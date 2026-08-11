/* Auren — virt.js
 *
 * Virtualization/container-runtime detection (Docker Desktop, Parallels,
 * VMware Fusion, UTM, VirtualBox, …). Purely informational: while Protection
 * is ON we warn the user that these environments have their own network
 * stacks that may not transit the host's pf anchor, so Auren may not fully
 * cover traffic from inside a VM or container.
 *
 * detection is best-effort (process-name heuristics). A tool running headless
 * under a different name can evade it; that's fine, because the guarantee is
 * an honest warning, not a boundary.
 */

'use strict';
const { spawnSync } = require('child_process');

// Ordered heuristic detectors. A single `ps` output line can match several
// (e.g. qemu-system running under Colima), and that's honest: both layers
// exist.
const DETECTORS = [
  { tool: 'Docker Desktop', re: /com\.docker\.|Docker Desktop|docker-desktop/i },
  { tool: 'Colima / Lima (QEMU VM)', re: /colima|lima/i },
  { tool: 'Parallels Desktop', re: /prl_(?:disp|vm|net)_service|Parallels/i },
  { tool: 'VMware Fusion', re: /vmware|vmnetd|vmx\./i },
  { tool: 'UTM', re: /(?:^|[\\/])UTM(?:\.|$)|utm-(?:guest|proxy)/i },
  { tool: 'QEMU/KVM', re: /qemu-system|qemu-kvm/i },
  { tool: 'VirtualBox', re: /VBoxHeadless|VBoxSVC|VirtualBox/i }
];

// Pure: classify a `ps axo comm` (or pgrep) blob into detected tool names.
function detectVirtualization(psOutput) {
  const out = String(psOutput || '');
  const found = [];
  for (const d of DETECTORS) {
    if (d.re.test(out)) found.push(d.tool);
  }
  return found;
}

let cache = { at: 0, list: [] };

// Shell out to `ps` and classify; cached for 10 s so the app's poll loop never
// forks on every state push.
function runningVirtualization() {
  const now = Date.now();
  if (now - cache.at < 10000) return cache.list.slice();
  let out = '';
  try {
    const r = spawnSync('/bin/ps', ['-axo', 'comm='], { encoding: 'utf8', timeout: 5000 });
    out = r.stdout || '';
  } catch {}
  cache = { at: now, list: detectVirtualization(out) };
  return cache.list.slice();
}

module.exports = { detectVirtualization, runningVirtualization, DETECTORS };
