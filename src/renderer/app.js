'use strict';

const api = window.auren;
const $ = (id) => document.getElementById(id);

let state = {
  mode: 'off', blocklist: [], appBlocklist: [], activity: [],
  onboardingDone: true, enforcement: false, platform: 'darwin',
  modeCooldownUntil: 0, degraded: false, terminalBlock: true, dohBlock: true,
  vmsDetected: [], settingsTampered: false, keystrokeShield: false,
  autoProtect: { enabled: true, engagedBy: [] },
  fsGuard: { mounts: [], defaultDeny: true },
  sandbox: { profile: {}, events: [] }
};
let busy = false;
let countdownTimer = null;
let sandboxPollTimer = null;

function cooldownUntil() {
  const u = Number(state.modeCooldownUntil) || 0;
  return u > Date.now() ? u : 0;
}

function syncCountdown() {
  const active = cooldownUntil() > 0;
  if (active && !countdownTimer) {
    countdownTimer = setInterval(() => {
      const remaining = cooldownUntil();
      if (remaining <= 0) {
        clearInterval(countdownTimer);
        countdownTimer = null;
        return;
      }
      const el = $('cooldown-count');
      if (el) el.textContent = Math.max(1, Math.ceil((remaining - Date.now()) / 1000));
    }, 250);
  } else if (!active && countdownTimer) {
    clearInterval(countdownTimer);
    countdownTimer = null;
  }
}

function showError(id, msg) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden');
}

const ICON_LINK = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M9.5 12a2.5 2.5 0 003.6 3.4l2.5-2.5a2.5 2.5 0 10-3.5-3.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><path d="M14.5 12a2.5 2.5 0 00-3.6-3.4l-2.5 2.5a2.5 2.5 0 103.5 3.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const ICON_APP = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="3.5" stroke="currentColor" stroke-width="1.7"/><path d="M9 9.5h.01M14 9.5h.01M9 14.5h.01M14 14.5h.01" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>';
const ICON_FOLDER = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 6.5A2.5 2.5 0 016.5 4H12l2 2h3.5A2.5 2.5 0 0120 8.5V17a2.5 2.5 0 01-2.5 2.5H6.5A2.5 2.5 0 014 17V6.5z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>';
const KIND_TAG = { block: 'Blocked', toggle: 'Mode', agent: 'Gated', command: 'Command', app: 'App', daemon: 'Service' };

function updateStatusPill(on) {
  const pill = $('status-pill');
  const label = $('status-label');
  const shield = $('shield-wrap');
  const badge = $('live-badge');
  pill.classList.remove('on', 'off', 'warn');
  shield.classList.remove('on', 'off', 'warn');
  badge.classList.add('hidden');
  if (state.degraded) {
    pill.classList.add('warn');
    label.textContent = 'Degraded';
    shield.classList.add('warn');
  } else if (on && state.enforcement) {
    pill.classList.add('on');
    label.textContent = 'Protected';
    shield.classList.add('on');
    badge.classList.remove('hidden');
  } else if (on) {
    pill.classList.add('warn');
    label.textContent = 'Starting…';
    shield.classList.add('warn');
  } else {
    pill.classList.add('off');
    label.textContent = 'Off';
    shield.classList.add('off');
  }
  // sandbox dot
  const dot = $('sandbox-dot');
  if (dot) {
    dot.className = 'nav-dot';
    if (state.degraded) dot.classList.add('warn');
    else if (on) dot.classList.add('on');
  }
}

function renderStats() {
  const items = state.activity || [];
  let blocks = 0;
  let gated = 0;
  let osBlocks = 0;
  let appBlocks = 0;
  for (const e of items) {
    if (e.kind === 'block') blocks += 1;
    else if (e.kind === 'agent') gated += 1;
    else if (e.kind === 'command' && e.outcome === 'blocked') osBlocks += 1;
    else if (e.kind === 'daemon' && e.outcome === 'pf_applied') osBlocks += 1;
    else if (e.kind === 'app' && e.outcome === 'blocked') appBlocks += 1;
  }
  const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  set('stat-sites', state.blocklist.length);
  set('stat-blocks', blocks);
  set('stat-gated', gated);
  set('stat-os', osBlocks);
  set('stat-apps', appBlocks);
  set('sites-count', state.blocklist.length);
  set('apps-count', (state.appBlocklist || []).length);
  // fs badge
  const fsBadge = $('fs-mount-badge');
  if (fsBadge) {
    const n = (state.fsGuard && state.fsGuard.mounts || []).length;
    fsBadge.textContent = n === 0 ? '0 mounts' : n === 1 ? '1 mount' : n + ' mounts';
  }
  // pill updates
  const terminalOn = !!state.terminalBlock;
  const autofillOn = state.autofillBlock !== false;
  const keystrokeOn = !!state.keystrokeShield;
  const pill = (id, on) => {
    const el = $(id);
    if (!el) return;
    el.textContent = on ? 'ON' : 'OFF';
    el.className = 'control-pill ' + (on ? 'on' : 'off');
  };
  // Network tab pills
  pill('pill-ssh', terminalOn);
  pill('pill-icmp', terminalOn);
  pill('pill-autofill', autofillOn);
  pill('pill-keystroke', keystrokeOn);
}

function render() {
  const on = state.mode === 'on';
  const cooldown = cooldownUntil();
  const inCooldown = cooldown > 0;
  const machine = state.platform === 'darwin' ? 'this Mac' : state.platform === 'win32' ? 'this PC' : 'this computer';
  const toggle = $('mode-toggle');
  if (toggle) {
    toggle.checked = on;
    toggle.disabled = busy || inCooldown;
  }

  const degradedEl = $('degraded-banner');
  if (degradedEl) degradedEl.classList.toggle('hidden', !state.degraded);
  if (state.degraded) {
    const reason = state.degradedReason || (state.dnsConflict ? 'dns_conflict' : 'heartbeat_stale');
    const who = state.dnsConflict && state.dnsConflict.name
      ? state.dnsConflict.name + ' (pid ' + state.dnsConflict.pid + ')'
      : null;
    const txt = $('degraded-text');
    if (txt) {
      if (reason === 'dns_conflict' && who) {
        txt.textContent = 'Auren\u2019s DNS resolver could not start: ' + who + ' is already using port 53. Domain blocking is off until that process is stopped and protection is toggled. Auren is failing closed \u2014 nothing it gates will be allowed through in the meantime.';
      } else if (reason === 'not_installed') {
        txt.textContent = 'Auren\u2019s background service isn\u2019t installed. Reinstall it to restore protection. Auren is failing closed — nothing it gates will be allowed through in the meantime.';
      } else if (reason === 'stale_daemon') {
        txt.textContent = 'Auren\u2019s background service is out of date. Reinstall it to restore protection. Auren is failing closed — nothing it gates will be allowed through until it updates.';
      } else if (reason === 'integrity_failed') {
        txt.textContent = 'Auren detected a config integrity issue — the background service is keeping the last verified policy. Restart protection or reinstall the service to recover.';
      } else if (reason === 'reconcile_stale') {
        txt.textContent = 'Auren\u2019s background service is running but its enforcement loop stopped responding. Auren is failing closed — nothing it gates will be allowed through until it recovers.';
      } else if (reason === 'fail_closed') {
        txt.textContent = 'Auren\u2019s encrypted store could not be verified and has failed closed. Review Recent activity for details.';
      } else {
        txt.textContent = 'Auren\u2019s background service isn\u2019t responding, so it can\u2019t verify that blocked sites are unreachable. Auren is failing closed — nothing it gates will be allowed through until the service recovers.';
      }
    }
    const reasonEl = $('degraded-reason');
    if (reasonEl) {
      const hbAge = typeof state.heartbeatAge === 'number' ? Math.round(state.heartbeatAge / 1000) + 's ago' : 'no heartbeat';
      const reconAge = typeof state.reconcileAge === 'number' ? Math.round(state.reconcileAge / 1000) + 's ago' : '—';
      const installed = state.daemonInstalled ? 'installed' : 'not installed';
      const current = state.daemonCurrent === false ? 'stale' : state.daemonCurrent ? 'current' : 'unknown';
      const lastHb = state.lastHeartbeat ? 'v' + (state.lastHeartbeat.version || '?') + ' hb ' + hbAge : 'no heartbeat';
      reasonEl.textContent = 'Reason: ' + reason + ' · daemon ' + installed + ' (' + current + ') · ' + lastHb + ' · reconcile ' + reconAge;
      if (state.daemonBusy) reasonEl.textContent += ' · reinstalling…';
      reasonEl.classList.remove('hidden');
    }
    const portsBtn = $('degraded-ports');
    if (portsBtn) portsBtn.classList.toggle('hidden', reason !== 'dns_conflict' && reason !== 'heartbeat_stale');
    const retryBtn = $('degraded-retry');
    if (retryBtn) retryBtn.disabled = !!state.daemonBusy || busy;
  } else {
    const reasonEl = $('degraded-reason');
    if (reasonEl) reasonEl.classList.add('hidden');
    const detailsBox = $('degraded-details-box');
    if (detailsBox) detailsBox.classList.add('hidden');
  }

  const autoProtect = state.autoProtect || { enabled: true, engagedBy: [] };
  const apToggle = $('autoprotect-toggle');
  if (apToggle) apToggle.checked = !!autoProtect.enabled;
  const apEngaged = on && Array.isArray(autoProtect.engagedBy) && autoProtect.engagedBy.length > 0;
  const apBanner = $('autoprotect-banner');
  if (apBanner) apBanner.classList.toggle('hidden', !apEngaged);
  if (!apEngaged) {
    const row = $('autoprotect-ignore-row');
    const note = $('autoprotect-ignore-note');
    const btn = $('autoprotect-ignore');
    if (row) row.classList.add('hidden');
    if (note) note.textContent = '';
    if (btn) btn.classList.remove('hidden');
  } else if ($('autoprotect-ignore-note') && !$('autoprotect-ignore-note').textContent) {
    const row = $('autoprotect-ignore-row');
    if (row) row.classList.remove('hidden');
  }

  const shieldOn = !!state.keystrokeShield;
  const badge = $('keystroke-shield-badge');
  if (badge) badge.classList.toggle('hidden', !shieldOn);
  document.body.classList.toggle('keystroke-shield', shieldOn);

  const cd = $('cooldown-display');
  if (cd) {
    cd.classList.toggle('hidden', !inCooldown);
    if (inCooldown) {
      const secs = Math.max(1, Math.ceil((cooldown - Date.now()) / 1000));
      const c = $('cooldown-count');
      if (c) c.textContent = secs;
    }
  }

  updateStatusPill(on);

  const hint = $('mode-hint');
  if (hint) {
    hint.textContent = inCooldown
      ? 'Verified. Sites stay blocked while you confirm \u2014 protection turns off in a moment.'
      : (state.degraded
          ? 'Auren can\u2019t verify its own enforcement right now, so it is failing closed: nothing it gates will be allowed through until the background service recovers.'
          : (on
              ? (state.enforcement
                  ? (state.terminalBlock
                      ? 'Blocked sites are unreachable in every app and browser on ' + machine + '. Terminal and OS-level network access (ping, ssh, …) is blocked too.' + (state.dohBlock ? ' Known DoH/DoT endpoints are blocked as well.' : '')
                      : 'Blocked sites are unreachable in every app and browser on ' + machine + '.')
                  : 'Protection is ON, but ' + machine + ' isn\u2019t resolving through Auren yet. The background service may still be starting \u2014 if this persists, check Recent activity.')
              : 'Everything is reachable as usual. Flip the switch to start guarding.'));
  }

  const vmOn = on && Array.isArray(state.vmsDetected) && state.vmsDetected.length > 0;
  const vmWarn = $('vm-warning');
  if (vmWarn) {
    vmWarn.classList.toggle('hidden', !vmOn);
    if (vmOn) vmWarn.textContent = 'Note: ' + state.vmsDetected.join(', ') + ' is running. VMs and containers use their own network stack, so Auren may not fully block traffic from inside them \u2014 see \u201cHonest limits\u201d in the README.';
  }

  const settingsWarn = $('settings-warning');
  if (settingsWarn) {
    settingsWarn.classList.toggle('hidden', !state.settingsTampered);
    if (state.settingsTampered) settingsWarn.textContent = 'Your settings file failed verification, so protection is running on safe defaults. Review settings.json and restart auren.';
  }

  // — Sites —
  const list = $('block-list');
  if (list) {
    list.textContent = '';
    const empty = $('block-empty');
    if (empty) empty.classList.toggle('hidden', state.blocklist.length > 0);
    for (const d of state.blocklist) {
      const li = document.createElement('li');
      li.className = 'block-item';
      li.innerHTML = ICON_LINK + '<span class="domain"></span>';
      li.querySelector('.domain').textContent = d;
      const btn = document.createElement('button');
      btn.className = 'remove-btn';
      btn.type = 'button';
      btn.textContent = '\u00d7';
      btn.setAttribute('aria-label', 'Remove ' + d);
      btn.addEventListener('click', () => api.removeDomain(d));
      li.append(btn);
      list.append(li);
    }
  }

  // — Apps —
  const alist = $('app-block-list');
  if (alist) {
    alist.textContent = '';
    const blockedApps = state.appBlocklist || [];
    const empty = $('app-block-empty');
    if (empty) empty.classList.toggle('hidden', blockedApps.length > 0);
    for (const a of blockedApps) {
      const li = document.createElement('li');
      li.className = 'block-item';
      li.innerHTML = ICON_APP + '<div class="app-name-wrap"><span class="domain"></span><span class="app-sub"></span></div>';
      li.querySelector('.domain').textContent = a.name;
      li.querySelector('.app-sub').textContent = a.id;
      const btn = document.createElement('button');
      btn.className = 'remove-btn';
      btn.type = 'button';
      btn.textContent = '\u00d7';
      btn.setAttribute('aria-label', 'Remove ' + a.name);
      btn.addEventListener('click', () => api.removeApp(a.id));
      li.append(btn);
      alist.append(li);
    }
  }

  // — FS Guard mounts —
  renderFsGuard();

  // — Sandbox —
  renderSandbox();

  // — Activity —
  const act = $('activity-list');
  if (act) {
    act.textContent = '';
    const items = state.activity || [];
    const empty = $('activity-empty');
    if (empty) empty.classList.toggle('hidden', items.length > 0);
    for (const e of items) {
      const li = document.createElement('li');
      const kind = e.kind || 'event';
      li.className = 'activity-item kind-' + kind;
      li.innerHTML =
        '<span class="activity-marker"></span>' +
        '<span class="activity-text"></span>' +
        '<span class="kind-tag">' + (KIND_TAG[kind] || 'Event') + '</span>';
      li.querySelector('.activity-text').textContent = e.text || e.note || e.outcome || e.domain || '';
      act.append(li);
    }
  }

  renderStats();
  syncCountdown();
}

function renderFsGuard() {
  const mounts = (state.fsGuard && state.fsGuard.mounts) || [];
  const box = $('fs-mounts');
  const empty = $('fs-empty');
  if (!box) return;
  box.textContent = '';
  if (empty) empty.classList.toggle('hidden', mounts.length > 0);
  for (const m of mounts) {
    const div = document.createElement('div');
    div.className = 'fs-mount';
    div.innerHTML =
      '<span class="fs-mount-icon">' + ICON_FOLDER + '</span>' +
      '<span class="fs-mount-meta"><span class="fs-mount-name"></span><span class="fs-mount-path"></span></span>' +
      '<span class="fs-mount-scope">read/write</span>';
    div.querySelector('.fs-mount-name').textContent = m.displayName || m.path.split('/').pop() || m.path;
    div.querySelector('.fs-mount-path').textContent = m.path;
    const btn = document.createElement('button');
    btn.className = 'remove-btn';
    btn.type = 'button';
    btn.textContent = '\u00d7';
    btn.setAttribute('aria-label', 'Remove ' + m.path);
    btn.addEventListener('click', async () => {
      const r = await api.removeWorkspace(m.id);
      if (r && !r.ok) showError('fs-error', r.error || 'Could not remove mount');
      else {
        const err = $('fs-error');
        if (err) err.classList.add('hidden');
      }
    });
    div.append(btn);
    box.append(div);
  }
}

function renderSandbox() {
  const sb = (state.sandbox && state.sandbox.profile) || {};
  const events = (state.sandbox && state.sandbox.events) || [];

  // Platform label
  const platEl = $('sandbox-platform');
  if (platEl) {
    const isWin = state.platform === 'win32';
    platEl.textContent = isWin ? 'Windows' : state.platform === 'darwin' ? 'macOS' : state.platform;
    platEl.className = 'control-pill on';
  }

  const setTile = (id, val, good) => {
    const el = $(id);
    if (!el) return;
    el.textContent = val;
    el.className = 'sandbox-tile-value ' + (good === true ? 'on' : good === false ? 'off' : '');
    if (val === 'Active' || val === 'Yes' || val === true) el.className = 'sandbox-tile-value on';
  };

  if (state.platform === 'darwin') {
    setTile('sb-app-sandbox', sb.appSandbox ? 'Active' : 'Not sandboxed', !!sb.appSandbox);
    const sub = $('sb-app-sandbox-sub');
    if (sub) sub.textContent = sb.appSandbox ? 'com.apple.security.app-sandbox' : '—';
    setTile('sb-hardened', sb.hardenedRuntime ? 'Yes' : 'No', !!sb.hardenedRuntime);
    setTile('sb-pf', sb.pfAnchorActive ? 'Active' : 'Inactive', !!sb.pfAnchorActive);
    setTile('sb-proxy', sb.proxyActive ? 'Active' : 'Inactive', !!sb.proxyActive);
    const proxySub = $('sb-proxy-sub');
    if (proxySub) proxySub.textContent = sb.proxyActive ? '127.0.0.1:' + (sb.proxyPort || 42792) : '—';
    const winInfo = $('sandbox-win-info');
    if (winInfo) winInfo.classList.add('hidden');
  } else if (state.platform === 'win32') {
    setTile('sb-app-sandbox', sb.appContainer ? 'Yes' : 'No', !!sb.appContainer);
    const sub = $('sb-app-sandbox-sub');
    if (sub) sub.textContent = sb.appContainer ? 'AppContainer' : 'Not isolated';
    setTile('sb-hardened', sb.integrityLevel || 'unknown', sb.integrityLevel === 'medium' || sb.integrityLevel === 'high');
    setTile('sb-pf', sb.firewallActive ? 'Active' : 'Inactive', !!sb.firewallActive);
    setTile('sb-proxy', sb.proxyActive ? 'Active' : 'Inactive', !!sb.proxyActive);
    const winInfo = $('sandbox-win-info');
    if (winInfo) winInfo.classList.remove('hidden');
    const acText = $('sb-appcontainer-text');
    if (acText) acText.textContent = sb.appContainer ? 'Process is AppContainer-isolated.' : 'Not running inside an AppContainer.';
    const acPill = $('sb-appcontainer-pill');
    if (acPill) { acPill.textContent = sb.appContainer ? 'YES' : 'NO'; acPill.className = 'control-pill ' + (sb.appContainer ? 'on' : 'off'); }
    const ilText = $('sb-integrity-text');
    if (ilText) ilText.textContent = 'Current integrity: ' + (sb.integrityLevel || 'unknown') + ' (Medium is standard; High is elevated).';
    const ilPill = $('sb-integrity-pill');
    if (ilPill) { ilPill.textContent = sb.integrityLevel || '—'; ilPill.className = 'control-pill ' + (sb.integrityLevel === 'high' || sb.integrityLevel === 'system' ? 'warn' : sb.integrityLevel === 'medium' ? 'on' : 'off'); }
  } else {
    setTile('sb-app-sandbox', '—', null);
    setTile('sb-hardened', '—', null);
    setTile('sb-pf', sb.pfAnchorActive ? 'Active' : 'Inactive', !!sb.pfAnchorActive);
    setTile('sb-proxy', sb.proxyActive ? 'Active' : 'Inactive', !!sb.proxyActive);
  }

  // Entitlements / capabilities
  const entBox = $('sb-entitlements');
  if (entBox) {
    entBox.textContent = '';
    const ents = sb.entitlements || [];
    if (!ents.length) {
      const chip = document.createElement('span');
      chip.className = 'exclusion-chip exclusion-chip--browser';
      chip.textContent = state.platform === 'win32' ? 'No entitlements (Windows — see ACL/Integrity)' : 'No entitlements detected (dev build or not sandboxed)';
      entBox.append(chip);
    } else {
      for (const e of ents.slice(0, 30)) {
        const chip = document.createElement('span');
        chip.className = 'exclusion-chip';
        chip.textContent = e;
        entBox.append(chip);
      }
    }
  }

  // Events (ephemeral)
  const evList = $('sandbox-events');
  const evEmpty = $('sandbox-empty');
  if (evList) {
    evList.textContent = '';
    const evs = events;
    if (evEmpty) evEmpty.classList.toggle('hidden', evs.length > 0);
    for (const ev of evs.slice(0, 100)) {
      const li = document.createElement('li');
      li.className = 'activity-item kind-command';
      const time = new Date(ev.ts).toLocaleTimeString();
      li.innerHTML =
        '<span class="activity-marker"></span>' +
        '<span class="activity-text"></span>' +
        '<span class="kind-tag">FS</span>';
      const text = li.querySelector('.activity-text');
      const p = ev.path ? ev.path.split('/').pop() || ev.path : '(unknown)';
      text.textContent = time + ' — ' + ev.reason + ' — ' + p;
      evList.append(li);
    }
  }
}

function initTabs() {
  const navItems = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.tab-panel');
  navItems.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.getAttribute('data-tab');
      navItems.forEach(b => b.classList.toggle('active', b === btn));
      panels.forEach(p => p.classList.toggle('active', p.id === 'tab-' + tab));
      // If switching to sandbox, refresh immediately
      if (tab === 'sandbox') refreshSandbox();
    });
  });
}

async function refreshSandbox() {
  try {
    const s = await api.getSandbox();
    state.sandbox = s;
    renderSandbox();
  } catch { /* ignore */ }
}

function startSandboxPoll() {
  if (sandboxPollTimer) clearInterval(sandboxPollTimer);
  sandboxPollTimer = setInterval(refreshSandbox, 2000);
}

async function init() {
  state = await api.getState();

  // ensure nested defaults
  state.fsGuard = state.fsGuard || { mounts: [] };
  state.sandbox = state.sandbox || { profile: {}, events: [] };

  render();
  initTabs();

  // Populate static exclusion chips once
  try {
    const ex = await api.getExclusions();
    const fill = (id, items, cls) => {
      const box = $(id);
      if (!box) return;
      box.textContent = '';
      for (const c of (items || []).slice(0, 20)) {
        const chip = document.createElement('span');
        chip.className = 'exclusion-chip ' + (cls || '');
        chip.textContent = c;
        box.append(chip);
      }
    };
    if (ex) {
      fill('excl-dotfiles', ex.basenames, '');
      fill('excl-keys', ex.extensions, 'exclusion-chip--ext');
      fill('excl-dirs', ex.dirSegments, 'exclusion-chip--dir');
      fill('excl-browser', ['Login Data', 'Cookies', 'Web Data', 'History', 'keychain'], 'exclusion-chip--browser');
    }
  } catch { /* ignore */ }

  const badge = $('keystroke-shield-badge');
  if (badge && state.platform !== 'darwin') {
    badge.title = "While Protection is on, auren's window can't be screen-captured, so nothing you type in auren ever appears in a recording.";
    const obShield = $('ob-shield');
    if (obShield) obShield.textContent = 'While protection is on, auren hides your keystrokes: this window can\u2019t be captured on screen, so nothing you type here ever appears in a recording.';
  }

  if (state.platform !== 'darwin' && state.platform !== 'win32') {
    showError('mode-error', 'This build supports macOS and Windows. Other platforms are planned, not yet supported.');
    const t = $('mode-toggle');
    if (t) t.disabled = true;
  }

  if (!state.onboardingDone) {
    $('onboarding').classList.remove('hidden');
    $('ob-step-1').classList.remove('hidden');
    $('ob-step-2').classList.add('hidden');
  }

  $('ob-next-1').addEventListener('click', () => {
    $('ob-step-1').classList.add('hidden');
    $('ob-step-2').classList.remove('hidden');
    document.querySelectorAll('.ob-dot').forEach((d, i) => d.classList.toggle('active', i === 1));
    $('domain-input').focus();
  });

  $('ob-finish').addEventListener('click', async () => {
    await api.finishOnboarding();
    $('onboarding').classList.add('hidden');
    $('domain-input').focus();
  });

  const modeToggle = $('mode-toggle');
  if (modeToggle) {
    modeToggle.addEventListener('change', async (ev) => {
      if (busy) return;
      const wantOn = ev.target.checked;
      ev.target.checked = !wantOn;
      busy = true;
      render();
      try {
        const r = await api.setMode(wantOn ? 'on' : 'off');
        const errEl = $('mode-error');
        if (errEl) errEl.classList.add('hidden');
        if (r && r.ok) {
          state.mode = r.mode;
          if (r.cooldownUntil) state.modeCooldownUntil = r.cooldownUntil;
        } else if (r && r.cancelled) {
          showError('mode-error', wantOn
            ? 'Setup was cancelled. Protection stays off.'
            : 'Verification cancelled. Protection stays ON.');
        } else if (r && r.error === 'setup') {
          showError('mode-error', 'Auren couldn\u2019t set up its background service, so protection stays off.');
        } else {
          showError('mode-error', 'Verification didn\u2019t pass. Protection stays ON.');
        }
        render();
      } finally {
        busy = false;
        render();
      }
    });
  }

  const apToggle = $('autoprotect-toggle');
  if (apToggle) {
    apToggle.addEventListener('change', async (ev) => {
      const enabled = ev.target.checked;
      await api.setAutoProtect({ enabled });
      state.autoProtect = Object.assign({}, state.autoProtect || {}, { enabled });
      render();
    });
  }

  const apEngage = $('autoprotect-engage');
  if (apEngage) {
    apEngage.addEventListener('click', async () => {
      $('autoprotect-prompt').classList.add('hidden');
      busy = true;
      render();
      try { await api.confirmAutoProtect(); } finally { busy = false; }
    });
  }
  const apDismiss = $('autoprotect-dismiss');
  if (apDismiss) apDismiss.addEventListener('click', () => $('autoprotect-prompt').classList.add('hidden'));

  const apIgnore = $('autoprotect-ignore');
  if (apIgnore) {
    apIgnore.addEventListener('click', async () => {
      const engaged = state.autoProtect && Array.isArray(state.autoProtect.engagedBy) ? state.autoProtect.engagedBy : [];
      if (!engaged.length) return;
      const tool = engaged[0];
      await api.ignoreAgentTool(tool);
      apIgnore.classList.add('hidden');
      const note = $('autoprotect-ignore-note');
      if (note) note.textContent = tool + ' is ignored \u2014 it won\u2019t auto-engage protection again.';
    });
  }

  // Degraded banner actions
  const degradedRetry = $('degraded-retry');
  if (degradedRetry) {
    degradedRetry.addEventListener('click', async () => {
      if (busy || state.daemonBusy) return;
      busy = true;
      degradedRetry.textContent = 'Reinstalling…';
      degradedRetry.disabled = true;
      render();
      try {
        const r = await api.reinstallDaemon();
        if (!r.ok) {
          showError('mode-error', r.cancelled ? 'Reinstall cancelled. Protection stays degraded.' : 'Reinstall failed: ' + (r.error || 'unknown error'));
        } else {
          const errEl = $('mode-error');
          if (errEl) errEl.classList.add('hidden');
        }
      } catch (err) {
        showError('mode-error', 'Reinstall error: ' + err.message);
      } finally {
        busy = false;
        degradedRetry.textContent = 'Retry — reinstall service';
        degradedRetry.disabled = false;
        render();
      }
    });
  }
  const degradedDetailsBtn = $('degraded-details');
  const degradedDetailsBox = $('degraded-details-box');
  if (degradedDetailsBtn && degradedDetailsBox) {
    degradedDetailsBtn.addEventListener('click', async () => {
      const visible = !degradedDetailsBox.classList.contains('hidden');
      if (visible) {
        degradedDetailsBox.classList.add('hidden');
        degradedDetailsBtn.textContent = 'View details';
        return;
      }
      degradedDetailsBtn.textContent = 'Loading…';
      try {
        const d = await api.getDiagnostics();
        const lines = [];
        lines.push('degraded: ' + d.degraded + ' (' + (d.degradedReason || '—') + ') since ' + (d.degradedSince ? new Date(d.degradedSince).toLocaleTimeString() : '—'));
        lines.push('daemon: ' + (d.daemonInstalled ? 'installed' : 'not installed') + ' · ' + (d.daemonCurrent ? 'current' : 'stale') + ' · busy=' + d.daemonBusy);
        if (d.daemonInfo) lines.push('daemonInfo: ' + JSON.stringify(d.daemonInfo));
        lines.push('heartbeat: ' + (d.lastHeartbeat ? JSON.stringify(d.lastHeartbeat) : 'none'));
        lines.push('enforcement: ' + d.enforcement + ' · heartbeatPath: ' + d.heartbeatPath);
        if (d.daemonLogTail) lines.push('\n— daemon.log tail —\n' + d.daemonLogTail);
        if (d.installLogTail) lines.push('\n— install.log tail —\n' + d.installLogTail);
        degradedDetailsBox.textContent = lines.join('\n');
        degradedDetailsBox.classList.remove('hidden');
        degradedDetailsBtn.textContent = 'Hide details';
      } catch (err) {
        degradedDetailsBox.textContent = 'Could not load diagnostics: ' + err.message;
        degradedDetailsBox.classList.remove('hidden');
        degradedDetailsBtn.textContent = 'Hide details';
      }
    });
  }
  const degradedPortsBtn = $('degraded-ports');
  if (degradedPortsBtn && degradedDetailsBox) {
    degradedPortsBtn.addEventListener('click', async () => {
      degradedPortsBtn.textContent = 'Checking…';
      try {
        const r = await api.checkPorts();
        const out = r.ok ? r.output : 'Error: ' + r.error;
        degradedDetailsBox.textContent = 'Port 53 check:\n' + out + '\n\nIf another process owns 53, stop it (e.g. AdGuard, dnsmasq, VPN resolver) then click Retry. Or run: sudo bash scripts/check-ports.sh';
        degradedDetailsBox.classList.remove('hidden');
        const btn = $('degraded-details');
        if (btn) btn.textContent = 'Hide details';
      } catch (err) {
        degradedDetailsBox.textContent = 'Port check failed: ' + err.message;
        degradedDetailsBox.classList.remove('hidden');
      } finally {
        degradedPortsBtn.textContent = 'Check port 53';
      }
    });
  }

  api.onAutoProtectPrompt((tools) => {
    const names = Array.isArray(tools) && tools.length ? tools.join(', ') : 'AI tooling';
    const el = $('autoprotect-prompt-tools');
    if (el) el.textContent = 'Turn protection on now (' + names + ')?';
    const p = $('autoprotect-prompt');
    if (p) p.classList.remove('hidden');
  });

  const addForm = $('add-form');
  if (addForm) {
    addForm.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const input = $('domain-input');
      const value = input.value.trim();
      if (!value) return;
      const r = await api.addDomain(value);
      if (r && r.ok) {
        input.value = '';
        const err = $('add-error');
        if (err) err.classList.add('hidden');
      } else if (r && r.error) {
        showError('add-error', r.error);
      }
    });
  }

  // App search
  let appSearchSeq = 0;
  let appSearchTimer = null;
  const searchInput = $('app-search-input');
  const matchesBox = $('app-matches');
  function clearMatches() {
    if (!matchesBox) return;
    matchesBox.classList.add('hidden');
    matchesBox.textContent = '';
  }
  function appSearch() {
    if (!searchInput || !matchesBox) return;
    const q = searchInput.value.trim();
    if (!q) { clearMatches(); return; }
    const seq = ++appSearchSeq;
    api.searchApps(q).then((matches) => {
      if (seq !== appSearchSeq) return;
      matchesBox.textContent = '';
      if (!matches.length) {
        const li = document.createElement('li');
        li.className = 'app-match empty-match';
        li.textContent = 'No apps found';
        matchesBox.append(li);
      } else {
        for (const m of matches.slice(0, 8)) {
          const li = document.createElement('li');
          li.className = 'app-match';
          li.innerHTML = '<span class="app-match-name"></span><span class="app-match-id"></span>';
          li.querySelector('.app-match-name').textContent = m.name;
          li.querySelector('.app-match-id').textContent = m.id;
          li.addEventListener('pointerdown', (ev) => {
            ev.preventDefault();
            addApp(m);
          });
          matchesBox.append(li);
        }
      }
      matchesBox.classList.remove('hidden');
    }).catch(() => { /* best-effort */ });
  }
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      clearTimeout(appSearchTimer);
      appSearchTimer = setTimeout(appSearch, 180);
    });
    searchInput.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') { searchInput.value = ''; clearMatches(); }
    });
  }
  async function addApp(entry) {
    const r = await api.addApp(entry);
    clearMatches();
    if (searchInput) searchInput.value = '';
    const err = $('app-error');
    if (err) err.classList.add('hidden');
    if (r && r.ok) {
      state.appBlocklist = r.appBlocklist;
      render();
    } else if (r && r.error) {
      showError('app-error', r.error);
    }
  }

  // FS Guard: pick workspace
  const pickBtn = $('fs-pick-btn');
  if (pickBtn) {
    pickBtn.addEventListener('click', async () => {
      pickBtn.disabled = true;
      const orig = pickBtn.textContent;
      pickBtn.textContent = 'Choosing…';
      try {
        const r = await api.pickWorkspace();
        if (r && r.ok) {
          const err = $('fs-error');
          if (err) err.classList.add('hidden');
        } else if (r && !r.cancelled && r.error) {
          showError('fs-error', r.error);
        }
      } finally {
        pickBtn.disabled = false;
        pickBtn.textContent = orig;
      }
    });
  }

  // FS Guard: path sanitizer tester
  const fsTestBtn = $('fs-test-btn');
  const fsTestInput = $('fs-test-input');
  const fsTestResult = $('fs-test-result');
  async function runFsTest() {
    if (!fsTestInput || !fsTestResult) return;
    const val = fsTestInput.value.trim();
    if (!val) { fsTestResult.classList.add('hidden'); return; }
    fsTestResult.classList.remove('hidden');
    fsTestResult.className = 'fs-test-result';
    fsTestResult.textContent = 'Checking…';
    try {
      const canon = await api.canonicalize(val);
      const check = await api.checkFsAccess({ path: val, op: 'read' });
      const canonicalStr = canon && canon.canonical ? canon.canonical : (check.canonical || val);
      if (check.allowed) {
        fsTestResult.classList.add('allowed');
        fsTestResult.innerHTML = '<strong>Allowed</strong> — <code>' + escapeHtml(canonicalStr) + '</code><br><span>' + escapeHtml(check.reason) + '</span>';
      } else {
        fsTestResult.classList.add('denied');
        fsTestResult.innerHTML = '<strong>Blocked</strong> — <code>' + escapeHtml(canonicalStr) + '</code><br><span>' + escapeHtml(check.reason) + (check.rule ? ' (' + escapeHtml(check.rule) + ')' : '') + '</span>';
      }
    } catch (err) {
      fsTestResult.classList.add('denied');
      fsTestResult.textContent = 'Error: ' + err.message;
    }
  }
  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  if (fsTestBtn) fsTestBtn.addEventListener('click', runFsTest);
  if (fsTestInput) fsTestInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runFsTest(); } });

  // Sandbox: clear
  const clearBtn = $('sandbox-clear');
  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      await api.clearSandboxEvents();
      const evEmpty = $('sandbox-empty');
      if (evEmpty) evEmpty.classList.remove('hidden');
      const evList = $('sandbox-events');
      if (evList) evList.textContent = '';
    });
  }

  api.onChange((s) => {
    state = s;
    // ensure defaults for new fields
    state.fsGuard = state.fsGuard || { mounts: [] };
    state.sandbox = state.sandbox || { profile: {}, events: [] };
    render();
  });

  startSandboxPoll();
}

document.addEventListener('DOMContentLoaded', init);
