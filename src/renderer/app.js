'use strict';

const api = window.auren;
const $ = (id) => document.getElementById(id);

let state = { mode: 'off', blocklist: [], appBlocklist: [], activity: [], onboardingDone: true, enforcement: false, platform: 'darwin', modeCooldownUntil: 0, degraded: false, terminalBlock: true, dohBlock: true, vmsDetected: [], settingsTampered: false, keystrokeShield: false, autoProtect: { enabled: true, engagedBy: [] } };
let busy = false;
let countdownTimer = null;

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
  el.textContent = msg;
  el.classList.remove('hidden');
}

const ICON_LINK = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M9.5 12a2.5 2.5 0 003.6 3.4l2.5-2.5a2.5 2.5 0 10-3.5-3.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><path d="M14.5 12a2.5 2.5 0 00-3.6-3.4l-2.5 2.5a2.5 2.5 0 103.5 3.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>';

const ICON_APP = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="3.5" stroke="currentColor" stroke-width="1.7"/><path d="M9 9.5h.01M14 9.5h.01M9 14.5h.01M14 14.5h.01" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>';

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
    label.textContent = 'Starting\u2026';
    shield.classList.add('warn');
  } else {
    pill.classList.add('off');
    label.textContent = 'Off';
    shield.classList.add('off');
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
  $('stat-sites').textContent = state.blocklist.length;
  $('stat-blocks').textContent = blocks;
  $('stat-gated').textContent = gated;
  $('stat-os').textContent = osBlocks;
  $('stat-apps').textContent = appBlocks;
  $('sites-count').textContent = state.blocklist.length;
  $('apps-count').textContent = (state.appBlocklist || []).length;
}

function render() {
  const on = state.mode === 'on';
  const cooldown = cooldownUntil();
  const inCooldown = cooldown > 0;
  const machine = state.platform === 'darwin' ? 'this Mac' : state.platform === 'win32' ? 'this PC' : 'this computer';
  const toggle = $('mode-toggle');
  toggle.checked = on;
  toggle.disabled = busy || inCooldown;

  $('degraded-banner').classList.toggle('hidden', !state.degraded);
  if (state.degraded && state.dnsConflict) {
    const who = state.dnsConflict.name
      ? state.dnsConflict.name + ' (pid ' + state.dnsConflict.pid + ')'
      : 'another process';
    $('degraded-text').textContent = 'Auren\u2019s DNS resolver could not start: ' + who + ' is already using port 53. Domain blocking is off until that process is stopped and protection is toggled. Auren is failing closed \u2014 nothing it gates will be allowed through in the meantime.';
  } else {
    $('degraded-text').textContent = 'Auren\u2019s background service isn\u2019t responding, so it can\u2019t verify that blocked sites are unreachable. Auren is failing closed \u2014 nothing it gates will be allowed through until the service recovers.';
  }

  const autoProtect = state.autoProtect || { enabled: true, engagedBy: [] };
  $('autoprotect-toggle').checked = !!autoProtect.enabled;
  const apEngaged = on && Array.isArray(autoProtect.engagedBy) && autoProtect.engagedBy.length > 0;
  $('autoprotect-banner').classList.toggle('hidden', !apEngaged);

  const shieldOn = !!state.keystrokeShield;
  $('keystroke-shield-badge').classList.toggle('hidden', !shieldOn);
  document.body.classList.toggle('keystroke-shield', shieldOn);

  const cd = $('cooldown-display');
  cd.classList.toggle('hidden', !inCooldown);
  if (inCooldown) {
    const secs = Math.max(1, Math.ceil((cooldown - Date.now()) / 1000));
    $('cooldown-count').textContent = secs;
  }

  updateStatusPill(on);

  $('mode-hint').textContent = inCooldown
    ? 'Verified. Sites stay blocked while you confirm \u2014 protection turns off in a moment.'
    : (state.degraded
        ? 'Auren can\u2019t verify its own enforcement right now, so it is failing closed: nothing it gates will be allowed through until the background service recovers.'
        : (on
            ? (state.enforcement
                ? (state.terminalBlock
                    ? 'Blocked sites are unreachable in every app and browser on ' + machine + '. Terminal and OS-level network access (ping, ssh, \u2026) is blocked too.' + (state.dohBlock ? ' Known DoH/DoT endpoints are blocked as well.' : '')
                    : 'Blocked sites are unreachable in every app and browser on ' + machine + '.')
                : 'Protection is ON, but ' + machine + ' isn\u2019t resolving through Auren yet. The background service may still be starting \u2014 if this persists, check Recent activity.')
            : 'Everything is reachable as usual. Flip the switch to start guarding.'));

  const vmOn = on && Array.isArray(state.vmsDetected) && state.vmsDetected.length > 0;
  const vmWarn = $('vm-warning');
  vmWarn.classList.toggle('hidden', !vmOn);
  if (vmOn) {
    vmWarn.textContent = 'Note: ' + state.vmsDetected.join(', ') + ' is running. VMs and containers use their own network stack, so Auren may not fully block traffic from inside them \u2014 see \u201cHonest limits\u201d in the README.';
  }

  const settingsWarn = $('settings-warning');
  settingsWarn.classList.toggle('hidden', !state.settingsTampered);
  if (state.settingsTampered) {
    settingsWarn.textContent = 'Your settings file failed verification, so protection is running on safe defaults. Review settings.json and restart auren.';
  }

    const list = $('block-list');
    list.textContent = '';
    $('block-empty').classList.toggle('hidden', state.blocklist.length > 0);
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

    const alist = $('app-block-list');
    alist.textContent = '';
    const blockedApps = state.appBlocklist || [];
    $('app-block-empty').classList.toggle('hidden', blockedApps.length > 0);
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


  const act = $('activity-list');
  act.textContent = '';
  const items = state.activity || [];
  $('activity-empty').classList.toggle('hidden', items.length > 0);
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

  renderStats();
  syncCountdown();
}

async function init() {
  state = await api.getState();
  render();

  // The shield badge claims "keystrokes hidden" via Secure Event Input, which
  // is macOS-only; on other platforms the honest claim is content protection.
  const badge = $('keystroke-shield-badge');
  if (state.platform !== 'darwin') {
    badge.title = "While Protection is on, auren's window can't be screen-captured, so nothing you type in auren ever appears in a recording.";
    $('ob-shield').textContent = 'While protection is on, auren hides your keystrokes: this window can\u2019t be captured on screen, so nothing you type here ever appears in a recording.';
  }

  if (state.platform !== 'darwin' && state.platform !== 'win32') {
    showError('mode-error', 'This build supports macOS and Windows. Other platforms are planned, not yet supported.');
    $('mode-toggle').disabled = true;
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

  $('mode-toggle').addEventListener('change', async (ev) => {
    if (busy) return;
    const wantOn = ev.target.checked;
    ev.target.checked = !wantOn;
    busy = true;
    render();
    try {
      const r = await api.setMode(wantOn ? 'on' : 'off');
      $('mode-error').classList.add('hidden');
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

  // Auto-protect: the toggle is instant and not busy-blocking (it only writes
  // settings.json), and a confirmed prompt engages protection like the toggle.
  $('autoprotect-toggle').addEventListener('change', async (ev) => {
    const enabled = ev.target.checked;
    await api.setAutoProtect({ enabled });
    state.autoProtect = Object.assign({}, state.autoProtect || {}, { enabled });
    render();
  });

  $('autoprotect-engage').addEventListener('click', async () => {
    $('autoprotect-prompt').classList.add('hidden');
    busy = true;
    render();
    try {
      await api.confirmAutoProtect();
    } finally {
      busy = false;
    }
  });

  $('autoprotect-dismiss').addEventListener('click', () => {
    $('autoprotect-prompt').classList.add('hidden');
  });

  api.onAutoProtectPrompt((tools) => {
    const names = Array.isArray(tools) && tools.length ? tools.join(', ') : 'AI tooling';
    $('autoprotect-prompt-tools').textContent = 'Turn protection on now (' + names + ')?';
    $('autoprotect-prompt').classList.remove('hidden');
  });

  $('add-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const input = $('domain-input');
    const value = input.value.trim();
    if (!value) return;
    const r = await api.addDomain(value);
    if (r && r.ok) {
      input.value = '';
      $('add-error').classList.add('hidden');
    } else if (r && r.error) {
      showError('add-error', r.error);
    }
  });

  // App search — the app card is search-as-you-type + pick, so there is no
  // form/submit. A stale in-flight search result must never overwrite a newer
  // one, so each input tick bumps a sequence and stale responses are dropped.
  let appSearchSeq = 0;
  let appSearchTimer = null;
  const searchInput = $('app-search-input');
  const matchesBox = $('app-matches');

  function clearMatches() {
    matchesBox.classList.add('hidden');
    matchesBox.textContent = '';
  }

  function appSearch() {
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
    }).catch(() => { /* search is best-effort */ });
  }

  searchInput.addEventListener('input', () => {
    clearTimeout(appSearchTimer);
    appSearchTimer = setTimeout(appSearch, 180);
  });
  searchInput.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') { searchInput.value = ''; clearMatches(); }
  });

  async function addApp(entry) {
    const r = await api.addApp(entry);
    clearMatches();
    searchInput.value = '';
    $('app-error').classList.add('hidden');
    if (r && r.ok) {
      state.appBlocklist = r.appBlocklist;
    } else if (r && r.error) {
      showError('app-error', r.error);
    }
  }

  api.onChange((s) => {
    state = s;
    render();
  });
}

document.addEventListener('DOMContentLoaded', init);
