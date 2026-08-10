'use strict';

const api = window.auren;
const $ = (id) => document.getElementById(id);

let state = { mode: 'off', blocklist: [], activity: [], onboardingDone: true, enforcement: false, platform: 'darwin', modeCooldownUntil: 0, degraded: false };
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
const ICON_BLOCK = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.7"/><path d="M5.6 5.6l12.8 12.8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>';
const ICON_TOGGLE = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3.5v8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M6.5 8.6a6.5 6.5 0 1011 0" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>';
const ICON_DAEMON = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3.5a8.5 8.5 0 11-8 11.3" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M3.5 15v-4.5H8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const ICON_GATE = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M8 14l5-5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M13 9h2.5v2.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><circle cx="14.5" cy="12" r="8" stroke="currentColor" stroke-width="1.5"/></svg>';

const KIND_TAG = { block: 'Blocked', toggle: 'Mode', agent: 'Gated', daemon: 'Service' };

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
  for (const e of items) {
    if (e.kind === 'block') blocks += 1;
    else if (e.kind === 'agent') gated += 1;
  }
  $('stat-sites').textContent = state.blocklist.length;
  $('stat-blocks').textContent = blocks;
  $('stat-gated').textContent = gated;
  $('sites-count').textContent = state.blocklist.length;
}

function render() {
  const on = state.mode === 'on';
  const cooldown = cooldownUntil();
  const inCooldown = cooldown > 0;
  const toggle = $('mode-toggle');
  toggle.checked = on;
  toggle.disabled = busy || inCooldown;

  $('degraded-banner').classList.toggle('hidden', !state.degraded);

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
                ? 'Blocked sites are unreachable in every app and browser on this Mac.'
                : 'Protection is ON, but this Mac isn\u2019t resolving through Auren yet. The background service may still be starting \u2014 if this persists, check Recent activity.')
            : 'Everything is reachable as usual. Flip the switch to start guarding.'));

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

  const act = $('activity-list');
  act.textContent = '';
  const items = state.activity || [];
  $('activity-empty').classList.toggle('hidden', items.length > 0);
  for (const e of items) {
    const li = document.createElement('li');
    const kind = e.kind || 'event';
    li.className = 'activity-item kind-' + kind;
    const icon = kind === 'block' ? ICON_BLOCK : kind === 'toggle' ? ICON_TOGGLE : kind === 'agent' ? ICON_GATE : ICON_DAEMON;
    li.innerHTML =
      '<span class="activity-marker">' + icon + '</span>' +
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

  if (state.platform !== 'darwin') {
    showError('mode-error', 'This build supports macOS. Other platforms are planned, not yet supported.');
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

  api.onChange((s) => {
    state = s;
    render();
  });
}

document.addEventListener('DOMContentLoaded', init);
