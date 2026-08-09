'use strict';

const api = window.auren;
const $ = (id) => document.getElementById(id);

let state = { mode: 'off', blocklist: [], activity: [], onboardingDone: true, enforcement: false, platform: 'darwin' };
let busy = false;

function showError(id, msg) {
  const el = $(id);
  el.textContent = msg;
  el.classList.remove('hidden');
}

const ICON_LINK = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M9.5 12a2.5 2.5 0 003.6 3.4l2.5-2.5a2.5 2.5 0 10-3.5-3.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><path d="M14.5 12a2.5 2.5 0 00-3.6-3.4l-2.5 2.5a2.5 2.5 0 103.5 3.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const ICON_BLOCK = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.7"/><path d="M5.6 5.6l12.8 12.8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>';
const ICON_TOGGLE = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3.5v8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M6.5 8.6a6.5 6.5 0 1011 0" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>';
const ICON_DAEMON = '<svg class="row-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3.5a8.5 8.5 0 11-8 11.3" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M3.5 15v-4.5H8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function updateStatusPill(on) {
  const pill = $('status-pill');
  const label = $('status-label');
  pill.classList.remove('on', 'off', 'warn');
  if (on && state.enforcement) {
    pill.classList.add('on');
    label.textContent = 'Protected';
  } else if (on) {
    pill.classList.add('warn');
    label.textContent = 'Starting\u2026';
  } else {
    pill.classList.add('off');
    label.textContent = 'Off';
  }
}

function render() {
  const on = state.mode === 'on';
  const toggle = $('mode-toggle');
  toggle.checked = on;
  toggle.disabled = busy;

  updateStatusPill(on);

  $('mode-hint').textContent = on
    ? (state.enforcement
        ? 'Protection is ON. Blocked sites are unreachable in every app and browser on this Mac.'
        : 'Protection is ON, but this Mac isn\u2019t resolving through Auren yet. The background service may still be starting \u2014 if this persists, check Recent activity.')
    : 'Protection is OFF. Everything is reachable as usual.';

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
    li.innerHTML =
      (kind === 'block' ? ICON_BLOCK : kind === 'toggle' ? ICON_TOGGLE : ICON_DAEMON) +
      '<span class="activity-text"></span>';
    li.querySelector('.activity-text').textContent = e.text || e.note || e.outcome || e.domain || '';
    act.append(li);
  }
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
