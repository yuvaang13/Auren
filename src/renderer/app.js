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

function render() {
  const on = state.mode === 'on';
  const toggle = $('mode-toggle');
  toggle.checked = on;
  toggle.disabled = busy;

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
    const span = document.createElement('span');
    span.textContent = d;
    const btn = document.createElement('button');
    btn.className = 'remove-btn';
    btn.textContent = '\u00d7';
    btn.setAttribute('aria-label', 'Remove ' + d);
    btn.addEventListener('click', () => api.removeDomain(d));
    li.append(span, btn);
    list.append(li);
  }

  const act = $('activity-list');
  act.textContent = '';
  const items = state.activity || [];
  $('activity-empty').classList.toggle('hidden', items.length > 0);
  for (const e of items) {
    const li = document.createElement('li');
    li.textContent = e.text || e.note || e.outcome || e.domain || '';
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
