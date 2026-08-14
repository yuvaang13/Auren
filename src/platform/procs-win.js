/* Auren — procs-win.js
 *
 * Windows process listing for the daemon's app blocker and auto-protect.
 * PowerShell's Win32_Process exposes ExecutablePath, CommandLine and
 * ParentProcessId, which lets the shared matcher compare exact executable
 * paths and argv tokens just like macOS `ps` — and lets auto-protect walk
 * agent ancestry. ppid feeds ancestry; the app blocker ignores it.
 *
 * Record format is `PID<US>PPID<US>EXE<US>COMMANDLINE`, one per line, where
 * <US> is the unit-separator control char (0x1f) — CommandLine frequently
 * contains pipes, commas and equals signs, so a printable delimiter would
 * split it. CommandLine can also be null (system processes), which the parser
 * treats as "no tokens".
 *
 * Kill is `taskkill /PID n /F`.
 */

'use strict';
const { spawn, spawnSync } = require('child_process');

const US = String.fromCharCode(0x1f);

function psBin() {
  return process.env.AUREN_PS || 'powershell.exe';
}

function runPS(script) {
  try {
    const r = spawnSync(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    return { status: r.status ?? -1, stdout: (r.stdout || ''), stderr: (r.stderr || '') };
  } catch (err) {
    return { status: -1, stdout: '', stderr: err.message || String(err) };
  }
}

// Non-blocking PowerShell: the daemon's app-block scan runs on the same event
// loop that answers DNS, and a synchronous CIM query would stall every lookup
// that arrives while it runs. `spawn` keeps the loop free.
function runPSAsync(script) {
  return new Promise((resolve) => {
    const child = spawn(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { err += c; });
    child.on('error', () => resolve({ status: -1, stdout: '', stderr: 'spawn failed' }));
    child.on('close', (code) => resolve({ status: code ?? -1, stdout: out, stderr: err }));
  });
}

// Tokenize a command line keeping quoted groups intact ("C:\Program Files\...").
function tokenize(cmd) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(cmd))) {
    out.push(m[1] != null ? m[1] : (m[2] != null ? m[2] : m[3]));
  }
  return out;
}

function parseLine(line) {
  const parts = String(line || '').split(US);
  let pid;
  let ppid = null;
  let exe;
  let cmd;
  if (parts.length >= 4) {
    pid = parseInt(parts[0], 10);
    ppid = parseInt(parts[1], 10);
    exe = String(parts[2] || '').trim();
    cmd = parts[3];
  } else {
    pid = parseInt(parts[0], 10);
    exe = String(parts[1] || '').trim();
    cmd = parts[2];
  }
  if (!Number.isFinite(pid) || pid <= 0) return null;
  const tokens = tokenize(String(cmd || ''));
  if (!exe && tokens.length === 0) return null;
  const rec = { pid, exe, tokens };
  if (Number.isFinite(ppid) && ppid > 0) rec.ppid = ppid;
  return rec;
}

function listCmd() {
  return 'Get-CimInstance Win32_Process | ForEach-Object { '
    + '$p = if ($_.ExecutablePath) { $_.ExecutablePath } else { "" }; '
    + '$c = if ($_.CommandLine) { $_.CommandLine } else { "" }; '
    + '"' + '{0}' + US + '{1}' + US + '{2}' + US + '{3}' + '" -f $_.ProcessId, $_.ParentProcessId, $p, $c }';
}

function parseList(stdout) {
  return String(stdout || '')
    .split(/\r?\n/)
    .map(parseLine)
    .filter(Boolean);
}

// Blocking snapshot for cached, occasional callers only — never the daemon's
// hot path (see runPSAsync note).
function listSync() {
  const r = runPS(listCmd());
  if (r.status !== 0) return null;
  return parseList(r.stdout);
}

// [{ pid, ppid, exe, tokens }, ...] or null when the query itself fails.
// Never blocks the event loop.
function list() {
  return runPSAsync(listCmd()).then((r) => (r.status !== 0 ? null : parseList(r.stdout)));
}

function kill(pid) {
  return new Promise((resolve) => {
    const child = spawn('taskkill', ['/PID', String(pid), '/F'], { stdio: ['ignore', 'ignore', 'pipe'] });
    let err = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (c) => { err += c; });
    child.on('error', (e) => resolve({ ok: false, error: e.message || String(e) }));
    child.on('close', (code) => resolve({ ok: code === 0, error: code === 0 ? '' : err.trim() }));
  });
}

module.exports = { list, listSync, kill, listCmd, parseLine, US };
