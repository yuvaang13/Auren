/* Auren — procs-win.js
 *
 * Windows process listing for the daemon's app blocker. PowerShell's
 * Win32_Process exposes ExecutablePath and CommandLine, which lets the shared
 * matcher compare exact executable paths and argv tokens just like macOS `ps`.
 *
 * Record format is `PID<US>EXE<US>COMMANDLINE`, one per line, where <US> is the
 * unit-separator control char (0x1f) — CommandLine frequently contains pipes,
 * commas and equals signs, so a printable delimiter would split it. CommandLine
 * can also be null (system processes), which the parser treats as "no tokens".
 *
 * Kill is `taskkill /PID n /F`.
 */

'use strict';
const { spawnSync } = require('child_process');

const US = String.fromCharCode(0x1f);

function psBin() {
  return process.env.AUREN_PS || 'powershell.exe';
}

function runPS(script) {
  const r = spawnSync(psBin(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  return { status: r.status, stdout: (r.stdout || ''), stderr: (r.stderr || '') };
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

// Pure parser, unit-testable without PowerShell.
function parseLine(line) {
  const parts = String(line || '').split(US);
  const pid = parseInt(parts[0], 10);
  if (!Number.isFinite(pid) || pid <= 0) return null;
  const exe = String(parts[1] || '').trim();
  const tokens = tokenize(String(parts[2] || ''));
  if (!exe && tokens.length === 0) return null;
  return { pid, exe, tokens };
}

function listCmd() {
  return 'Get-CimInstance Win32_Process | ForEach-Object { '
    + '$p = if ($_.ExecutablePath) { $_.ExecutablePath } else { "" }; '
    + '$c = if ($_.CommandLine) { $_.CommandLine } else { "" }; '
    + '"{0}' + US + '{1}' + US + '{2}" -f $_.ProcessId, $p, $c }';
}

// [{ pid, exe, tokens }, ...] or null when the query itself fails.
function list() {
  const r = runPS(listCmd());
  if (r.status !== 0) return null;
  return String(r.stdout || '')
    .split(/\r?\n/)
    .map(parseLine)
    .filter(Boolean);
}

function kill(pid) {
  const r = spawnSync('taskkill', ['/PID', String(pid), '/F'], { encoding: 'utf8' });
  return { ok: r.status === 0, error: r.status === 0 ? '' : String(r.stderr || '').trim() };
}

module.exports = { list, kill, listCmd, parseLine, US };
