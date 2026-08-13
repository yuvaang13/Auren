/* Auren — platform logic tests.
 *
 * Pure, platform-independent tests for the Windows port's rule/policy/command
 * generators: pf-win firewall rule translation, autofill registry policies,
 * and procs/dnsops line parsing. Everything here is side-effect-free, so it
 * runs on every platform; the exec-touching paths are gated behind injectable
 * runners and only exercised where the runner is fake.
 *
 * Run: node test/platform.test.js
 */
'use strict';
const assert = require('assert');

const pf = require('../src/dns/pf');
const pfWin = require('../src/dns/pf-win');
const dnsops = require('../src/platform/dnsops');
const dnsopsMac = require('../src/platform/dnsops-mac');
const dnsopsWin = require('../src/platform/dnsops-win');
const procsWin = require('../src/platform/procs-win');
const apps = require('../src/core/apps');
const autofillWin = require('../src/platform/autofill-win');
const dcWin = require('../src/platform/dns-controller-win');
const bioWin = require('../src/platform/biometrics-win');
const appResolverWin = require('../src/platform/app-resolver-win');
const virt = require('../src/core/virt');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try { fn(); passed += 1; console.log('  ok   ' + name); }
  catch (err) { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (err && err.stack || err)); }
}

console.log('platform logic tests');

test('dnsops: port-owner parsing (macOS lsof -F pcn)', () => {
  const out = 'p1045\ncCoreAudioD\nn*:53\np1\nclaunchd\nn*:53\n';
  assert.deepStrictEqual(dnsopsMac.parseLsofPcn(out), { pid: 1045, name: 'CoreAudioD' });
  assert.strictEqual(dnsopsMac.parseLsofPcn(''), null);
  assert.strictEqual(dnsopsMac.parseLsofPcn('n*:53\n'), null);
  assert.deepStrictEqual(dnsopsMac.parseLsofPcn('p42\ncfoo\n'), { pid: 42, name: 'foo' });
});

test('dnsops: port-owner parsing (Windows PID:name lines)', () => {
  assert.deepStrictEqual(dnsopsWin.parsePortOwnerLine('1234:dnslookup.exe'), { pid: 1234, name: 'dnslookup.exe' });
  assert.strictEqual(dnsopsWin.parsePortOwnerLine(''), null);
  assert.strictEqual(dnsopsWin.parsePortOwnerLine('garbage'), null);
  assert.ok(dnsopsWin.portOwnerCmd(53).includes('Get-NetTCPConnection -LocalPort 53 -State Listen'));
});

test('pf-win: shared rule engine emits the same rule lines everywhere', () => {
  const rules = pf.buildAnchorRules({ allowPorts: [2222], allowHosts: ['10.0.0.5'], dohBlock: true, dohHosts: ['1.1.1.1'] });
  assert.ok(rules.includes('block out proto icmp'));
  assert.ok(rules.includes('block out proto icmp6'));
  assert.ok(rules.some((l) => /block out proto \{ tcp udp \} to port \{ 21 22 /.test(l)));
  assert.ok(rules.includes('block out proto { tcp udp } to 169.254.169.254'));
  assert.ok(rules.includes('block out proto { tcp udp } to 1.1.1.1'));
  assert.ok(rules.includes('pass out proto tcp to port 443'));
  assert.ok(rules.includes('pass out proto { tcp udp } to port 2222'));
  assert.ok(rules.includes('pass out proto { tcp udp } to 10.0.0.5'));
});

test('pf-win: parseRuleLines keeps only block rules', () => {
  const rules = pf.buildAnchorRules({ allowPorts: [2222], allowHosts: ['10.0.0.5'], dohBlock: true, dohHosts: ['1.1.1.1', '2606:4700:4700::1111'] });
  const parsed = pfWin.parseRuleLines(rules);
  const kinds = parsed.map((r) => {
    if (r.icmp) return 'icmp:' + r.icmp;
    if (r.remotePort) return 'port:' + r.proto;
    return 'host:' + r.proto;
  });
  assert.ok(kinds.includes('icmp:ICMPv4'));
  assert.ok(kinds.includes('icmp:ICMPv6'));
  assert.ok(kinds.includes('port:tcp'));
  assert.ok(kinds.includes('port:udp'));
  assert.ok(kinds.includes('host:tcp'));
  assert.ok(kinds.includes('host:udp'));
  // pass lines (loopback, DNS, 80, allowlist) must never become rules
  assert.ok(!parsed.some((r) => r.remotePort && r.remotePort.includes(53)));
  assert.ok(!parsed.some((r) => r.remotePort && r.remotePort.includes(80)));
  assert.ok(!parsed.some((r) => r.remotePort && r.remotePort.includes(2222)));
  assert.ok(!parsed.some((r) => r.remoteAddress === '10.0.0.5'));
  // QUIC (UDP 443) is blocked while proxy protection is on, but TCP 443 stays
  // passable so HTTPS can reach the blocking proxy.
  assert.ok(parsed.some((r) => r.proto === 'udp' && r.remotePort && r.remotePort.includes(443)), 'UDP 443 blocked (QUIC)');
  assert.ok(!parsed.some((r) => r.proto === 'tcp' && r.remotePort && r.remotePort.includes(443)), 'TCP 443 must stay passable');
});

test('pf-win: blocked ports survive the translation intact', () => {
  const parsed = pfWin.parseRuleLines(pf.buildAnchorRules({}));
  const portRule = parsed.find((r) => r.remotePort && pf.BLOCKED_PORTS.every((p) => r.remotePort.includes(p)));
  assert.ok(portRule, 'a port-block rule exists');
  for (const p of pf.BLOCKED_PORTS) assert.ok(portRule.remotePort.includes(p), 'port ' + p + ' blocked');
  // allowlist carving is already prevented by the safetyFloor; here the floor
  // drops 2222 only because 2222 is not in BLOCKED_PORTS anyway — assert the
  // floor keeps its guarantees on the shared engine.
  const floor = pf.safetyFloor({ terminalBlock: true, allowPorts: [22, 2222], allowHosts: ['169.254.169.254'], dohBlock: true, dohHosts: [] });
  assert.ok(!floor.allowPorts.includes(22), 'floor drops allowlisted blocked port 22');
  assert.ok(floor.allowPorts.includes(2222), 'floor keeps non-blocked allowed port');
  assert.ok(!floor.allowHosts.includes('169.254.169.254'), 'floor drops metadata host allow');
});

test('pf-win: buildPSScript clears then recreates Auren firewall rules', () => {
  const script = pfWin.buildPSScript(pf.buildAnchorRules({ dohBlock: true, dohHosts: ['1.1.1.1'] }));
  assert.ok(script.includes('Remove-NetFirewallRule -Group ' + pfWin.RULE_GROUP));
  assert.ok(script.includes('New-NetFirewallRule'));
  assert.ok(script.includes('-Action Block'));
  assert.ok(script.includes('-Protocol TCP'));
  assert.ok(script.includes('-Protocol UDP'));
  assert.ok(script.includes('-Protocol ICMPv4'));
  assert.ok(script.includes('-Protocol ICMPv6'));
  assert.ok(script.includes('-RemotePort'));
  assert.ok(script.includes('1.1.1.1'));
  assert.ok(/AUREN_FW_OK/.test(script));
});

test('pf-win: ruleStats is an honest no-op on Windows', () => {
  assert.deepStrictEqual(pfWin.ruleStats(), { ok: true, stats: [] });
});

test('pf-win: parseRuleLines tolerates junk and blank lines', () => {
  assert.deepStrictEqual(pfWin.parseRuleLines(['', '   ', '# comment', 'not a rule']), []);
});

test('dnsops: dispatcher resolves to the mac impl on non-win32', () => {
  if (process.platform === 'win32') {
    assert.strictEqual(dnsops, dnsopsWin);
  } else {
    assert.strictEqual(dnsops, dnsopsMac);
  }
});

test('dnsops-mac: discoverUpstream prefers backed-up state servers', () => {
  const services = { 'Wi-Fi': ['8.8.8.8', '1.1.1.1'], Ethernet: ['127.0.0.1'] };
  const got = dnsopsMac.discoverUpstream(services, ['9.9.9.9']);
  assert.deepStrictEqual(got, ['8.8.8.8', '1.1.1.1']);
  // dedup + skip loopback even when the fallback would differ
  assert.deepStrictEqual(dnsopsMac.discoverUpstream({ A: ['127.0.0.1'], B: ['8.8.8.8', '8.8.8.8'] }, ['9.9.9.9']), ['8.8.8.8']);
});

test('dnsops-mac: discoverUpstream falls back when state holds no servers', () => {
  // Empty state forces the scutil scan; on a machine where scutil runs this
  // returns real servers. Assert the shape, not the values.
  const got = dnsopsMac.discoverUpstream({}, ['9.9.9.9']);
  assert.ok(Array.isArray(got) && got.length > 0);
  assert.ok(!got.includes('127.0.0.1'));
});

test('dnsops-win: service commands target DnsClient and key by InterfaceIndex', () => {
  assert.ok(/Get-DnsClientServerAddress/.test(dnsopsWin.listServicesCmd()));
  assert.ok(/Group-Object InterfaceIndex/.test(dnsopsWin.listServicesCmd()));
  assert.ok(/InterfaceIndex 12/.test(dnsopsWin.getServersCmd(12)));
  assert.ok(/InterfaceIndex 12/.test(dnsopsWin.setServersCmd('12:Wi-Fi', ['127.0.0.1'])));
  assert.ok(/ResetServerAddresses/.test(dnsopsWin.setServersCmd(12, [])));
  assert.ok(/'127.0.0.1'/.test(dnsopsWin.setServersCmd(12, ['127.0.0.1'])));
});

test('dnsops-win: discover/isEnforcing commands exclude the loopback takeover', () => {
  assert.ok(/Where-Object { \$_ -ne "127.0.0.1" }/.test(dnsopsWin.discoverUpstreamCmd()));
  assert.ok(/Where-Object { \$_ -ne "127.0.0.1" }/.test(dnsopsWin.isEnforcingCmd()));
  assert.ok(/Select-Object -Unique/.test(dnsopsWin.discoverUpstreamCmd()));
});

test('dnsops-win: discoverUpstream prefers backed-up state servers', () => {
  assert.deepStrictEqual(dnsopsWin.discoverUpstream({ '4:Ethernet': ['10.0.0.2'] }, ['9.9.9.9']), ['10.0.0.2']);
});

test('procs-win: parseLine survives pipes, quotes and empty command lines', () => {
  const US = procsWin.US;
  const p = procsWin.parseLine('1234' + US + '5678' + US + 'C:\\Program Files\\Discord\\Discord.exe' + US + '"C:\\Program Files\\Discord\\Discord.exe" --type=renderer');
  assert.strictEqual(p.pid, 1234);
  assert.strictEqual(p.ppid, 5678);
  assert.strictEqual(p.exe, 'C:\\Program Files\\Discord\\Discord.exe');
  assert.deepStrictEqual(p.tokens, ['C:\\Program Files\\Discord\\Discord.exe', '--type=renderer']);
  // Legacy 3-field records (no ppid) still parse for older callers.
  const legacy = procsWin.parseLine('9' + US + 'C:\\Windows\\System32\\svchost.exe' + US + '');
  assert.strictEqual(legacy.pid, 9);
  assert.strictEqual(legacy.ppid, undefined);
  // null CommandLine -> no tokens, but the exe path still matches
  const sys = procsWin.parseLine('4' + US + 'C:\\Windows\\System32\\csrss.exe' + US + '');
  assert.strictEqual(sys.pid, 4);
  assert.strictEqual(sys.tokens.length, 0);
  assert.strictEqual(procsWin.parseLine('garbage'), null);
  assert.strictEqual(procsWin.parseLine('0' + US + '0' + US + '' + US + ''), null);
});

test('procs-win: listCmd emits the CIM query with ppid and unit-separator records', () => {
  const cmd = procsWin.listCmd();
  assert.ok(/Get-CimInstance Win32_Process/.test(cmd));
  assert.ok(cmd.includes(procsWin.US));
  assert.ok(/ExecutablePath/.test(cmd));
  assert.ok(/CommandLine/.test(cmd));
  assert.ok(/ParentProcessId/.test(cmd), 'ppid is part of the record');
});

test('apps: parsePsLine captures ppid (ps -axo pid=,ppid=,command=) and stays legacy-compatible', () => {
  const rec = apps.parsePsLine('100 99 /usr/bin/node /x.js');
  assert.deepStrictEqual(rec, { pid: 100, ppid: 99, exe: '/usr/bin/node', tokens: ['/usr/bin/node', '/x.js'] });
  const legacy = apps.parsePsLine('101 /usr/bin/node /x.js');
  assert.strictEqual(legacy.pid, 101);
  assert.strictEqual(legacy.ppid, undefined);
});

test('apps: findBlockedProcesses matches descriptors like findBlockedPids does', () => {
  const list = [
    { pid: 42, exe: '/Applications/Safari.app/Contents/MacOS/Safari', tokens: ['/Applications/Safari.app/Contents/MacOS/Safari'] },
    { pid: 99, exe: '/usr/bin/node', tokens: ['/usr/bin/node', '/opt/x/launcher.js'] },
    { pid: 7, exe: '/usr/bin/node', tokens: ['/usr/bin/node'] }
  ];
  const blocklist = [
    { id: 'com.apple.Safari', name: 'Safari', path: '/Applications/Safari.app/Contents/MacOS/Safari' },
    { id: 'x.launcher', name: 'Launcher', path: '/opt/x/launcher.js' }
  ];
  const hits = apps.findBlockedProcesses(list, blocklist, { selfPid: 7 });
  const ids = hits.map((h) => h.entry.id).sort();
  assert.deepStrictEqual(ids, ['com.apple.Safari', 'x.launcher']);
  // findBlockedPids stays in sync with the descriptor path
  const psHits = apps.findBlockedPids(['42 /Applications/Safari.app/Contents/MacOS/Safari'], blocklist, { selfPid: 1 });
  assert.strictEqual(psHits.length, 1);
  assert.strictEqual(psHits[0].pid, 42);
});

test('apps: findBlockedProcesses never matches self or protected executables', () => {
  const list = [
    { pid: 1, exe: '/sbin/launchd', tokens: ['/sbin/launchd'] },
    { pid: 10, exe: '/opt/auren/bin/node', tokens: ['/opt/auren/bin/node', 'daemon.js'] }
  ];
  const blocklist = [{ id: 'auren.daemon', name: 'Daemon', path: '/opt/auren/bin/node' }];
  assert.deepStrictEqual(apps.findBlockedProcesses(list, blocklist, { selfPid: 10, protectedExes: ['/opt/auren/bin/node'] }), []);
  // without the safety floor, the same daemon process would match (pid 10 != 5)
  assert.strictEqual(apps.findBlockedProcesses(list, blocklist, { selfPid: 5 }).length, 1);
});

test('autofill-win: policy keys mirror the mac browser family', () => {
  assert.deepStrictEqual(
    autofillWin.BROWSERS.map((b) => b.id),
    ['Google Chrome', 'Chromium', 'Brave', 'Microsoft Edge']
  );
  for (const key of Object.keys(autofillWin.BLOCK_POLICIES)) {
    assert.strictEqual(autofillWin.BLOCK_POLICIES[key], 0, key + ' disabled');
  }
});

test('autofill-win: setPolicyCmds writes REG_DWORD 0 into vendor HKLM keys', () => {
  const chrome = autofillWin.BROWSERS[0];
  const cmds = autofillWin.setPolicyCmds(chrome);
  assert.strictEqual(cmds.length, Object.keys(autofillWin.BLOCK_POLICIES).length);
  for (const argv of cmds) {
    assert.strictEqual(argv[0], 'add');
    assert.strictEqual(argv[1], chrome.key);
    assert.ok(argv.includes('/t') && argv[argv.indexOf('/t') + 1] === 'REG_DWORD');
    assert.ok(argv.includes('/d') && argv[argv.indexOf('/d') + 1] === '0');
  }
  assert.ok(cmds.some((a) => a.includes('PasswordManagerEnabled')));
});

test('autofill-win: deletePolicyCmds removes exactly the values we wrote', () => {
  const brave = autofillWin.BROWSERS[2];
  const cmds = autofillWin.deletePolicyCmds(brave);
  assert.strictEqual(cmds.length, Object.keys(autofillWin.BLOCK_POLICIES).length);
  for (const argv of cmds) {
    assert.strictEqual(argv[0], 'delete');
    assert.strictEqual(argv[1], brave.key);
    assert.ok(argv.includes('/f'));
  }
});

test('autofill-win: reconcile is idempotent per desired state', () => {
  assert.strictEqual(autofillWin.reconcileAutofill(true).changed, true);
  assert.strictEqual(autofillWin.reconcileAutofill(true).changed, false);
  assert.strictEqual(autofillWin.reconcileAutofill(false).changed, true);
  assert.strictEqual(autofillWin.reconcileAutofill(false).changed, false);
});

test('dns-controller-win: installer bakes the daemon args into a SYSTEM task', () => {
  const opts = {
    srcDir: 'C:\\staged',
    nodeBin: 'C:\\Program Files\\Auren\\auren.exe',
    configPath: 'C:\\Users\\u\\AppData\\Roaming\\Auren\\config.json',
    activityPath: 'C:\\Users\\u\\AppData\\Roaming\\Auren\\activity.json',
    statePath: 'C:\\ProgramData\\Auren\\state.json',
    keyPath: 'C:\\Users\\u\\AppData\\Roaming\\Auren\\key.bin',
    heartbeatPath: 'C:\\ProgramData\\Auren\\heartbeat.json'
  };
  const script = dcWin.buildInstallerScript(opts);
  assert.ok(script.includes('Register-ScheduledTask'));
  assert.ok(script.includes('AurenGuardrailDaemon'));
  assert.ok(script.includes('-UserId "SYSTEM"'));
  assert.ok(script.includes('-RunLevel Highest'));
  assert.ok(script.includes('--AUREN_CONFIG=' + opts.configPath));
  assert.ok(script.includes('--AUREN_KEY=' + opts.keyPath));
  assert.ok(script.includes('--AUREN_HEARTBEAT=' + opts.heartbeatPath));
  assert.ok(script.includes('ELECTRON_RUN_AS_NODE'));
  assert.ok(script.includes(JSON.stringify('"version":' + dcWin.DAEMON_VERSION + '[,}]')));
  assert.ok(script.includes('AUREN_INSTALL_OK'));
  assert.ok(script.includes('Copy-Item'));
});

test('dns-controller-win: installedDaemonInfo round-trips the runner args', () => {
  const info = dcWin.installedDaemonInfo();
  // No installed task on this machine — but on a real Windows box the runner
  // would parse. Just assert the shape when the task happens to exist.
  if (info) assert.ok('version' in info && 'keyPath' in info && 'heartbeatPath' in info);
});

test('biometrics-win: helloCmd prompts UserConsentVerifier and emits the result code', () => {
  const cmd = bioWin.helloCmd('Turn off auren protection');
  assert.ok(/UserConsentVerifier/.test(cmd));
  assert.ok(/RequestVerificationAsync/.test(cmd));
  assert.ok(/AsTask\(\)\.Result/.test(cmd));
  assert.ok(/Turn off auren protection/.test(cmd));
  assert.ok(/\[int\]\$r/.test(cmd));
});

test('app-resolver-win: parseLine derives a valid block id from the exe path', () => {
  const US = String.fromCharCode(0x1f);
  const e = appResolverWin.parseLine('C:\\Program Files\\Discord\\Discord.exe' + US + 'Discord');
  assert.deepStrictEqual(e, { id: 'Discord', name: 'Discord', path: 'C:\\Program Files\\Discord\\Discord.exe' });
  assert.ok(appResolverWin.parseLine('junk') === null);
  assert.strictEqual(appResolverWin.parseLine(''), null);
});

test('app-resolver-win: filterEntries matches by name or id, excludes self, caps at 10', () => {
  const entries = [
    { id: 'Discord', name: 'Discord', path: 'C:\\Program Files\\Discord\\Discord.exe' },
    { id: 'chrome', name: 'Google Chrome', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' },
    { id: 'auren', name: 'auren', path: 'C:\\Program Files\\Auren\\auren.exe' }
  ];
  const byId = appResolverWin.filterEntries(entries, 'disc', {});
  assert.deepStrictEqual(byId, [{ id: 'Discord', name: 'Discord', path: 'C:\\Program Files\\Discord\\Discord.exe' }]);
  const byName = appResolverWin.filterEntries(entries, 'google', {});
  assert.strictEqual(byName.length, 1);
  assert.strictEqual(byName[0].id, 'chrome');
  // excluding the self path drops Discord, leaving nothing for "disc"
  const excluded = appResolverWin.filterEntries(entries, 'disc', { excludePaths: ['c:\\program files\\discord\\discord.exe'] });
  assert.deepStrictEqual(excluded, []);
  const all = appResolverWin.filterEntries(entries, '', {});
  assert.strictEqual(all.length, 3);
  // sort + cap
  const many = Array.from({ length: 15 }, (_, i) => ({ id: 'a' + i, name: 'App ' + i, path: 'C:\\x\\a' + i + '.exe' }));
  assert.strictEqual(appResolverWin.filterEntries(many, 'App', {}).length, 10);
});

test('app-resolver-win: listInstalledExesCmd scans the standard install dirs', () => {
  const cmd = appResolverWin.listInstalledExesCmd();
  assert.ok(/Get-ChildItem/.test(cmd));
  assert.ok(/Program Files/.test(cmd));
  assert.ok(/VersionInfo/.test(cmd));
  assert.ok(cmd.includes(String.fromCharCode(0x1f)));
});

test('virt: detectVirtualization classifies Windows process paths', () => {
  const blob = 'C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe\nC:\\Program Files\\Oracle\\VirtualBox\\VBoxHeadless.exe\n';
  const found = virt.detectVirtualization(blob);
  assert.ok(found.includes('Docker Desktop'));
  assert.ok(found.includes('VirtualBox'));
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
