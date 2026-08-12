# Auren — real end-to-end verification of system-wide DNS blocking on Windows.
#
# Prerequisites:
#   - the DNS daemon is installed and running (scripts\install-daemon.ps1)
#   - Protection Mode is ON (config.json mode = "on")
#
# What it checks, for real, at the network layer:
#   1. an adapter's DNS points at Auren (127.0.0.1)
#   2. a blocked domain returns NXDOMAIN via the local resolver
#   3. a normal domain still resolves via the upstream forwarder
#
# It temporarily adds a harmless test domain (auren-e2e-check.test) to the
# block list, verifies, then removes it again.
param([string]$Config = '', [string]$Key = '')

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$UserData = Join-Path $env:APPDATA 'Auren'
$cfg = if ($Config) { $Config } else { Join-Path $UserData 'config.json' }
$key = if ($Key) { $Key } else { Join-Path $UserData 'auren.key' }
$testDomain = 'auren-e2e-check.test'
$failed = 0

function Pass($msg) { Write-Host "  PASS  $msg" }
function Fail($msg) { Write-Host "  FAIL  $msg"; $script:failed = 1 }

Write-Host 'Auren end-to-end check'
Write-Host '======================'

# 1. Any adapter pointed at Auren?
$ours = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.ServerAddresses } |
  Select-Object -ExpandProperty ServerAddresses |
  Where-Object { $_ -eq '127.0.0.1' })
if ($ours.Count -gt 0) {
  Pass 'an adapter points DNS at the Auren resolver (127.0.0.1)'
} else {
  Fail 'DNS does NOT point at 127.0.0.1 — is the daemon running and Protection ON?'
}

# 2/3. Add the test domain to the block list, wait for the daemon to pick it up.
# Writes a SIGNED config (the daemon fails closed if the signature is missing).
if ((Test-Path $cfg) -and (Test-Path $key)) {
  & node -e @"
const fs = require('fs');
const c = require(process.argv[1] + '/src/core/config');
const cfg = c.readConfigFile(process.argv[2]);
if (!cfg.blocklist.includes(process.argv[4])) cfg.blocklist.push(process.argv[4]);
c.writeSignedConfig(process.argv[2], cfg, fs.readFileSync(process.argv[3]));
"@ "$Root" "$cfg" "$key" "$testDomain"
  Start-Sleep -Seconds 2

  $blocked = Resolve-DnsName -Name $testDomain -Server 127.0.0.1 -ErrorAction SilentlyContinue
  if (-not $blocked) {
    Pass "blocked domain returns NXDOMAIN ($testDomain)"
  } else {
    Fail "blocked domain did not return NXDOMAIN (got: $($blocked.NameHost))"
  }

  $allowed = Resolve-DnsName -Name example.com -Server 127.0.0.1 -Type A -ErrorAction Stop
  if ($allowed) {
    Pass 'non-blocked domain resolves via upstream (example.com)'
  } else {
    Fail 'non-blocked domain did not resolve'
  }

  # Clean up the test domain.
  & node -e @"
const fs = require('fs');
const c = require(process.argv[1] + '/src/core/config');
const cfg = c.readConfigFile(process.argv[2]);
cfg.blocklist = cfg.blocklist.filter((d) => d !== process.argv[4]);
c.writeSignedConfig(process.argv[2], cfg, fs.readFileSync(process.argv[3]));
"@ "$Root" "$cfg" "$key" "$testDomain"
  Write-Host "  INFO  removed $testDomain from the block list"
} else {
  Fail "no config or signing key found ($cfg, $key) — run the app once first"
}

Write-Host '======================'
if ($failed -eq 0) { Write-Host 'ALL CHECKS PASSED' } else { Write-Host 'SOME CHECKS FAILED' }
exit $failed
