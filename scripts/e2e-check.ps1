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
# Plus the HTTPS/SNI blocking layer (daemon v16+):
#   4. the loopback proxy serves the PAC at http://127.0.0.1:42792/proxy.pac
#   5. WinINET is pointed at that PAC (AutoConfigURL) so browsers route HTTPS
#      through the proxy
#   6. a blocked domain's HTTPS CONNECT is refused with 403 by the proxy
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

  # 4. The loopback proxy serves the PAC (daemon v16+).
  $pac = 'http://127.0.0.1:42792/proxy.pac'
  try {
    $pacBody = (Invoke-WebRequest -Uri $pac -TimeoutSec 3 -UseBasicParsing).Content
    if ($pacBody -match 'FindProxyForURL' -and $pacBody -match 'PROXY 127\.0\.0\.1:42792') {
      Pass "HTTPS proxy serves the PAC at $pac"
    } else {
      Fail "HTTPS proxy PAC at $pac has the wrong content"
    }
  } catch {
    Fail "HTTPS proxy PAC not served at $pac — is the v16 daemon running with Protection ON?"
  }

  # 5. WinINET is pointed at the PAC for the current user.
  $inet = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  $autoUrl = (Get-ItemProperty -Path $inet -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
  if ($autoUrl -eq $pac) {
    Pass "WinINET proxy points at the Auren PAC ($pac)"
  } else {
    Fail "WinINET AutoConfigURL is not $pac (got: $autoUrl) — Protection may be off"
  }

  # 6. HTTPS CONNECT to the blocked domain is refused by the proxy.
  $connectOut = & curl.exe -sS -m 5 -x "http://127.0.0.1:42792" "https://$testDomain/" 2>&1
  if ($connectOut -match '403') {
    Pass "HTTPS CONNECT to $testDomain refused with 403 by the proxy"
  } else {
    Fail "HTTPS CONNECT to $testDomain was not refused: $($connectOut | Select-Object -Last 1)"
  }
  $allowedCode = & curl.exe -s -m 10 -x "http://127.0.0.1:42792" -o NUL -w '%{http_code}' "https://example.com/" 2>$null
  if ($allowedCode -eq '200' -or $allowedCode -eq '301' -or $allowedCode -eq '302') {
    Pass "HTTPS through the proxy still works (example.com -> HTTP $allowedCode)"
  } else {
    Fail "HTTPS through the proxy failed for a non-blocked domain (HTTP $allowedCode)"
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
