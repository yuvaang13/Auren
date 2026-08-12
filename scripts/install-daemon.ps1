# Install or update the Auren DNS daemon (a SYSTEM Scheduled Task).
#
# Run as Administrator, or let the script re-launch itself elevated (UAC):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-daemon.ps1
#
# The daemon then runs persistently with SYSTEM privileges and starts/stops DNS
# interception based on config.json (mode + block list) — no per-toggle admin
# needed.
#
# Overrides (all optional):
#   -NodeBin <node or electron exe>   interpreter to run daemon.js with
#   -Config / -Key / -Heartbeat / -Activity / -State
#                                     paths for the shared config, state and logs
param(
  [string]$NodeBin = '',
  [string]$Config = '',
  [string]$Key = '',
  [string]$Heartbeat = '',
  [string]$Activity = '',
  [string]$State = ''
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$UserData = Join-Path $env:APPDATA 'Auren'
$Spool = Join-Path $env:ProgramData 'Auren'

$node = $NodeBin
if (-not $node) { $node = (Get-Command node -ErrorAction SilentlyContinue).Source }
if (-not $node) { throw 'No node found on PATH. Pass -NodeBin.' }

$cfg = if ($Config) { $Config } else { Join-Path $UserData 'config.json' }
$key = if ($Key) { $Key } else { Join-Path $UserData 'auren.key' }
$hb  = if ($Heartbeat) { $Heartbeat } else { Join-Path $Spool 'heartbeat.json' }
$act = if ($Activity) { $Activity } else { Join-Path $UserData 'activity.jsonl' }
$st  = if ($State) { $State } else { Join-Path $Spool 'state.json' }

# Re-launch elevated when not already running as Administrator.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  $scriptArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
  foreach ($p in $MyInvocation.BoundParameters.GetEnumerator()) {
    if ($p.Value) { $scriptArgs += ('-{0}' -f $p.Key); $scriptArgs += ('"{0}"' -f $p.Value) }
  }
  $proc = Start-Process powershell -Verb RunAs -Wait -PassThru -ArgumentList $scriptArgs
  exit $proc.ExitCode
}

Write-Host "Installing Auren DNS daemon (SYSTEM scheduled task) using $node"

& $node -e @"
const dns = require(process.argv[1] + '/src/platform/dns-controller');
const o = dns.installDaemonCli({
  nodeBin: process.argv[2],
  configPath: process.argv[3],
  keyPath: process.argv[4],
  heartbeatPath: process.argv[5],
  activityPath: process.argv[6],
  statePath: process.argv[7]
});
process.stdout.write(o);
"@ "$Root" "$node" "$cfg" "$key" "$hb" "$act" "$st"

Write-Host "Auren DNS daemon installed."
