# Auren — diagnose port conflicts before or while installing the daemon.
#
#   .\scripts\check-ports.ps1
#
# What it checks, for real:
#   1. who (if anyone) is listening on TCP/UDP 53 (DNS) — a conflict here means
#      Auren's resolver can't bind and domain blocking silently does nothing
#   2. whether any adapter's DNS is already pointed at 127.0.0.1
#   3. who (if anyone) is listening on TCP 42792 (the HTTPS blocking proxy port)
$ErrorActionPreference = 'SilentlyContinue'

Write-Host 'Auren port conflict check'
Write-Host '========================'

function Show-Owner {
  param([int]$Port)
  $conns = @(Get-NetTCPConnection -LocalPort $Port -State Listen)
  if ($conns.Count -eq 0) {
    Write-Host "  FREE  TCP/$Port"
    return
  }
  Write-Host "  USED  TCP/$Port:"
  foreach ($c in $conns) {
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "        pid $($c.OwningProcess)  $($p.ProcessName)"
  }
  Write-Host '        ^ a process is listening on this port'
}

Show-Owner -Port 53
Show-Owner -Port 42792

$udp53 = @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue)
if ($udp53.Count -gt 0) {
  Write-Host '  USED  UDP/53 (DNS queries):'
  foreach ($e in $udp53) {
    $p = Get-Process -Id $e.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "        pid $($e.OwningProcess)  $($p.ProcessName)"
  }
  Write-Host '        ^ a process is answering DNS on 53'
} else {
  Write-Host '  FREE  UDP/53'
}

$ours = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
  Where-Object { $_.ServerAddresses } |
  Select-Object -ExpandProperty ServerAddresses |
  Where-Object { $_ -eq '127.0.0.1' })
if ($ours.Count -gt 0) {
  Write-Host '  INFO  an adapter points DNS at 127.0.0.1 (at Auren or another local resolver)'
} else {
  Write-Host '  INFO  DNS currently points at a normal upstream resolver (not Auren)'
}

Write-Host '========================'
Write-Host 'If TCP/UDP 53 shows USED by another process, stop that process (or the daemon that'
Write-Host 'started it), then toggle protection OFF and ON in Auren so its resolver can bind.'
