#!/bin/bash
# Auren — diagnose port conflicts before or while installing the daemon.
#
#   bash scripts/check-ports.sh          (as yourself)
#   sudo bash scripts/check-ports.sh     (full visibility into other users' processes)
#
# What it checks, for real:
#   1. who (if anyone) is listening on TCP/UDP 53 (DNS) — a conflict here means
#      Auren's resolver can't bind and domain blocking silently does nothing
#   2. whether the system's DNS is already pointed at 127.0.0.1
#   3. who (if anyone) is listening on TCP 42792 (the HTTPS blocking proxy port)
set -u

echo "Auren port conflict check"
echo "========================"
if [ "$(id -u)" -ne 0 ]; then
  echo "  WARN  running as a normal user — re-run with sudo for full process visibility"
fi

for port in 53 42792; do
  OWNER="$(lsof -nP -iTCP:$port -sTCP:LISTEN 2>/dev/null | tail -n +2)"
  if [ -n "$OWNER" ]; then
    echo "  USED  TCP/$port:"
    printf '%s\n' "$OWNER" | head -5
    echo "        ^ a process is listening on this port"
  else
    echo "  FREE  TCP/$port"
  fi
done

UDP53="$(lsof -nP -iUDP:53 2>/dev/null | tail -n +2)"
if [ -n "$UDP53" ]; then
  echo "  USED  UDP/53 (DNS queries):"
  printf '%s\n' "$UDP53" | head -5
  echo "        ^ a process is answering DNS on 53"
else
  echo "  FREE  UDP/53"
fi

if scutil --dns 2>/dev/null | grep -q "nameserver\[[0-9]*\] *: *127.0.0.1"; then
  echo "  INFO  system DNS currently points at 127.0.0.1 (at Auren or another local resolver)"
else
  echo "  INFO  system DNS currently points at a normal upstream resolver (not Auren)"
fi

echo "========================"
echo "If TCP/UDP 53 shows USED by another process, stop that process (or the daemon that
started it), then toggle protection OFF and ON in Auren so its resolver can bind."
