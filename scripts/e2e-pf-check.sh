#!/bin/bash
# Auren — real end-to-end verification of OS/terminal-level network blocking.
#
# Prerequisites:
#   - the DNS daemon (v6+) is installed and running (scripts/install-daemon.sh)
#   - Protection Mode is ON (config.json mode = "on"), so the daemon has loaded
#     the pf anchor `auren`
#   - run as root (pfctl requires privileges). From the repo root:
#       sudo npm run e2e:pf
#       sudo bash scripts/e2e-pf-check.sh
#
# What it checks, for real, at the OS firewall layer:
#   1. the pf anchor `auren` is loaded with rules
#   2. ICMP echo (ping) to a public IP is blocked
#   3. outbound SSH (port 22) to a public IP is blocked
#   4. HTTPS (443) still works — browsing must not break while Protection is ON
set -u

FAILED=0
pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAILED=1; }

echo "Auren OS-level (pf) blocking check"
echo "=================================="

if [ "$(id -u)" -ne 0 ]; then
  fail "must be run as root. From the repo root:  sudo npm run e2e:pf"
  echo "=================================="
  exit 1
fi

# 1. anchor loaded?
RULES="$(pfctl -a auren -sr 2>/dev/null)"
if [ -n "$RULES" ]; then
  COUNT="$(printf '%s\n' "$RULES" | wc -l | tr -d ' ')"
  pass "pf anchor 'auren' is loaded ($COUNT rules)"
else
  fail "pf anchor 'auren' has no rules — is Protection ON and the v6 daemon running?"
fi

# 2. ping blocked?
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
  fail "ping 8.8.8.8 succeeded — ICMP is NOT blocked"
else
  pass "ping 8.8.8.8 is blocked"
fi

# 3. SSH port blocked?
if nc -z -w 2 8.8.8.8 22 >/dev/null 2>&1; then
  fail "outbound port 22 (ssh) reached 8.8.8.8 — NOT blocked"
else
  pass "outbound port 22 (ssh) is blocked"
fi

# 4. HTTPS still allowed (positive control)?
if nc -z -w 3 1.1.1.1 443 >/dev/null 2>&1; then
  pass "HTTPS (443) still reachable"
else
  fail "HTTPS (443) did not connect — browsing may be broken by the anchor"
fi

echo "=================================="
if [ "$FAILED" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
else
  echo "SOME CHECKS FAILED"
fi
exit "$FAILED"
