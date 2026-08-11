#!/bin/bash
# Auren — real end-to-end verification of OS/terminal-level network blocking.
#
# Prerequisites:
#   - the DNS daemon (v7+) is installed and running (scripts/install-daemon.sh)
#   - Protection Mode is ON (config.json mode = "on"), so the daemon has loaded
#     the pf anchor `auren`
#   - run as root (pfctl requires privileges). From the repo root:
#       sudo npm run e2e:pf
#       sudo bash scripts/e2e-pf-check.sh
#
# What it checks, for real, at the OS firewall layer:
#   1. the pf anchor `auren` is loaded with rules, including the DoH block rules
#   2. ICMP echo (ping) to a public IP is blocked
#   3. outbound SSH (port 22) to a public IP is blocked
#   4. DNS-over-TLS (853) is blocked and a known DoH endpoint (1.1.1.1) is
#      unreachable on 443/853 — DoH/DoT bypasses must fail
#   5. HTTPS (443) still works against a normal site — browsing must not break
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
  fail "pf anchor 'auren' has no rules — is Protection ON and the v7 daemon running?"
fi

# 1b. DoH block rules present in the anchor?
if printf '%s\n' "$RULES" | grep -q 'block out proto { tcp udp } to 1\.1\.1\.1'; then
  pass "DoH block rules are present in the anchor"
else
  fail "no DoH block rules found in the anchor — is the v7 daemon installed?"
fi

# 2. ping blocked?
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
  fail "ping 8.8.8.8 succeeded — ICMP is NOT blocked"
else
  pass "ping 8.8.8.8 is blocked"
fi

# 3. SSH port blocked? (example.com is not a DoH endpoint, so this isolates the
#    port block from the DoH IP block.)
if nc -z -w 2 example.com 22 >/dev/null 2>&1; then
  fail "outbound port 22 (ssh) reached example.com — NOT blocked"
else
  pass "outbound port 22 (ssh) is blocked"
fi

# 4. DoT / DoH bypass blocked?
if nc -z -w 2 example.com 853 >/dev/null 2>&1; then
  fail "DNS-over-TLS (853) reached example.com — NOT blocked"
else
  pass "DNS-over-TLS (853) is blocked"
fi
if nc -z -w 2 1.1.1.1 443 >/dev/null 2>&1; then
  fail "DoH endpoint 1.1.1.1:443 is reachable — DoH bypass NOT blocked"
else
  pass "DoH endpoint 1.1.1.1 is unreachable (443)"
fi
if nc -z -w 2 1.1.1.1 853 >/dev/null 2>&1; then
  fail "DoH endpoint 1.1.1.1:853 is reachable — DoH bypass NOT blocked"
else
  pass "DoH endpoint 1.1.1.1 is unreachable (853)"
fi

# 5. HTTPS still allowed (positive control)?
if nc -z -w 3 example.com 443 >/dev/null 2>&1; then
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
